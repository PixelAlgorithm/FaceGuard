"""Wires adapters + services from Settings. AWS clients are created only for AWS-backed adapters, so
local runs (fake/memory/sqlite) never need credentials. Credentials come from the standard boto3 chain
(EC2 instance profile on AWS; profile `hid-sandbox` / env vars on a laptop) - never from this repo."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from .auth import ReplayCache
from .clock import Clock
from .config import Settings
from .metrics import Metrics
from .policy_bridge import PolicyBridge
from .services.adapters import (
    DisabledBlobs,
    DisabledMailer,
    FakeMailer,
    FernetBox,
    KmsBox,
    MemoryBlobs,
    NoBox,
    S3Blobs,
    SesMailer,
    TokenBucket,
)
from .services.enroll_service import EnrollService
from .services.faces import DisabledFaces, FakeFaces, RekognitionFaces
from .services.health import HealthMonitor
from .services.kv import DynamoKV, MemoryKV, SqliteKV
from .services.liveness_service import LivenessService
from .services.match_service import MatchService
from .services.otp_service import OtpService
from .services.schedule_service import ScheduleService
from .services.sync_service import SyncService
from .thresholds import CloudThresholds, load_thresholds

log = logging.getLogger("hid.cloud")


@dataclass
class Services:
    settings: Settings
    thresholds: CloudThresholds
    clock: Clock
    kv: Any
    faces: Any
    mailer: Any
    blobs: Any
    box: Any
    metrics: Metrics
    policy: PolicyBridge
    schedule: ScheduleService
    sync: SyncService
    match: MatchService
    enroll: EnrollService
    otp: OtpService
    liveness: LivenessService
    health: HealthMonitor
    replay: ReplayCache
    extras: dict = field(default_factory=dict)


class _Aws:
    def __init__(self, region: str) -> None:
        self.region = region
        self._session = None
        self._clients: dict[str, Any] = {}

    def client(self, name: str, *, no_retries: bool = False, read_timeout: float = 5.0):
        if name not in self._clients:
            import boto3
            from botocore.config import Config

            if self._session is None:
                self._session = boto3.session.Session(region_name=self.region)
            cfg = Config(region_name=self.region, connect_timeout=2, read_timeout=read_timeout,
                         retries={"max_attempts": 1 if no_retries else 3, "mode": "standard"},
                         max_pool_connections=20, tcp_keepalive=True)
            self._clients[name] = self._session.client(name, config=cfg)
        return self._clients[name]


def build_services(settings: Settings, *, clock: Clock | None = None, kv=None, faces=None, mailer=None,
                   blobs=None, box=None, metrics: Metrics | None = None, policy: PolicyBridge | None = None,
                   thresholds: CloudThresholds | None = None) -> Services:
    clock = clock or Clock()
    aws = _Aws(settings.region)
    t = thresholds or load_thresholds(settings.thresholds_path)
    if t.missing:
        log.warning("thresholds.yaml keys missing, documented defaults used: %s", ", ".join(t.missing))

    def now_fn() -> float:
        return clock.now().timestamp()

    if kv is None:
        if settings.store_backend == "dynamodb":
            kv = DynamoKV(aws.client("dynamodb"), users_table=settings.ddb_table_users,
                          decisions_table=settings.ddb_table_decisions, state_table=settings.ddb_table_state,
                          now_fn=now_fn)
        elif settings.store_backend == "sqlite":
            kv = SqliteKV(settings.sqlite_path, now_fn=now_fn)
        else:
            kv = MemoryKV(now_fn=now_fn)
    if faces is None:
        if settings.face_backend == "rekognition":
            faces = RekognitionFaces(aws.client("rekognition", no_retries=True, read_timeout=3.0),
                                     settings.collection_id)
        elif settings.face_backend == "fake":
            faces = FakeFaces(settings.collection_id)
        else:
            faces = DisabledFaces()
    if mailer is None:
        mailer = {"ses": lambda: SesMailer(aws.client("sesv2"), settings.ses_sender),
                  "fake": FakeMailer, "disabled": DisabledMailer}[settings.email_backend]()
    if blobs is None:
        blobs = {"s3": lambda: S3Blobs(aws.client("s3"), settings.s3_bucket, settings.kms_key_id),
                 "memory": MemoryBlobs, "disabled": DisabledBlobs}[settings.blob_backend]()
    if box is None:
        mode = settings.secretbox
        if mode == "auto":
            mode = "kms" if settings.kms_key_id else ("fernet" if settings.cloud_data_key else "none")
        box = {"kms": lambda: KmsBox(aws.client("kms"), settings.kms_key_id),
               "fernet": lambda: FernetBox(settings.cloud_data_key), "none": NoBox}[mode]()
    if metrics is None:
        cw = aws.client("cloudwatch") if settings.metrics_sink == "put_metric_data" else None
        metrics = Metrics(settings.metrics_sink, settings.metrics_namespace, cw_client=cw)
    policy = policy or PolicyBridge()

    schedule = ScheduleService(kv, settings, t, clock, policy)
    match = MatchService(faces, kv, t, metrics, budget_ms=settings.match_budget_ms,
                         search_tps=settings.rekognition_search_tps, compare_tps=settings.rekognition_compare_tps,
                         blobs=blobs, store_reference=settings.enroll_store_reference)
    enroll = EnrollService(faces, kv, schedule, box, blobs, clock, card_pepper=settings.card_id_pepper,
                           quality_filter=t.quality_filter, min_faces=settings.enroll_min_faces,
                           store_reference=settings.enroll_store_reference,
                           search_bucket=TokenBucket(settings.rekognition_search_tps),  # IndexFaces: own quota
                           match_threshold=t.user_match_threshold,  # AssociateFaces: appended face must match user
                           max_faces=settings.enroll_max_faces_per_user, pinned_faces=settings.enroll_pinned_faces)
    otp_pepper = settings.otp_pepper or secrets.token_hex(32)  # per-process if unset: OTPs die on restart
    otp = OtpService(kv, mailer, t, clock, metrics, pepper=otp_pepper, resend_after_s=settings.otp_resend_after_s)
    liveness = LivenessService(faces, kv, match, t, clock, tps=settings.liveness_tps,
                               max_concurrent=settings.liveness_max_concurrent, region=settings.region,
                               s3_bucket=settings.s3_bucket if settings.blob_backend == "s3" else None,
                               kms_key_id=settings.kms_key_id or None, backend=settings.liveness_backend)
    sync = SyncService(kv, settings, t, clock, schedule, metrics)
    health = HealthMonitor(faces, kv, refresh_s=settings.health_refresh_s, store_backend=settings.store_backend)
    return Services(settings=settings, thresholds=t, clock=clock, kv=kv, faces=faces, mailer=mailer, blobs=blobs,
                    box=box, metrics=metrics, policy=policy, schedule=schedule, sync=sync, match=match,
                    enroll=enroll, otp=otp, liveness=liveness, health=health,
                    replay=ReplayCache(ttl_s=2 * settings.auth_skew_s + 5))
