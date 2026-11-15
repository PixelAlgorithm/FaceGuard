"""Matcher search semantics, encrypted template store, PAD upstream crop, metrics bounds."""

from __future__ import annotations

import numpy as np
import pytest
from cryptography.fernet import Fernet

from edge.metrics import MetricsStore, clopper_pearson_upper, error_upper_95
from edge.ml.matcher import Gallery, best_cosine, search
from edge.ml.pad import upstream_crop
from edge.ml.templates import TemplateStore, TemplateStoreError


def unit(v):
    v = np.asarray(v, np.float32)
    return v / np.linalg.norm(v)


def rand_emb(seed: int) -> np.ndarray:
    return unit(np.random.default_rng(seed).normal(size=512))


def test_search_top1_top2_are_different_users():
    a, b = rand_emb(1), rand_emb(2)
    a2 = unit(a + 0.05 * rand_emb(3))
    g = Gallery(user_ids=("u_a", "u_a", "u_b"), matrix=np.stack([a, a2, b]))
    r = search(a, g)
    assert r.top1_user == "u_a" and r.top1 == pytest.approx(1.0, abs=1e-3)
    assert r.top2 == pytest.approx(float(a @ b), abs=1e-3)  # best *different* user, not a's 2nd template
    assert r.n_users == 2


def test_search_single_user_and_filters():
    a = rand_emb(1)
    g = Gallery(user_ids=("u_a",), matrix=a[None])
    assert search(a, g).top2 is None
    assert search(a, g, allowed={"u_x"}).top1_user is None
    assert search(None, g).top1 is None
    assert search(a, Gallery()).top1_user is None
    assert best_cosine(a, g, "u_a") == pytest.approx(1.0, abs=1e-3)
    assert best_cosine(a, g, "u_missing") is None


def test_template_store_encrypted_roundtrip(tmp_path):
    key = Fernet.generate_key().decode()
    path = tmp_path / "templates.fernet"
    store = TemplateStore(path, key, "arcface_test@1")
    embs = np.stack([rand_emb(i) for i in range(3)])
    u = store.upsert(user_id="u_1", display_name="One", role="student", embeddings=embs,
                     consent_version="v1", card_id_hash="ab" * 32, totp_secret="JBSWY3DPEHPK3PXP")
    assert u.template_version == 1
    blob = path.read_bytes()
    # Fernet tokens are urlsafe base64: a quote can never appear, so quoted JSON markers prove encryption
    assert embs.astype(np.float32).tobytes()[:64] not in blob and b'"u_1"' not in blob and b'"One"' not in blob
    assert blob.startswith(b"gAAAA")  # Fernet version byte 0x80
    again = TemplateStore(path, key, "arcface_test@1")
    again.load()
    assert again.count() == 1 and again.gallery.matrix.shape == (3, 512)
    assert search(embs[0], again.gallery).top1_user == "u_1"
    assert again.get("u_1").totp_secret == "JBSWY3DPEHPK3PXP"
    assert again.upsert(user_id="u_1", display_name="One", role="student", embeddings=embs[:1],
                        consent_version="v1", card_id_hash=None, totp_secret=None).template_version == 2
    assert again.get("u_1").card_id_hash == "ab" * 32  # kept when not re-supplied
    assert again.delete("u_1") and again.count() == 0


def test_template_store_append_keeps_previous_looks(tmp_path):
    """Re-enrolment with append=True keeps the earlier look (glasses on + off both match), newest capped."""
    from edge.ml.templates import MAX_TEMPLATES_PER_USER

    store = TemplateStore(tmp_path / "t.fernet", Fernet.generate_key().decode(), "m@1")
    glasses, bare = rand_emb(10), rand_emb(11)
    kw = {"user_id": "u_1", "display_name": "One", "role": "student", "consent_version": "v1",
          "card_id_hash": None, "totp_secret": None}
    store.upsert(embeddings=glasses[None], **kw)
    assert store.upsert(embeddings=bare[None], append=True, **kw).template_version == 2
    assert store.gallery.matrix.shape == (2, 512)
    assert best_cosine(glasses, store.gallery, "u_1") == pytest.approx(1.0, abs=1e-3)
    assert best_cosine(bare, store.gallery, "u_1") == pytest.approx(1.0, abs=1e-3)
    many = np.stack([rand_emb(100 + i) for i in range(MAX_TEMPLATES_PER_USER)])
    store.upsert(embeddings=many, append=True, **kw)
    assert store.gallery.matrix.shape == (MAX_TEMPLATES_PER_USER, 512)  # capped
    assert best_cosine(glasses, store.gallery, "u_1") == pytest.approx(1.0, abs=1e-3)  # original pinned
    store.upsert(embeddings=bare[None], **kw)  # default: replace
    assert store.gallery.matrix.shape == (1, 512)


def test_template_store_cap_pins_the_original_enrolment(tmp_path):
    """Repeated appends evict only appended templates: the first PINNED_TEMPLATES never drift away."""
    from edge.ml.templates import MAX_TEMPLATES_PER_USER, PINNED_TEMPLATES

    store = TemplateStore(tmp_path / "t.fernet", Fernet.generate_key().decode(), "m@1")
    kw = {"user_id": "u_1", "display_name": "One", "role": "student", "consent_version": "v1",
          "card_id_hash": None, "totp_secret": None}
    original = np.stack([rand_emb(200 + i) for i in range(PINNED_TEMPLATES)])
    store.upsert(embeddings=original, **kw)
    appended = [rand_emb(300 + i) for i in range(30)]
    for e in appended:  # many small appends, like repeated re-enrolments
        store.upsert(embeddings=e[None], append=True, **kw)
    g = store.gallery
    assert g.matrix.shape == (MAX_TEMPLATES_PER_USER, 512)
    assert all(best_cosine(o, g, "u_1") == pytest.approx(1.0, abs=1e-3) for o in original)
    assert best_cosine(appended[-1], g, "u_1") == pytest.approx(1.0, abs=1e-3)  # newest kept
    assert best_cosine(appended[0], g, "u_1") < 0.5  # oldest appended evicted
    keep = MAX_TEMPLATES_PER_USER - PINNED_TEMPLATES
    assert sum(best_cosine(e, g, "u_1") > 0.99 for e in appended) == keep  # nothing dropped by mistake


def test_template_store_refuses_non_finite_or_zero_embeddings(tmp_path):
    store = TemplateStore(tmp_path / "t.fernet", Fernet.generate_key().decode(), "m@1")
    kw = {"user_id": "u_1", "display_name": "One", "role": "student", "consent_version": "v1",
          "card_id_hash": None, "totp_secret": None}
    bad_nan = rand_emb(1).copy()
    bad_nan[3] = np.nan
    for bad in (bad_nan, np.zeros(512, np.float32)):
        with pytest.raises(TemplateStoreError):
            store.upsert(embeddings=bad[None], **kw)
    assert store.count() == 0


def test_resemblance_to_stored_fails_closed():
    """Append-mode re-enrolment guard: every new frame must resemble the stored templates; NaN never passes."""
    from edge.enroll import resemblance_to_stored

    a = rand_emb(1)
    near = unit(a + 0.3 * rand_emb(2))
    other = rand_emb(3)
    stored = np.stack([a, rand_emb(4)])
    assert resemblance_to_stored(stored, np.stack([near, a])) == pytest.approx(float(near @ a), abs=1e-3)
    assert resemblance_to_stored(stored, np.stack([near, other])) < 0.3  # one unrelated frame is enough
    nan_new = near.copy()
    nan_new[0] = np.nan
    for worst in (resemblance_to_stored(stored, nan_new[None]),
                  resemblance_to_stored(np.full((2, 512), np.nan, np.float32), near[None]),
                  resemblance_to_stored(np.zeros((0, 512), np.float32), near[None])):
        assert np.isnan(worst) and not worst >= 0.30  # the caller's `not worst >= floor` rejects NaN


def test_template_store_wrong_key_and_model_mismatch(tmp_path):
    key = Fernet.generate_key().decode()
    path = tmp_path / "t.fernet"
    TemplateStore(path, key, "m@1").upsert(user_id="u", display_name="U", role="r", embeddings=rand_emb(0)[None],
                                           consent_version="v", card_id_hash=None, totp_secret=None)
    with pytest.raises(TemplateStoreError):
        TemplateStore(path, Fernet.generate_key().decode(), "m@1").load()
    other = TemplateStore(path, key, "m@2")
    other.load()
    assert other.count() == 0 and other.skipped_model_mismatch == 1
    with pytest.raises(TemplateStoreError):
        TemplateStore(path, "", "m@1")


def _reference_crop(img, box, scale):
    """Independent transcription of minivision src/generate_patches.py CropImage."""
    src_h, src_w = img.shape[:2]
    x, y, bw, bh = box
    scale = min((src_h - 1) / bh, min((src_w - 1) / bw, scale))
    nw, nh = bw * scale, bh * scale
    cx, cy = bw / 2 + x, bh / 2 + y
    ltx, lty, rbx, rby = cx - nw / 2, cy - nh / 2, cx + nw / 2, cy + nh / 2
    if ltx < 0:
        rbx -= ltx
        ltx = 0
    if lty < 0:
        rby -= lty
        lty = 0
    if rbx > src_w - 1:
        ltx -= rbx - src_w + 1
        rbx = src_w - 1
    if rby > src_h - 1:
        lty -= rby - src_h + 1
        rby = src_h - 1
    return int(ltx), int(lty), int(rbx), int(rby)


@pytest.mark.parametrize("box", [(270, 190, 100, 120), (5, 5, 120, 150), (560, 380, 70, 90), (100, 300, 200, 170)])
@pytest.mark.parametrize("scale", [2.7, 4.0])
def test_pad_crop_matches_upstream_shift_semantics(box, scale):
    rng = np.random.default_rng(0)
    img = rng.integers(0, 255, (480, 640, 3), dtype=np.uint8)
    out = upstream_crop(img, box, scale)
    assert out.shape == (80, 80, 3) and out.dtype == np.uint8
    l, t, r, b = _reference_crop(img, box, scale)
    import cv2

    ref = cv2.resize(img[t : b + 1, l : r + 1], (80, 80))
    assert np.array_equal(out, ref)
    assert l >= 0 and t >= 0 and r <= 639 and b <= 479  # shifted inside, never outside


def test_pad_crop_shifts_rather_than_shrinks_at_the_edge():
    l, _t, r, _b = _reference_crop(np.zeros((480, 640, 3)), (5, 100, 100, 100), 2.7)
    assert l == 0 and (r - l) == pytest.approx(270, abs=1)  # full 2.7x width kept, window moved right


def test_error_bounds():
    assert error_upper_95(0, 100) == 0.03  # rule of 3
    assert error_upper_95(0, 0) is None
    u = clopper_pearson_upper(1, 50)
    assert 0.08 < u < 0.10  # exact one-sided 95 % bound for 1/50 is ~0.0921
    assert clopper_pearson_upper(5, 5) == 1.0


def test_metrics_final_decision_and_client_latency():
    m = MetricsStore()
    m.record({"attempt_id": "a1", "decision": "STEP_UP", "mode": "OFFLINE", "reason_codes": ["MATCH_LOW"],
              "latency_ms": {"total": 100, "liveness": 50}}, "bona_fide", kind="frames")
    m.record({"attempt_id": "a1", "decision": "ALLOW", "mode": "OFFLINE", "reason_codes": ["ACCESS_OK"],
              "latency_ms": {"total": 9}}, "bona_fide", kind="fallback")
    m.record({"attempt_id": "a2", "decision": "ALLOW", "mode": "OFFLINE", "reason_codes": ["ACCESS_OK"],
              "latency_ms": {"total": 120}}, "print", kind="frames")
    m.record_client("a1", 1300, "bona_fide")
    s = m.summary()
    assert s["attempts"] == 2 and s["decisions"] == {"ALLOW": 2}
    assert s["latency_ms"]["total"]["n"] == 2  # fallback latency excluded from the 2 s path
    assert s["latency_ms"]["client"] == {"p50": 1300.0, "p95": 1300.0, "n": 1}
    assert s["by_label"]["print"]["accepted"] == 1 and s["by_label"]["print"]["apcer"] == 1.0
    assert s["by_label"]["bona_fide"]["rejected"] == 0
