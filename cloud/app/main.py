"""HID kiosk cloud API (FastAPI). Run locally from the project root:

    cloud/.venv/bin/python -m uvicorn cloud.app.main:app --host 127.0.0.1 --port 9000

Defaults are fully local (FACE_BACKEND=fake, STORE_BACKEND=memory, EMAIL_BACKEND=fake) so the edge can be
integration-tested before AWS exists. On AWS set FACE_BACKEND=rekognition STORE_BACKEND=dynamodb
EMAIL_BACKEND=ses BLOB_BACKEND=s3 METRICS_SINK=put_metric_data CLOUD_AWS_REGION=us-east-1.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import APP_VERSION, Settings, settings_from_env
from .container import Services, build_services
from .errors import install_error_handlers
from .middleware import HidMiddleware
from .routers import admin, core

log = logging.getLogger("hid.cloud")


def create_app(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    if services is None:
        settings = settings or settings_from_env()
        services = build_services(settings)
    s = services.settings

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        services.schedule.ensure_seeded()
        await services.health.probe_once()  # warms the Rekognition / DynamoDB connections
        services.health.start()
        log.info("hid-cloud %s started: %s policy=%s", APP_VERSION, s.public_summary(), services.policy.source)
        yield
        await services.health.stop()
        services.metrics.close()

    app = FastAPI(title="HID kiosk cloud API", version=APP_VERSION, lifespan=lifespan,
                  docs_url="/docs" if s.enable_docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if s.enable_docs else None)
    app.state.services = services
    install_error_handlers(app)
    install_schedule_error_handlers(app)
    app.include_router(core.router)
    app.include_router(admin.router)
    app.add_middleware(HidMiddleware, get_services=lambda: app.state.services)
    return app


def install_schedule_error_handlers(app: FastAPI) -> None:
    """Schedule-service exceptions -> the protocol error envelope (never a generic 500)."""
    from fastapi import Request
    from fastapi.responses import JSONResponse

    from .errors import STATUS_BY_CODE, error_body
    from .services.schedule_service import BundleRejected, ScheduleConflict, UnknownUser

    @app.exception_handler(BundleRejected)
    async def _rejected(_: Request, exc: BundleRejected) -> JSONResponse:
        return JSONResponse(error_body(exc.code, exc.message, reason=exc.reason),
                            status_code=STATUS_BY_CODE.get(exc.code, 500))

    @app.exception_handler(ScheduleConflict)
    async def _conflict(_: Request, exc: ScheduleConflict) -> JSONResponse:
        return JSONResponse(error_body("INVALID_STATE", "schedule changed concurrently; retry",
                                       reason="SCHEDULE_CONFLICT"), status_code=409)

    @app.exception_handler(UnknownUser)
    async def _unknown(_: Request, exc: UnknownUser) -> JSONResponse:
        return JSONResponse(error_body("NOT_FOUND", f"unknown user_id {exc} (not in the schedule or the enrolment "
                                                    "store)", reason="UNKNOWN_USER"), status_code=404)


def _configure_logging() -> None:
    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


_configure_logging()
_app: FastAPI | None = None


def __getattr__(name: str):
    """`uvicorn cloud.app.main:app` resolves `app` lazily, so importing create_app() in tests or tools
    never requires the production environment."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
