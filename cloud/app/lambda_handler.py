"""AWS Lambda entry point (alternative deployment; EC2 is recommended - see cloud/SANDBOX.md §6).

Handler: cloud.app.lambda_handler.handler  (API Gateway HTTP API, payload format 2.0, via Mangum).
"""

from __future__ import annotations

from mangum import Mangum

from .main import create_app

handler = Mangum(create_app(), lifespan="auto")
