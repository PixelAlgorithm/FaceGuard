"""ONNX Runtime session factory (CPU by default; CoreML optional for the embedder).

The model file is read once, hash-verified against its pin when it is a pinned model
(registry.verified_bytes), and ORT is given those bytes, never the path (audit EM-13).
"""

from __future__ import annotations

from pathlib import Path

import onnxruntime as ort

from edge.ml.registry import verified_bytes

ort.set_default_logger_severity(3)  # errors only; shape-metadata warnings are noise


def make_session(path: Path, *, threads: int = 2, coreml: bool = False) -> ort.InferenceSession:
    so = ort.SessionOptions()
    so.intra_op_num_threads = threads
    so.inter_op_num_threads = 1
    so.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    providers: list = ["CPUExecutionProvider"]
    if coreml and "CoreMLExecutionProvider" in ort.get_available_providers():
        providers = [
            ("CoreMLExecutionProvider", {"ModelFormat": "MLProgram", "MLComputeUnits": "ALL"}),
            "CPUExecutionProvider",
        ]
    return ort.InferenceSession(verified_bytes(Path(path)), so, providers=providers)


def active_provider(session: ort.InferenceSession) -> str:
    return session.get_providers()[0]
