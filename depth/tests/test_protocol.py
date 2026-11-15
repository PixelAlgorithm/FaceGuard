"""Wire format of POST /v1/depth/frames (what DepthProbe sends and the edge decodes)."""

from __future__ import annotations

import json

import numpy as np
import pytest

from depth import synth
from depth.checks import SIGNAL_KEYS
from depth.protocol import (
    DepthProtocolError,
    decode_frames,
    encode_multipart,
    parse_meta,
    parse_multipart,
    process_upload,
)


def _meta(cam: synth.SynthCamera, frame: synth.SynthFrame, **over) -> dict:
    meta = {
        "attempt_id": "att_01TEST",
        "phase": "PASSIVE",
        "depth_type": "disparity",
        "dtype": "float16",
        "width": cam.width,
        "height": cam.height,
        "intrinsics": cam.intrinsics(640, 480),
        "face_box_norm": frame.face_box_norm,
        "landmarks_norm": frame.landmarks_norm,
        "timestamps_ms": [1731571200000, 1731571200033],
        "device": "iPhone17,2",
        "depth_accuracy": "absolute",
        "depth_nonce": "n0nce",
        "some_future_field": {"ignored": True},
    }
    meta.update(over)
    return meta


def _blobs(frame, rng, n=2, depth_type="disparity", dtype="float16"):
    return [synth.to_wire(synth.add_sensor_noise(frame.depth_m, rng), depth_type, dtype) for _ in range(n)]


@pytest.mark.parametrize("dtype", ["float16", "float32"])
def test_decode_little_endian_row_major(cam, dtype):
    depth = 0.25 + np.arange(cam.width * cam.height, dtype=np.float64).reshape(cam.height, cam.width) / 2e5
    depth[5, 7] = 0.70  # marker: row 5, column 7
    meta = parse_meta(
        {
            "attempt_id": "a",
            "phase": "PASSIVE",
            "depth_type": "depth",
            "dtype": dtype,
            "width": cam.width,
            "height": cam.height,
        }
    )
    out = decode_frames(meta, [synth.to_wire(depth, "depth", dtype)])
    assert out.shape == (1, cam.height, cam.width) and out.dtype == np.float32
    rtol = 1e-3 if dtype == "float16" else 1e-6  # float16 ulp at 0.25-0.5 m is 0.12-0.24 mm
    assert np.allclose(out[0], depth, rtol=rtol, atol=0)
    assert out[0, 5, 7] == pytest.approx(0.70, rel=rtol) and out[0, 7, 5] < 0.5  # (H, W) row-major


@pytest.mark.parametrize(
    "over,msg",
    [
        ({"attempt_id": ""}, "attempt_id"),
        ({"phase": "LIVE"}, "phase"),
        ({"depth_type": "mm"}, "depth_type"),
        ({"dtype": "uint16"}, "dtype"),
        ({"width": "x"}, "width"),
        ({"width": 4000, "height": 3000}, "size"),
        ({"face_box_norm": [0.1, 0.2, 0.3]}, "face_box_norm"),
        ({"face_box_norm": [0.1, 0.2, -0.3, 0.4]}, "face_box_norm"),
        ({"landmarks_norm": {"left_eye": [0.1]}}, "left_eye"),
        ({"intrinsics": {"fx": 1.0}}, "intrinsics"),
    ],
)
def test_parse_meta_rejects_malformed(cam, over, msg):
    frame = synth.scene_face(cam)
    with pytest.raises(DepthProtocolError, match=msg):
        parse_meta(_meta(cam, frame, **over))


def test_parse_meta_normalises(cam):
    frame = synth.scene_face(cam)
    m = parse_meta(json.dumps(_meta(cam, frame, phase="challenge", landmarks_norm={"left_eye": [0.4, 0.4]})))
    assert m["phase"] == "CHALLENGE" and m["landmarks_norm"] is None  # incomplete landmarks -> box only
    assert m["depth_accuracy"] == "absolute" and m["some_future_field"] == {"ignored": True}
    assert parse_meta(_meta(cam, frame, depth_accuracy="bogus"))["depth_accuracy"] is None
    with pytest.raises(DepthProtocolError, match="JSON"):
        parse_meta(b"{not json")


def test_decode_rejects_size_mismatch_and_too_many_frames(cam, rng):
    frame = synth.scene_face(cam)
    meta = parse_meta(_meta(cam, frame))
    good = _blobs(frame, rng, 1)[0]
    with pytest.raises(DepthProtocolError, match="bytes"):
        decode_frames(meta, [good[:-2]])
    with pytest.raises(DepthProtocolError, match="at most"):
        decode_frames(meta, [good] * 4)
    with pytest.raises(DepthProtocolError, match="depth_0"):
        decode_frames(meta, [])


def test_multipart_round_trip(cam, rng):
    frame = synth.scene_face(cam)
    blobs = _blobs(frame, rng, 3)
    body, ctype = encode_multipart(_meta(cam, frame), blobs, rgb_jpeg=b"\xff\xd8fakejpeg\xff\xd9")
    parts = parse_multipart(body, ctype)
    assert set(parts) == {"meta", "depth_0", "depth_1", "depth_2", "rgb_0"}
    assert "filename" not in parts["meta"][0] and parts["depth_1"][0]["filename"] == "depth_1.bin"
    assert parts["depth_2"][1] == blobs[2] and parts["rgb_0"][1].startswith(b"\xff\xd8")
    assert json.loads(parts["meta"][1])["attempt_id"] == "att_01TEST"


def test_process_upload_passive_then_challenge_fills_m1(cam, cfg, rng):
    neutral_f = synth.scene_face(cam, rng=rng, landmark_jitter=0.0015)
    res = process_upload(json.dumps(_meta(cam, neutral_f)), _blobs(neutral_f, rng, 3), cfg)
    assert tuple(res.signal) == SIGNAL_KEYS and res.signal["available"] is True and res.n_frames == 3
    assert res.signal["absolute"] is True and res.signal["d4_ipd_mm"] is not None
    assert res.signal["m1_mouth_residual_mm"] is None  # PASSIVE never fills M1
    assert res.depth_m is not None and res.depth_m.shape == (cam.height, cam.width)

    open_f = synth.scene_face(cam, deform=synth.open_mouth(), rng=rng, landmark_jitter=0.0015)
    ch = process_upload(_meta(cam, open_f, phase="CHALLENGE"), _blobs(open_f, rng, 1), cfg, neutral=res)
    m = cfg["liveness"]["mask"]
    assert ch.signal["m1_mouth_residual_mm"] > m["m1_mouth_residual_min_mm"]
    assert ch.signal["m1_forehead_residual_mm"] < m["m1_forehead_residual_max_mm"]
    no_neutral = process_upload(_meta(cam, open_f, phase="CHALLENGE"), _blobs(open_f, rng, 1), cfg)
    assert no_neutral.signal["m1_mouth_residual_mm"] is None
    signals = pytest.importorskip("edge.policy.signals")
    signals.DepthSignal(**ch.signal)


def test_process_upload_flat_print_fails_d1(cam, cfg, rng):
    from depth.checks import classify

    f = synth.scene_print(cam)
    res = process_upload(_meta(cam, f), _blobs(f, rng, 3), cfg)
    assert classify(res.signal, cfg)["checks"]["d1"] == "FAIL"
    assert res.compute_ms < cfg["latency_budget_ms"]["depth_max_wait"]


def test_per_frame_challenge_lists(cam, cfg, rng):
    neutral_f = synth.scene_face(cam, rng=rng, landmark_jitter=0.0015)
    passive = process_upload(_meta(cam, neutral_f), _blobs(neutral_f, rng, 3), cfg)
    frames = [
        synth.scene_face(cam, rng=rng, landmark_jitter=0.0015),
        synth.scene_face(cam, deform=synth.open_mouth(), rng=rng, landmark_jitter=0.0015),
    ]
    blobs = [synth.to_wire(synth.add_sensor_noise(f.depth_m, rng)) for f in frames]
    meta = _meta(
        cam,
        frames[0],
        phase="CHALLENGE",
        face_box_norm_frames=[f.face_box_norm for f in frames],
        landmarks_norm_frames=[f.landmarks_norm for f in frames],
    )
    assert parse_meta(meta)["landmarks_norm_frames"][1]["mouth"] == frames[1].landmarks_norm["mouth"]
    ch = process_upload(meta, blobs, cfg, neutral=passive)
    assert ch.diag["m1"]["m1_frames"] == 2 and ch.diag["m1"]["m1_frame_index"] == 1
    assert ch.signal["m1_mouth_residual_mm"] > cfg["liveness"]["mask"]["m1_mouth_residual_min_mm"]
    with pytest.raises(DepthProtocolError, match="per-frame"):
        parse_meta(_meta(cam, frames[0], landmarks_norm_frames=[frames[0].landmarks_norm] * 4))
