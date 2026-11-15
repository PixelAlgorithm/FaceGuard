"""Offline genuine / impostor cross-matching -> eval/results/comparisons.csv (FMR/FNMR, DET, threshold calibration).

Runs in the EDGE venv so the embedding pipeline is exactly the live matcher's:
edge.ml.detect.FaceDetector (retinaface_mv2) -> align112 -> edge.ml.matcher.ArcFaceEmbedder (w600k_r50, pinned sha256).
Score(probe, subject) = max cosine over that subject's enrolment templates (the edge's 1:N rule).

  ../edge/.venv/bin/python compare.py                         # eval/captures -> results/comparisons.csv
  ../edge/.venv/bin/python compare.py --lfw-dir /path/to/lfw --lfw-max-ids 300   # + LFW padding (source=lfw)

Pairs: genuine = probe vs own templates; impostor = probe vs every other subject. split = dev (both subjects dev),
test (both test), cross (otherwise; supplementary only). Embeddings are cached ONLY under eval/captures/ (gitignored,
deleted by `collect_faces.py purge --yes`); results never contain images or embeddings.
LFW: Labeled Faces in the Wild, UMass Amherst (vis-www.cs.umass.edu/lfw) - web images of public figures, no formal
licence, research use only; identities split dev/test by a hash of the name (40/60).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import numpy as np

EVAL = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL))

from evallib import CAPTURES_DIR, EVAL_DIR, PROJECT_DIR, RESULTS_DIR
from evallib import io as eio
from evallib import schema as S


@dataclass
class Item:
    image_id: str
    subject: str
    split: str  # dev | test
    role: str  # enrol | probe
    lighting: str
    source: str  # live | lfw
    emb: np.ndarray | None = None


def pair_split(a: str, b: str) -> str:
    return a if a == b else "cross"


def comparisons(items: Iterable[Item], matcher: str, model: str, run_id: str, template_rule: str = "max") -> list[dict]:
    """Probe x subject scores. Pure function (unit-tested with DUMMY embeddings)."""
    items = [i for i in items if i.emb is not None]
    templates: dict[str, list[np.ndarray]] = {}
    split_of: dict[str, str] = {}
    for it in items:
        split_of[it.subject] = it.split
        if it.role == "enrol":
            templates.setdefault(it.subject, []).append(it.emb / (np.linalg.norm(it.emb) + 1e-9))
    gallery = {s: np.stack(v) for s, v in templates.items()}
    rows = []
    for it in items:
        if it.role != "probe":
            continue
        q = it.emb / (np.linalg.norm(it.emb) + 1e-9)
        for g, mat in gallery.items():
            if (it.source == "lfw") != g.startswith("lfw:"):
                continue  # LFW is matched within LFW only
            sims = mat @ q
            score = float(sims.max() if template_rule == "max" else (mat.mean(0) / np.linalg.norm(mat.mean(0))) @ q)
            rows.append({
                "probe_attempt_id": it.image_id, "probe_subject": it.subject, "gallery_subject": g,
                "matcher": matcher, "score": round(score, 6), "genuine": int(g == it.subject),
                "split": pair_split(it.split, split_of[g]), "source": it.source, "run_id": run_id, "model": model,
                "gallery_template": f"{template_rule}_of_{len(mat)}", "probe_lighting": it.lighting,
            })
    return rows


# --------------------------------------------------------------------- inputs

def load_team(captures: Path, subjects: Path, enrol_k: int) -> list[Item]:
    _, reg_rows = eio.read_csv(subjects)
    reg = {r["subject_id"]: r for r in reg_rows}
    _, man = eio.read_csv(captures / "manifest.csv")
    dup = [k for k, v in Counter(r["image_id"] for r in man).items() if v > 1]
    if dup:
        raise SystemExit(f"manifest has duplicate image ids {dup[:5]} - identical images would inflate N; fix it")
    by_subj: dict[str, list[dict]] = {}
    for r in man:
        if r["subject_id"] not in reg:
            raise SystemExit(f"manifest subject {r['subject_id']} not in {subjects}")
        if (reg[r["subject_id"]].get("consent") or "").lower() not in ("yes", "y", "true", "1"):
            raise SystemExit(f"subject {r['subject_id']} has no recorded consent")
        by_subj.setdefault(r["subject_id"], []).append(r)
    items = []
    for s, rows in by_subj.items():
        rows.sort(key=lambda r: r["captured_at_utc"])
        explicit = any(r["role"] == "enrol" for r in rows)
        office = [r for r in rows if r["lighting"] == "office"]
        enrol_ids = {r["image_id"] for r in rows if r["role"] == "enrol"} if explicit else \
            {r["image_id"] for r in (office or rows)[:enrol_k]}
        for r in rows:
            items.append(Item(r["image_id"], s, reg[s]["split"], "enrol" if r["image_id"] in enrol_ids else "probe",
                              r["lighting"], "live"))
    return items


def load_lfw(root: Path, max_ids: int, per_id: int, dev_frac: float = 0.4) -> tuple[list[Item], dict[str, Path]]:
    items, paths = [], {}
    people = sorted(d for d in root.iterdir() if d.is_dir() and len(list(d.glob("*.jpg"))) >= 2)[:max_ids]
    for d in people:
        h = int(hashlib.sha1(d.name.encode()).hexdigest(), 16) % 100
        split = "dev" if h < dev_frac * 100 else "test"
        for k, f in enumerate(sorted(d.glob("*.jpg"))[:per_id]):
            iid = "lfw_" + hashlib.sha256(f.read_bytes()).hexdigest()[:16]
            paths[iid] = f
            items.append(Item(iid, f"lfw:{d.name}", split, "enrol" if k == 0 else "probe", "", "lfw"))
    return items, paths


# --------------------------------------------------------------------- embedding (edge venv only)

class EdgeEmbedder:
    def __init__(self, models_dir: Path):
        sys.path.insert(0, str(PROJECT_DIR))
        import cv2  # noqa: F401  (edge venv)
        from edge.ml.detect import FaceDetector, align112
        from edge.ml.matcher import ArcFaceEmbedder
        from edge.ml.registry import MODEL_FILES, verified_path

        self._align = align112
        self.det = FaceDetector(verified_path(models_dir, "face_detector"))
        self.emb = ArcFaceEmbedder(verified_path(models_dir, "arcface"), MODEL_FILES["arcface"].sha256, provider="cpu")
        self.model_id = self.emb.model_id

    def embed_file(self, path: Path) -> np.ndarray | None:
        import cv2

        img = cv2.imread(str(path))
        if img is None:
            return None
        faces = self.det.detect(img)
        if not faces:
            return None
        return self.emb.embed(self._align(img, faces[0].kps))


def embed_all(items: list[Item], paths: dict[str, Path], embedder, cache_path: Path) -> Counter:
    cache: dict[str, np.ndarray] = {}
    if cache_path.exists():
        with np.load(cache_path) as z:
            cache = {k: z[k] for k in z.files}
    stats: Counter = Counter()
    for it in items:
        key = f"{embedder.model_id}:{it.image_id}"
        if key in cache:
            it.emb = cache[key]
            stats["cached"] += 1
            continue
        p = paths.get(it.image_id)
        e = embedder.embed_file(p) if p else None
        if e is None:
            stats["no_face_or_unreadable"] += 1
            continue
        it.emb = e
        cache[key] = e
        stats["embedded"] += 1
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(cache_path, **cache)  # eval/captures/ only (gitignored)
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures", type=Path, default=CAPTURES_DIR)
    ap.add_argument("--subjects", type=Path, default=EVAL_DIR / "subjects.csv")
    ap.add_argument("--models", type=Path, default=PROJECT_DIR / "models")
    ap.add_argument("--out", type=Path, default=RESULTS_DIR / "comparisons.csv")
    ap.add_argument("--enrol-k", type=int, default=3, help="enrolment images per subject if none flagged 'enrol'")
    ap.add_argument("--template-rule", choices=["max", "mean"], default="max", help="edge uses max over templates")
    ap.add_argument("--lfw-dir", type=Path, default=None)
    ap.add_argument("--lfw-max-ids", type=int, default=300)
    ap.add_argument("--lfw-per-id", type=int, default=4)
    ap.add_argument("--run-id", default=None)
    a = ap.parse_args(argv)

    run_id = a.run_id or "C" + eio.utc_now_iso(ms=False).replace("-", "").replace(":", "")
    if eio.is_inside(a.out, RESULTS_DIR) and S.is_dummy_run(run_id):
        raise SystemExit("refusing DUMMY run ids in eval/results/")
    items = load_team(a.captures, a.subjects, a.enrol_k)
    _, man = eio.read_csv(a.captures / "manifest.csv")
    paths = {r["image_id"]: a.captures / r["file"] for r in man}
    if a.lfw_dir:
        lfw_items, lfw_paths = load_lfw(a.lfw_dir, a.lfw_max_ids, a.lfw_per_id)
        items += lfw_items
        paths |= lfw_paths
    if not items:
        raise SystemExit(f"no images in {a.captures}/manifest.csv - run collect_faces.py first")
    embedder = EdgeEmbedder(a.models)
    stats = embed_all(items, paths, embedder, a.captures / ".embcache.npz")
    rows = comparisons(items, "arcface", embedder.model_id, run_id, a.template_rule)
    eio.write_csv(a.out, S.COMPARISON_COLUMNS, rows)
    counts = Counter((r["split"], "genuine" if r["genuine"] else "impostor", r["source"]) for r in rows)
    man_out = eio.RunManifest(run_id, "compare", a.out.parent / "runs", {
        "out": str(a.out), "model": embedder.model_id, "template_rule": a.template_rule, "enrol_k": a.enrol_k,
        "embedding_stats": dict(stats), "subjects_sha256": eio.sha256_file(a.subjects),
        "manifest_sha256": eio.sha256_file(a.captures / "manifest.csv"),
        "lfw": {"dir": str(a.lfw_dir), "max_ids": a.lfw_max_ids, "per_id": a.lfw_per_id} if a.lfw_dir else None,
        "counts": {"/".join(k): v for k, v in sorted(counts.items())}, "rows": len(rows)})
    man_out.close()
    print(f"wrote {a.out}: {len(rows)} comparisons; {dict(stats)}")
    for k, v in sorted(counts.items()):
        print(f"  {'/'.join(k)}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
