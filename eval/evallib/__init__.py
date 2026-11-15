"""Shared code for the HID kiosk evaluation harness (eval/).

Modules:
  stats   - Clopper-Pearson bounds, rule of 3, trials-needed, bootstrap quantile CIs, conservative formatting
  schema  - CSV schemas, enums, reason-code classes, validation (attempts / comparisons / scenarios)
  det     - DET points, EER, operating points
  style   - dataviz palette (light/dark) for matplotlib charts
  io      - CSV helpers, sha256, run manifests, config loading
"""

from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = EVAL_DIR.parent
RESULTS_DIR = EVAL_DIR / "results"
CAPTURES_DIR = EVAL_DIR / "captures"
THRESHOLDS_PATH = PROJECT_DIR / "config" / "thresholds.yaml"
