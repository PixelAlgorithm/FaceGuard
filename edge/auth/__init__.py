"""System-user authentication and role-based access control for the edge (and, vendored, the cloud).

Keep this file free of imports: the cloud deploy artifact vendor-copies an explicit allowlist of this
package (__init__.py, rbac.py, tokens.py; see cloud/infra/build_artifact.sh), so importing `edge.auth`
must never pull in `cryptography`, `pyotp` or FastAPI.
"""
