"""Key-value storage with conditional writes: memory (tests), SQLite (no-DynamoDB fallback), DynamoDB.

Every backend implements the same primitives so idempotency (put_if_absent) and optimistic concurrency
(cas on `_rev`) behave identically in tests, on a laptop and on AWS:

    get(ns, key)                       -> item | None     (expired items are invisible)
    put(ns, key, item, ttl=None)                          (unconditional upsert)
    put_if_absent(ns, key, item, ttl)  -> bool            (False if a live item exists)
    cas(ns, key, item, expected_rev)   -> bool            (expected_rev None == must not exist)
    delete(ns, key)
    list(ns, prefix="", start="")      -> [(key, item)]   (ascending key order; prefix match is case-sensitive,
                                                           start = inclusive lower key bound, a key-range query)

`ttl` is an absolute epoch-seconds expiry (DynamoDB TTL attribute `ttl`). Items carry `_rev`.
DynamoDB layout: three tables with the same key schema (pk HASH = namespace, sk RANGE = key):
users -> DDB_TABLE_USERS, decisions* -> DDB_TABLE_DECISIONS, everything else -> DDB_TABLE_STATE.
"""

from __future__ import annotations

import copy
import json
import os
import sqlite3
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

RESERVED = ("pk", "sk", "_rev", "ttl")
_PUT_RETRIES = 8


class KVError(RuntimeError):
    pass


class StoreUnavailable(RuntimeError):
    """The store could not answer and no last-good value exists: callers answer 503, never guess."""


def _prefix_upper(prefix: str) -> str | None:
    """Smallest string greater than every string starting with `prefix` (None = no upper bound)."""
    for i in range(len(prefix) - 1, -1, -1):
        if ord(prefix[i]) < 0x10FFFF:
            return prefix[:i] + chr(ord(prefix[i]) + 1)
    return None


class KV(Protocol):
    backend: str

    def get(self, ns: str, key: str) -> dict | None: ...
    def put(self, ns: str, key: str, item: dict, ttl: int | None = None) -> None: ...
    def put_if_absent(self, ns: str, key: str, item: dict, ttl: int | None = None) -> bool: ...
    def cas(self, ns: str, key: str, item: dict, expected_rev: int | None, ttl: int | None = None) -> bool: ...
    def delete(self, ns: str, key: str) -> None: ...
    def list(self, ns: str, prefix: str = "", start: str = "") -> list[tuple[str, dict]]: ...
    def ping(self) -> None: ...


def _clean(item: dict) -> dict:
    return {k: v for k, v in item.items() if k not in RESERVED}


def _alive(ttl: int | None, now: float | None = None) -> bool:
    return ttl is None or ttl > (time.time() if now is None else now)


# ----------------------------------------------------------------------------- memory
class MemoryKV:
    backend = "memory"

    def __init__(self, now_fn=time.time) -> None:
        self._d: dict[tuple[str, str], tuple[dict, int, int | None]] = {}
        self._lock = threading.Lock()
        self._now = now_fn

    def _live(self, ns: str, key: str) -> tuple[dict, int, int | None] | None:
        v = self._d.get((ns, key))
        if v is None or not _alive(v[2], self._now()):
            return None
        return v

    def get(self, ns: str, key: str) -> dict | None:
        with self._lock:
            v = self._live(ns, key)
            if v is None:
                return None
            out = copy.deepcopy(v[0])
            out["_rev"] = v[1]
            return out

    def put(self, ns: str, key: str, item: dict, ttl: int | None = None) -> None:
        with self._lock:
            v = self._live(ns, key)
            self._d[(ns, key)] = (copy.deepcopy(_clean(item)), (v[1] if v else 0) + 1, ttl)

    def put_if_absent(self, ns: str, key: str, item: dict, ttl: int | None = None) -> bool:
        return self.cas(ns, key, item, None, ttl)

    def cas(self, ns: str, key: str, item: dict, expected_rev: int | None, ttl: int | None = None) -> bool:
        with self._lock:
            v = self._live(ns, key)
            if expected_rev is None:
                if v is not None:
                    return False
                self._d[(ns, key)] = (copy.deepcopy(_clean(item)), 1, ttl)
                return True
            if v is None or v[1] != expected_rev:
                return False
            self._d[(ns, key)] = (copy.deepcopy(_clean(item)), expected_rev + 1, ttl)
            return True

    def delete(self, ns: str, key: str) -> None:
        with self._lock:
            self._d.pop((ns, key), None)

    def list(self, ns: str, prefix: str = "", start: str = "") -> list[tuple[str, dict]]:
        with self._lock:
            out = []
            for (n, k), (item, rev, ttl) in self._d.items():
                if n == ns and k.startswith(prefix) and k >= start and _alive(ttl, self._now()):
                    it = copy.deepcopy(item)
                    it["_rev"] = rev
                    out.append((k, it))
        return sorted(out, key=lambda kv: kv[0])

    def ping(self) -> None:
        return None


# ----------------------------------------------------------------------------- sqlite
class SqliteKV:
    """Single-file store for EC2-without-DynamoDB or laptop runs. File mode 0600 (may hold e-mails)."""

    backend = "sqlite"

    def __init__(self, path: str, now_fn=time.time) -> None:
        self._now = now_fn
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        new = not p.exists()
        self._conn = sqlite3.connect(str(p), check_same_thread=False, isolation_level=None, timeout=5)
        if new:
            os.chmod(p, 0o600)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS kv (ns TEXT NOT NULL, key TEXT NOT NULL, item TEXT NOT NULL,"
                " rev INTEGER NOT NULL, ttl INTEGER, PRIMARY KEY (ns, key))"
            )
        self._ops = 0

    def _row(self, ns: str, key: str) -> tuple[str, int, int | None] | None:
        r = self._conn.execute("SELECT item, rev, ttl FROM kv WHERE ns=? AND key=?", (ns, key)).fetchone()
        if r is None or not _alive(r[2], self._now()):
            return None
        return r

    def _maybe_purge(self) -> None:
        self._ops += 1
        if self._ops % 200 == 0:
            self._conn.execute("DELETE FROM kv WHERE ttl IS NOT NULL AND ttl <= ?", (int(self._now()),))

    def get(self, ns: str, key: str) -> dict | None:
        with self._lock:
            r = self._row(ns, key)
        if r is None:
            return None
        item = json.loads(r[0])
        item["_rev"] = r[1]
        return item

    def put(self, ns: str, key: str, item: dict, ttl: int | None = None) -> None:
        data = json.dumps(_clean(item), ensure_ascii=False)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                r = self._row(ns, key)
                self._conn.execute(
                    "INSERT OR REPLACE INTO kv (ns, key, item, rev, ttl) VALUES (?,?,?,?,?)",
                    (ns, key, data, (r[1] if r else 0) + 1, ttl),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._maybe_purge()

    def put_if_absent(self, ns: str, key: str, item: dict, ttl: int | None = None) -> bool:
        return self.cas(ns, key, item, None, ttl)

    def cas(self, ns: str, key: str, item: dict, expected_rev: int | None, ttl: int | None = None) -> bool:
        data = json.dumps(_clean(item), ensure_ascii=False)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                r = self._row(ns, key)
                if expected_rev is None:
                    ok = r is None
                    new_rev = 1
                else:
                    ok = r is not None and r[1] == expected_rev
                    new_rev = expected_rev + 1
                if ok:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO kv (ns, key, item, rev, ttl) VALUES (?,?,?,?,?)",
                        (ns, key, data, new_rev, ttl),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._maybe_purge()
        return ok

    def delete(self, ns: str, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM kv WHERE ns=? AND key=?", (ns, key))

    def list(self, ns: str, prefix: str = "", start: str = "") -> list[tuple[str, dict]]:
        # Key-range query (case-sensitive, uses the primary key): LIKE is case-insensitive for ASCII in SQLite,
        # so prefix "u_A" also returned "u_a..." rows.
        lower = max(prefix, start)
        upper = _prefix_upper(prefix) if prefix else None
        sql = "SELECT key, item, rev, ttl FROM kv WHERE ns=? AND key >= ?"
        args: list[Any] = [ns, lower]
        if upper is not None:
            sql += " AND key < ?"
            args.append(upper)
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY key", args).fetchall()
        out = []
        for k, data, rev, ttl in rows:
            if _alive(ttl, self._now()):
                it = json.loads(data)
                it["_rev"] = rev
                out.append((k, it))
        return out

    def ping(self) -> None:
        with self._lock:
            self._conn.execute("SELECT 1").fetchone()


# ----------------------------------------------------------------------------- dynamodb
def _to_ddb(obj: Any) -> Any:
    return json.loads(json.dumps(obj, ensure_ascii=False), parse_float=Decimal)


def _from_ddb(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return int(obj) if obj.as_tuple().exponent >= 0 else float(obj)
    if isinstance(obj, dict):
        return {k: _from_ddb(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple | set):
        return [_from_ddb(v) for v in obj]
    return obj


class DynamoKV:
    backend = "dynamodb"

    def __init__(self, client, *, users_table: str, decisions_table: str, state_table: str,
                 now_fn=time.time) -> None:
        from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

        self._now = now_fn
        self._c = client
        self._ser = TypeSerializer()
        self._de = TypeDeserializer()
        self._users = users_table
        self._decisions = decisions_table
        self._state = state_table

    def _table(self, ns: str) -> str:
        if ns == "users":
            return self._users
        if ns.startswith("decisions"):
            return self._decisions
        return self._state

    def _marshal(self, ns: str, key: str, item: dict, rev: int, ttl: int | None) -> dict:
        body = _to_ddb(_clean(item))
        body.update({"pk": ns, "sk": key, "_rev": rev})
        if ttl is not None:
            body["ttl"] = int(ttl)
        return {k: self._ser.serialize(v) for k, v in body.items()}

    def _unmarshal(self, raw: dict) -> dict:
        d = {k: self._de.deserialize(v) for k, v in raw.items()}
        rev = int(d.get("_rev", 0))
        out = _from_ddb(_clean(d))
        out["_rev"] = rev
        return out

    def get(self, ns: str, key: str) -> dict | None:
        r = self._c.get_item(TableName=self._table(ns), Key={"pk": {"S": ns}, "sk": {"S": key}},
                             ConsistentRead=True)
        raw = r.get("Item")
        if not raw:
            return None
        ttl = raw.get("ttl", {}).get("N")
        if ttl is not None and not _alive(int(ttl), self._now()):
            return None
        return self._unmarshal(raw)

    def put(self, ns: str, key: str, item: dict, ttl: int | None = None) -> None:
        """Unconditional upsert with a monotonic `_rev`: read-then-conditional-write, retried, so two concurrent
        puts can never both write the same rev (a later CAS on that rev would then clobber one of them)."""
        for _ in range(_PUT_RETRIES):
            cur = self.get(ns, key)
            if self.cas(ns, key, item, cur["_rev"] if cur else None, ttl):
                return
        raise KVError(f"put {ns}/{key}: contention")

    def put_if_absent(self, ns: str, key: str, item: dict, ttl: int | None = None) -> bool:
        return self.cas(ns, key, item, None, ttl)

    def cas(self, ns: str, key: str, item: dict, expected_rev: int | None, ttl: int | None = None) -> bool:
        from botocore.exceptions import ClientError

        now = int(self._now())
        if expected_rev is None:
            cond = "attribute_not_exists(pk) OR #ttl <= :now"
            names = {"#ttl": "ttl"}
            values = {":now": {"N": str(now)}}
            rev = 1
        else:
            # an expired (TTL-passed, not yet reaped) item is invisible to get(): it must not satisfy a CAS either
            cond = "#rev = :rev AND (attribute_not_exists(#ttl) OR #ttl > :now)"
            names = {"#rev": "_rev", "#ttl": "ttl"}
            values = {":rev": {"N": str(expected_rev)}, ":now": {"N": str(now)}}
            rev = expected_rev + 1
        try:
            self._c.put_item(
                TableName=self._table(ns),
                Item=self._marshal(ns, key, item, rev, ttl),
                ConditionExpression=cond,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise

    def delete(self, ns: str, key: str) -> None:
        self._c.delete_item(TableName=self._table(ns), Key={"pk": {"S": ns}, "sk": {"S": key}})

    def list(self, ns: str, prefix: str = "", start: str = "") -> list[tuple[str, dict]]:
        values: dict[str, Any] = {":ns": {"S": ns}}
        cond = "pk = :ns"
        if start and start > prefix:  # key range: start .. end of the prefix
            values[":s"] = {"S": start}
            upper = _prefix_upper(prefix) if prefix else None
            if upper is not None:
                cond += " AND sk BETWEEN :s AND :e"
                values[":e"] = {"S": upper}
            else:
                cond += " AND sk >= :s"
        elif prefix:
            cond += " AND begins_with(sk, :p)"
            values[":p"] = {"S": prefix}
        kwargs: dict[str, Any] = {"TableName": self._table(ns), "KeyConditionExpression": cond,
                                  "ExpressionAttributeValues": values, "ConsistentRead": True}
        out: list[tuple[str, dict]] = []
        while True:
            r = self._c.query(**kwargs)
            for raw in r.get("Items", []):
                ttl = raw.get("ttl", {}).get("N")
                if ttl is not None and not _alive(int(ttl), self._now()):
                    continue
                if prefix and not raw["sk"]["S"].startswith(prefix):  # BETWEEN includes the upper bound itself
                    continue
                out.append((raw["sk"]["S"], self._unmarshal(raw)))
            if "LastEvaluatedKey" not in r:
                break
            kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]
        return out

    def ping(self) -> None:
        self._c.get_item(TableName=self._state, Key={"pk": {"S": "__health__"}, "sk": {"S": "ping"}})
