"""Ledger tests against a local stand-in for Supabase's PostgREST API.

Running these against the real Supabase would make the test suite depend on
network access and on somebody's project still existing. A local server that
speaks the same request shape gives the same coverage of our code — which is
the part under test — without either dependency.

Run with:  python -m tests.test_ledger
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, ".")

from core.ledger import (  # noqa: E402
    LedgerConfig,
    LedgerStatus,
    NullLedger,
    SupabaseLedger,
    build_ledger,
)
from core.payload import PayloadRecord  # noqa: E402

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


# --------------------------------------------------------------------------
# Fake PostgREST
# --------------------------------------------------------------------------

STORE = {"issued_records": [], "verification_log": []}
FAIL_MODE = {"on": False, "status": 401}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _table(self):
        return urlparse(self.path).path.rsplit("/", 1)[-1]

    def _send(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _guard(self):
        if FAIL_MODE["on"]:
            self._send(FAIL_MODE["status"], {"message": "row-level security violation"})
            return True
        return False

    def do_GET(self):
        if self._guard():
            return
        table = self._table()
        rows = STORE.get(table, [])
        params = parse_qs(urlparse(self.path).query)
        if "media_id" in params:
            wanted = params["media_id"][0].removeprefix("eq.")
            rows = [r for r in rows if r.get("media_id") == wanted]
        if "limit" in params:
            rows = rows[: int(params["limit"][0])]
        self._send(200, rows)

    def do_POST(self):
        if self._guard():
            return
        table = self._table()
        length = int(self.headers.get("Content-Length", 0))
        row = json.loads(self.rfile.read(length) or b"{}")

        if table == "issued_records":
            if any(r["media_id"] == row["media_id"] for r in STORE[table]):
                self._send(409, {"message": "duplicate key value"})
                return
            row.setdefault("revoked", False)
        STORE[table].append(row)
        self._send(201, [row])

    def do_PATCH(self):
        if self._guard():
            return
        table = self._table()
        length = int(self.headers.get("Content-Length", 0))
        patch = json.loads(self.rfile.read(length) or b"{}")
        params = parse_qs(urlparse(self.path).query)
        wanted = params.get("media_id", ["eq."])[0].removeprefix("eq.")

        updated = []
        for r in STORE[table]:
            if r.get("media_id") == wanted:
                r.update(patch)
                updated.append(r)
        self._send(200, updated)


def start_server():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


# --------------------------------------------------------------------------

def make_record(media_id="IMG-abc123", nonce="n1", cover_hash="h1"):
    return PayloadRecord(
        media_id=media_id,
        media_type="image",
        timestamp="2026-09-17T00:00:00+00:00",
        cover_hash=cover_hash,
        nonce=nonce,
        issuer="Team P1-4",
        n_lsb=2,
        payload_kind="text",
        filename="",
        mime="text/plain",
        content="hello",
        content_encrypted=False,
    )


def main():
    print("Testing ledger")
    server, base = start_server()
    ledger = SupabaseLedger(LedgerConfig(url=base, key="anon-test-key", timeout=3))

    print("\n=== registration and lookup ===")
    rec = make_record()
    res = ledger.register(rec, "aa:bb:cc")
    check("register succeeds", res.status == LedgerStatus.REGISTERED, res.message)

    res = ledger.check(rec)
    check("known record reports Registered", res.status == LedgerStatus.REGISTERED, res.message)

    check(
        "verifying the same file twice is not suspicious",
        ledger.check(rec).status == LedgerStatus.REGISTERED,
    )

    print("\n=== substitution ===")
    swapped = make_record(cover_hash="DIFFERENT")
    res = ledger.check(swapped)
    check("different cover hash reports Identity reused",
          res.status == LedgerStatus.SUBSTITUTED, res.message)
    check("substitution is blocking", res.is_blocking)

    renonce = make_record(nonce="n2")
    res = ledger.check(renonce)
    check("same hash, different nonce reports Identity reused",
          res.status == LedgerStatus.SUBSTITUTED, res.message)

    print("\n=== unknown record ===")
    res = ledger.check(make_record(media_id="IMG-neverseen"))
    check("unseen media ID reports Not in ledger", res.status == LedgerStatus.UNKNOWN)
    check("unknown is not blocking", not res.is_blocking)

    print("\n=== revocation ===")
    res = ledger.revoke("IMG-abc123", "superseded")
    check("revoke succeeds", res.status == LedgerStatus.REVOKED, res.message)

    res = ledger.check(rec)
    check("revoked record reports Revoked", res.status == LedgerStatus.REVOKED, res.message)
    check("revoked is blocking", res.is_blocking)
    check("revocation reason surfaces", "superseded" in res.message, res.message)

    res = ledger.revoke("IMG-doesnotexist", "typo")
    check("revoking an unknown ID reports Not in ledger", res.status == LedgerStatus.UNKNOWN)

    print("\n=== duplicate issuance ===")
    res = ledger.register(make_record(cover_hash="h2"), "aa:bb:cc")
    check("duplicate media ID is rejected", res.status == LedgerStatus.UNAVAILABLE, res.message)

    print("\n=== audit log ===")
    ledger.log_verification("IMG-abc123", "image", "Authentic", "Registered", "aa:bb:cc", "ok")
    rows = ledger.recent_verifications(10)
    check("verification is logged", len(rows) == 1 and rows[0]["verdict"] == "Authentic")

    issued = ledger.recent_issuances(10)
    check("issuances are listable", len(issued) == 1)

    print("\n=== failure handling ===")
    FAIL_MODE["on"] = True
    res = ledger.check(rec)
    check("RLS rejection degrades to Ledger offline", res.status == LedgerStatus.UNAVAILABLE)
    check("error message is surfaced", "401" in res.message, res.message)
    res = ledger.register(make_record(media_id="IMG-x"), "aa:bb:cc")
    check("register degrades rather than raising", res.status == LedgerStatus.UNAVAILABLE)
    try:
        ledger.log_verification("x", "image", "Authentic", "Registered", "f", "d")
        check("logging never raises", True)
    except Exception as exc:
        check("logging never raises", False, str(exc))
    check("listing returns empty on failure", ledger.recent_issuances(5) == [])
    FAIL_MODE["on"] = False

    print("\n=== unreachable host ===")
    dead = SupabaseLedger(LedgerConfig(url="http://127.0.0.1:1", key="k", timeout=1))
    res = dead.check(rec)
    check("unreachable host degrades to Ledger offline",
          res.status == LedgerStatus.UNAVAILABLE, res.message)

    print("\n=== null ledger ===")
    null = build_ledger(None)
    check("no config yields a NullLedger", isinstance(null, NullLedger))
    check("null ledger is disabled", not null.enabled)
    check("null check reports Disabled", null.check(rec).status == LedgerStatus.DISABLED)
    check("null status is not blocking", not null.check(rec).is_blocking)
    check("partial config yields a NullLedger",
          isinstance(build_ledger(LedgerConfig(url="https://x.supabase.co", key="")), NullLedger))

    server.shutdown()
    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    for name, detail in FAILED:
        print(f"  FAILED: {name}  {detail}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
