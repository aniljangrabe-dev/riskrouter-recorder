"""
The Python recorder against a real log: the RiskRouter Worker on the local harness
(tests/recorders.test.mjs starts it and runs this file with RISKROUTER_BASE,
RISKROUTER_API_KEY, RR_KEY_FILE and RR_VECTORS set).

    python3 -m unittest discover -s recorders/python/tests
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from riskrouter_recorder import (Recorder, EvidenceHandler, EvidenceSpanProcessor, canonical_record,  # noqa: E402
                                 record_digest, RecordError, JOURNAL_FORMAT)

ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BASE = os.environ.get("RISKROUTER_BASE")
KEY = os.environ.get("RISKROUTER_API_KEY")
KEY_FILE = os.environ.get("RR_KEY_FILE")
VECTORS = os.environ.get("RR_VECTORS", os.path.join(ROOT, "spec-vectors.json"))
live = unittest.skipUnless(BASE and KEY and KEY_FILE, "no log to record to (run through tests/recorders.test.mjs)")


def journal_path():
    return os.path.join(tempfile.mkdtemp(prefix="rr-rec-"), "evidence.jsonl")


def lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def verify_bundle(bundle):
    f = os.path.join(tempfile.mkdtemp(prefix="rr-bundle-"), "bundle.json")
    with open(f, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh)
    return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "python", "riskrouter_verify.py"), f, "--key", KEY_FILE],
                          capture_output=True, text=True)


class Canonical(unittest.TestCase):
    def test_the_specifications_record_vectors(self):
        with open(VECTORS, encoding="utf-8") as fh:
            v = json.load(fh)
        for r in v["records"]:
            self.assertEqual(canonical_record(r["record"]), r["canonical"], r["name"])
            self.assertEqual(record_digest(r["salt_hex"], r["record"]), r["record_digest"], r["name"])
        for r in v["records_refused"]:
            with self.assertRaises(RecordError, msg=r["name"]):
                canonical_record(r["record"])


class LocalOnly(unittest.TestCase):
    def test_without_a_key_nothing_leaves_and_the_journal_keeps_everything(self):
        path = journal_path()
        r = Recorder(api_key="", api="http://127.0.0.1:9", journal=path, start_thread=False)
        r.record({"kind": "ai.decision", "record_id": "a"})
        self.assertEqual(r.flush(), {"sent": 0, "local_only": True, "pending": 1})
        r.close()
        got = lines(path)
        self.assertEqual(got[0], {"format": JOURNAL_FORMAT})
        self.assertEqual(got[1]["type"], "pending")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    def test_a_record_without_a_valid_kind_is_refused_at_once(self):
        r = Recorder(api_key="", journal=journal_path(), start_thread=False)
        for bad in ({}, {"kind": "Upper"}, {"kind": "x" * 41}):
            with self.assertRaises(RecordError):
                r.record(bad)
        with self.assertRaises(RecordError):
            r.record({"kind": "ai.decision", "amount": 12.5})


@live
class Recording(unittest.TestCase):
    def test_records_become_leaves_and_bundles_verify_with_the_independent_verifier(self):
        path = journal_path()
        r = Recorder(api=BASE, api_key=KEY, journal=path, start_thread=False)
        kept = [r.record({"kind": "ai.decision", "record_id": "py-%d" % i, "outcome": "refer"}) for i in range(3)]
        out = r.flush()
        self.assertEqual(out["recorded"], 3, out)
        recorded = [l for l in lines(path) if l.get("type") == "recorded"]
        self.assertEqual([l["record_digest"] for l in recorded], [k["record_digest"] for k in kept])
        bundle = r.bundle(kept[1]["record_digest"])
        self.assertEqual(bundle["record"]["record_id"], "py-1")
        v = verify_bundle(bundle)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        r.close()

    def test_the_record_itself_never_leaves_the_process(self):
        r = Recorder(api=BASE, api_key=KEY, journal=journal_path(), start_thread=False)
        sent = []
        real = r._call
        r._call = lambda method, path, body=None: (sent.append(json.dumps(body)), real(method, path, body))[1]
        r.record({"kind": "ai.decision", "customer_ref": "cust-SECRET-7731", "outcome": "decline"})
        self.assertEqual(r.flush()["recorded"], 1)
        self.assertTrue(sent)
        self.assertFalse(any("SECRET" in s or "decline" in s for s in sent), sent)
        r.close()

    def test_an_outage_leaves_entries_pending_and_a_restart_sends_them(self):
        path = journal_path()
        r = Recorder(api="http://127.0.0.1:9", api_key=KEY, journal=path, start_thread=False, timeout=2)
        k = r.record({"kind": "dora.incident", "record_id": "inc-1"})
        out = r.flush()
        self.assertIn("error", out)
        self.assertEqual(out["pending"], 1)
        self.assertEqual(r.status()["pending"], 1)
        r._journal.close()  # the process dies here
        again = Recorder(api=BASE, api_key=KEY, journal=path, start_thread=False)
        self.assertEqual(again.flush()["recorded"], 1)
        self.assertEqual(again.status()["recorded"], 1)
        self.assertEqual(verify_bundle(again.bundle(k["record_digest"])).returncode, 0)
        again.close()

    def test_the_logging_handler_records_evidence_and_nothing_else(self):
        r = Recorder(api=BASE, api_key=KEY, journal=journal_path(), start_thread=False)
        log = logging.getLogger("decisions-test")
        log.setLevel(logging.INFO)
        log.propagate = False
        handler = EvidenceHandler(r)
        log.addHandler(handler)
        log.info("an ordinary line")
        log.info("referred", extra={"evidence": {"kind": "ai.decision", "record_id": "log-1", "outcome": "refer"}})
        self.assertEqual(r.status()["pending"], 1)
        handler.flush()
        self.assertEqual(r.status()["recorded"], 1)
        log.removeHandler(handler)
        r.close()

    def test_the_decorator_records_digests_by_default_and_the_fields_it_is_given(self):
        r = Recorder(api=BASE, api_key=KEY, journal=journal_path(), start_thread=False)

        @r.decision("ai.decision")
        def score(income_cents, applicant_ref):
            return {"outcome": "refer", "score": 612}

        @r.decision("mifid.suitability", build=lambda a, k, res: {"kind": "mifid.suitability", "client_ref": a[0], "suitable": res})
        def assess(client_ref):
            return True

        self.assertEqual(score(420000, "app-9"), {"outcome": "refer", "score": 612})
        self.assertTrue(assess("cl-30918"))
        records = [e["record"] for e in r._journal.entries.values()]
        default = next(x for x in records if x["kind"] == "ai.decision")
        self.assertEqual(sorted(default), ["decided_at", "decision", "input_digest", "kind", "output_digest"])
        self.assertNotIn("app-9", json.dumps(default))
        self.assertIn({"kind": "mifid.suitability", "client_ref": "cl-30918", "suitable": True}, records)
        self.assertEqual(r.flush()["recorded"], 2)
        r.close()


try:
    from opentelemetry.sdk.trace import TracerProvider
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


class OpenTelemetry(unittest.TestCase):
    def test_otel_is_there_when_required(self):
        if os.environ.get("REQUIRE_OTEL"):
            self.assertTrue(HAS_OTEL, "REQUIRE_OTEL is set but opentelemetry-sdk is not installed")

    @unittest.skipUnless(HAS_OTEL, "opentelemetry-sdk not installed")
    @live
    def test_a_span_with_evidence_kind_becomes_a_record_and_others_do_not(self):
        r = Recorder(api=BASE, api_key=KEY, journal=journal_path(), start_thread=False)
        provider = TracerProvider()
        provider.add_span_processor(EvidenceSpanProcessor(r))
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("unrelated"):
            pass
        with tracer.start_as_current_span("credit-decision") as span:
            span.set_attribute("evidence.kind", "ai.decision")
            span.set_attribute("evidence.model.version", "credit-v4")
            span.set_attribute("evidence.score", 0.73)
            span.set_attribute("http.url", "https://internal.example/secret")
        entries = list(r._journal.entries.values())
        self.assertEqual(len(entries), 1)
        rec = entries[0]["record"]
        self.assertEqual(rec["name"], "credit-decision")
        self.assertEqual(rec["fields"], {"model_version": "credit-v4", "score": "0.73"})
        self.assertNotIn("internal.example", json.dumps(rec))
        self.assertTrue(provider.force_flush())
        self.assertEqual(r.status()["recorded"], 1)
        provider.shutdown()


if __name__ == "__main__":
    unittest.main()
