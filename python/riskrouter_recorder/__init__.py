"""
riskrouter_recorder: evidence from where decisions are already made.
docs/recorders.md in the RiskRouter repository; https://riskrouter.eu/integrate#recorders

    from riskrouter_recorder import Recorder, EvidenceHandler

    recorder = Recorder(api_key=os.environ["RISKROUTER_API_KEY"], journal="evidence.jsonl")
    recorder.record({"kind": "ai.decision", "record_id": "dec-2291", "model": "credit-v4", "outcome": "refer"})

    logging.getLogger("decisions").addHandler(EvidenceHandler(recorder))
    log.info("referred", extra={"evidence": {"kind": "ai.decision", "record_id": "dec-2292", "outcome": "refer"}})

    recorder.close()        # on shutdown: sends what is pending

The record and its salt stay here, in your journal. Only SHA-256(salt || RFC 8785 of
the record) and the kind are sent, in batches, to any log that speaks the RiskRouter
evidence API: ours, your own instance, or none (with no key, nothing leaves the process).

A record is written to the journal, and synced to disk, before its digest is sent, so a
crash or an outage never loses one: the next flush sends it. If a confirmation is lost
in transit, a digest may be sent twice and becomes two leaves; either one proves it.

Python 3.8 or later, standard library only. The OpenTelemetry span processor implements
the SDK's interface by shape, so OpenTelemetry is not a dependency.
"""
import functools
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

__all__ = ["Recorder", "EvidenceHandler", "EvidenceSpanProcessor", "canonical_record", "record_digest", "digest_file",
           "RecordError", "JOURNAL_FORMAT", "BUNDLE_FORMAT"]

JOURNAL_FORMAT = "riskrouter-evidence-journal|1"
BUNDLE_FORMAT = "riskrouter-record-bundle|1"
KIND = re.compile(r"^[a-z0-9][a-z0-9.-]{0,39}\Z")
_RECORD_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}\Z")
_BATCH_MAX = 500
_log = logging.getLogger("riskrouter_recorder")


class RecordError(ValueError):
    pass


# ----------------------------------------------------------- the canonical record

def canonical_record(record, _depth=1, _where="$"):
    """RFC 8785 of a record, under the profile the specification fixes (https://riskrouter.eu/spec#records):
    keys a-z, 0-9 and _ starting with a letter; whole numbers within +/-(2^53 - 1); valid Unicode; 32 deep at most."""
    if _depth == 1 and not isinstance(record, dict):
        raise RecordError("a record is a JSON object")
    if _depth > 32:
        raise RecordError("%s: nested more than 32 deep" % _where)
    v = record
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")) or not v.is_integer():
            raise RecordError("%s: numbers must be whole; write money as integer cents" % _where)
        v = int(v)
    if isinstance(v, int):
        if abs(v) > 2 ** 53 - 1:
            raise RecordError("%s: integers must be within +/-(2^53 - 1)" % _where)
        return str(v)
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise RecordError("%s: the string is not valid Unicode" % _where)
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_record(x, _depth + 1, "%s[%d]" % (_where, i)) for i, x in enumerate(v)) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str) or not _RECORD_KEY.match(k):
                raise RecordError("%s: key %r is not lower-case a-z, 0-9 and _ starting with a letter" % (_where, k))
        return "{" + ",".join(json.dumps(k) + ":" + canonical_record(v[k], _depth + 1, _where + "." + k) for k in sorted(v)) + "}"
    raise RecordError("%s: %s is not a JSON value a record may hold" % (_where, type(v).__name__))


def record_digest(salt_hex, record):
    """SHA-256(salt || UTF-8(canonical)), lowercase hex."""
    return hashlib.sha256(bytes.fromhex(salt_hex) + canonical_record(record).encode("utf-8")).hexdigest()


def digest_file(path, chunk=1 << 20):
    """SHA-256 of a file, read in chunks, for a record that names a file it does not contain:
    a call recording (mifid.call-recording), an invoice, a release. The file stays where it is."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------- journal

class _Journal:
    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"format": JOURNAL_FORMAT}) + "\n")
        self.entries = {}
        self.chains = {}   # chain_tag -> (seq, digest) of the last record journalled in it
        with open(path, "r", encoding="utf-8") as fh:
            lines = [json.loads(l) for l in fh if l.strip()]
        if not lines or lines[0].get("format") != JOURNAL_FORMAT:
            raise ValueError("%s is not a %s journal" % (path, JOURNAL_FORMAT))
        for l in lines[1:]:
            e = self.entries.setdefault(l["record_digest"], {})
            if l["type"] == "pending" and l.get("chain_tag"):
                e.update(chain_tag=l["chain_tag"], chain_seq=l["chain_seq"])
                if l["chain_tag"] not in self.chains or self.chains[l["chain_tag"]][0] < l["chain_seq"]:
                    self.chains[l["chain_tag"]] = (l["chain_seq"], l["record_digest"])
            if l["type"] == "pending":
                e.setdefault("state", "pending")
                e.update(kind=l["kind"], salt_hex=l["salt_hex"], record=l["record"])
            elif l["type"] == "recorded":
                e.update(state="recorded", leaf_index=l["leaf_index"], created_at=l.get("created_at"))
            elif l["type"] == "refused":
                e.update(state="refused", code=l.get("code"), reason=l.get("reason"))
        self.fh = open(path, "a", encoding="utf-8")

    def append(self, line):
        line = dict(line, at=_now())
        self.fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def close(self):
        self.fh.close()


# --------------------------------------------------------------------- recorder

class _LogError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code = status, code
        super().__init__("the log answered %s %s%s" % (status, code, ": " + message if message else ""))


class Recorder:
    """Keeps records in your journal and sends their digests, in batches, from a background thread.

    api_key   your key; without one nothing is sent (RISKROUTER_API_KEY)
    api       the log's base URL (RISKROUTER_BASE, default https://api.riskrouter.eu)
    journal   where records, salts and outcomes are kept (default ./evidence-journal.jsonl)
    signer    optional: an object with sign_claim(kind, digest), e.g. signer.py from the kit, for v3 leaves
    chain_secret  hex; with it, records go in numbered completeness chains (RISKROUTER_CHAIN_SECRET)
    chain     the chain a record goes in when record() names none
    """

    def __init__(self, api_key=None, api=None, journal="evidence-journal.jsonl", batch_size=_BATCH_MAX,
                 flush_interval=5.0, signer=None, timeout=20, start_thread=True, chain_secret=None, chain=None):
        self.chain_secret = chain_secret if chain_secret is not None else os.environ.get("RISKROUTER_CHAIN_SECRET")
        if self.chain_secret is not None and not re.match(r"^(?:[0-9a-f]{2}){16,64}\Z", self.chain_secret):
            raise ValueError("chain_secret is 16 to 64 bytes written as lowercase hex")
        self.default_chain = chain
        self.api_key = api_key if api_key is not None else os.environ.get("RISKROUTER_API_KEY")
        self.api = (api or os.environ.get("RISKROUTER_BASE") or "https://api.riskrouter.eu").rstrip("/")
        self.batch_size = max(1, min(_BATCH_MAX, int(batch_size)))
        self.signer = signer
        self.timeout = timeout
        self.last_error = None
        self._journal = _Journal(journal)
        self._lock = threading.Lock()          # the journal and its state
        self._flush_lock = threading.Lock()    # one flush at a time
        self._closed = False
        self._wake = threading.Event()
        self._interval = flush_interval
        self._thread = None
        if start_thread:
            self._thread = threading.Thread(target=self._run, name="riskrouter-recorder", daemon=True)
            self._thread.start()

    # -- keeping

    def record(self, record, kind=None, chain=None):
        """Keep a record; returns its digest and salt at once. The digest is sent at the next flush.

        With a chain secret, the record goes in a completeness chain (chain, or the recorder's default):
        chain_tag, chain_seq and chain_prev are added to it, so a record later left out is a gap.
        One recorder process writes a given chain."""
        if self._closed:
            raise RuntimeError("the recorder is closed")
        kind = kind if kind is not None else (record.get("kind") if isinstance(record, dict) else None)
        if not isinstance(kind, str) or not KIND.match(kind):
            raise RecordError("a record needs a kind: lower-case letters, digits, dots and hyphens, up to 40 characters")
        chain_name = chain if chain is not None else self.default_chain
        with self._lock:
            link = {}
            if chain_name is not None:
                if not self.chain_secret:
                    raise RecordError("a chain needs the recorder's chain_secret (RISKROUTER_CHAIN_SECRET)")
                if isinstance(record, dict) and any(f in record for f in ("chain_tag", "chain_seq", "chain_prev")):
                    raise RecordError("the recorder sets chain_tag, chain_seq and chain_prev itself")
                tag = self.chain_tag(chain_name)
                seq, prev = self._journal.chains.get(tag, (0, "0" * 64))
                link = {"chain_tag": tag, "chain_seq": seq + 1, "chain_prev": prev}
                record = dict(record, **link)
            salt_hex = secrets.token_hex(16)
            digest = record_digest(salt_hex, record)
            # A copy: what the caller changes afterwards is not what was digested.
            record = json.loads(canonical_record(record))
            chained = {"chain_tag": link["chain_tag"], "chain_seq": link["chain_seq"]} if link else {}
            self._journal.append(dict({"type": "pending", "record_digest": digest, "kind": kind, "salt_hex": salt_hex, "record": record}, **chained))
            self._journal.entries[digest] = dict({"state": "pending", "kind": kind, "salt_hex": salt_hex, "record": record}, **chained)
            if link:
                self._journal.chains[link["chain_tag"]] = (link["chain_seq"], digest)
        return dict({"record_digest": digest, "kind": kind, "salt_hex": salt_hex}, **chained)

    def chain_tag(self, name=None):
        """The chain_tag of a named chain, to give an auditor so they can ask the log about it."""
        name = name if name is not None else self.default_chain
        if not self.chain_secret or name is None:
            raise ValueError("no chain: the recorder needs a chain_secret and a chain name")
        return hmac.new(bytes.fromhex(self.chain_secret), ("riskrouter-chain-tag|1|" + str(name)).encode("utf-8"), hashlib.sha256).hexdigest()

    def completeness(self, name=None):
        """What you hand an auditor to show a chain is complete: the log's signed statement and every
        record of the chain in this journal (riskrouter-completeness-bundle|1)."""
        tag = self.chain_tag(name)
        pages, path = [], "/api/v2/evidence/chain?chain_tag=" + tag
        while path:
            status, body = self._call("GET", path)
            if status != 200:
                raise _LogError(status, ((body or {}).get("error") or {}).get("code"), "the chain statement could not be fetched")
            pages.append(body)
            path = body.get("next")
        with self._lock:
            records = [{"record": e["record"], "salt_hex": e["salt_hex"]} for e in self._journal.entries.values() if e.get("chain_tag") == tag]
        return {"format": "riskrouter-completeness-bundle|1", "chain": pages, "records": records}

    def _pending(self):
        with self._lock:
            return [dict(e, record_digest=d) for d, e in self._journal.entries.items() if e.get("state") == "pending"]

    # -- sending

    def _call(self, method, path, body=None):
        req = urllib.request.Request(self.api + path, method=method,
                                     data=None if body is None else json.dumps(body).encode("utf-8"))
        req.add_header("Accept", "application/json")
        req.add_header("Authorization", "Bearer " + self.api_key)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except ValueError:
                return e.code, None

    def _send(self, batch):
        entries = []
        for e in batch:
            entry = {"record_digest": e["record_digest"], "kind": e["kind"]}
            if e.get("chain_tag"):
                entry.update(chain_tag=e["chain_tag"], chain_seq=e["chain_seq"])
            if self.signer is not None:
                entry.update(self.signer.sign_claim(e["kind"], e["record_digest"]))
            entries.append(entry)
        status, body = self._call("POST", "/api/v2/evidence/batch", {"entries": entries})
        got = (body or {}).get("entries") if isinstance(body, dict) else None
        if status == 201 and isinstance(got, list) and len(got) == len(batch):
            with self._lock:
                for sent, answer in zip(batch, got):
                    if answer.get("record_digest") != sent["record_digest"]:
                        raise RuntimeError("the log answered for a different digest than was sent")
                    self._journal.append({"type": "recorded", "record_digest": answer["record_digest"], "leaf_index": answer["leaf_index"],
                                          "created_at": answer.get("created_at"), "leaf_version": answer.get("leaf_version", 2)})
                    self._journal.entries[answer["record_digest"]].update(state="recorded", leaf_index=answer["leaf_index"], created_at=answer.get("created_at"))
            return "recorded", len(batch)
        error = (body or {}).get("error", {}) if isinstance(body, dict) else {}
        code, message = error.get("code") or "HTTP_%d" % status, error.get("message") or ""
        if status == 400:
            m = re.match(r"^Entry (\d+):", message)
            bad = batch[int(m.group(1))] if m else (batch[0] if len(batch) == 1 else None)
            if bad is None:
                return "split", 0
            with self._lock:
                self._journal.append({"type": "refused", "record_digest": bad["record_digest"], "code": code, "reason": message[:300]})
                self._journal.entries[bad["record_digest"]].update(state="refused", code=code, reason=message)
            return "refused", 1
        raise _LogError(status, code, message)

    def flush(self):
        """Send every pending digest. Never raises: a failure leaves entries pending and is returned."""
        if not self.api_key:
            return {"sent": 0, "local_only": True, "pending": len(self._pending())}
        with self._flush_lock:
            recorded = refused = 0
            width = self.batch_size
            try:
                queue = self._pending()
                while queue:
                    outcome, n = self._send(queue[:width])
                    if outcome == "split":
                        width = 1
                        continue
                    recorded += n if outcome == "recorded" else 0
                    refused += n if outcome == "refused" else 0
                    queue = self._pending()
                self.last_error = None
                return {"sent": recorded + refused, "recorded": recorded, "refused": refused, "pending": 0}
            except Exception as e:  # never into the caller's decision path
                self.last_error = str(e)
                _log.warning("riskrouter-recorder: %s; %d pending", e, len(self._pending()))
                return {"error": str(e), "recorded": recorded, "refused": refused, "pending": len(self._pending())}

    def _run(self):
        while not self._closed:
            self._wake.wait(self._interval)
            self._wake.clear()
            if self._pending():
                self.flush()

    # -- afterwards

    def bundle(self, digest):
        """What you hand a supervisor: the record, its salt and the proof. Both verifiers check it offline."""
        with self._lock:
            e = self._journal.entries.get(digest)
        if e is None:
            raise KeyError("no such record in this journal")
        if e.get("state") != "recorded":
            raise ValueError("that record is %s, not recorded yet" % e.get("state"))
        status, proof = self._call("GET", "/api/v2/evidence/proof?leaf_index=%d" % e["leaf_index"])
        if status != 200:
            raise _LogError(status, (proof or {}).get("error", {}).get("code"), "the proof could not be fetched")
        return {"format": BUNDLE_FORMAT, "record": e["record"], "salt_hex": e["salt_hex"], "proof": proof}

    def lookup(self, digest):
        """Where one record stands, without the record or its salt."""
        with self._lock:
            e = self._journal.entries.get(digest)
        if e is None:
            return None
        out = {"record_digest": digest, "kind": e.get("kind"), "state": e.get("state", "pending")}
        if out["state"] == "recorded":
            out.update(leaf_index=e.get("leaf_index"), created_at=e.get("created_at"))
        if out["state"] == "refused":
            out["code"] = e.get("code")
        return out

    def status(self):
        counts = {"pending": 0, "recorded": 0, "refused": 0}
        with self._lock:
            for e in self._journal.entries.values():
                counts[e.get("state", "pending")] += 1
        return dict(counts, local_only=not self.api_key, last_error=self.last_error)

    def close(self):
        """Stop the background thread and send what is pending."""
        if self._closed:
            return
        self._closed = True
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=self.timeout + 5)
        self.flush()
        self._journal.close()

    # -- drop-in: a function

    def decision(self, kind, build=None):
        """Decorate a function that makes a decision. By default the record holds digests of its
        arguments and result, not the values; pass build(args, kwargs, result) -> record to keep
        the fields a regime pack asks for. Recording never raises into the caller."""
        def wrap(fn):
            @functools.wraps(fn)
            def evidenced(*args, **kwargs):
                result = fn(*args, **kwargs)
                try:
                    record = build(args, kwargs, result) if build else {
                        "kind": kind, "decision": fn.__name__, "decided_at": _now(),
                        "input_digest": _digest_of({"args": list(args), "kwargs": kwargs}), "output_digest": _digest_of(result)}
                    self.record(record, kind=kind)
                except Exception as e:
                    _log.warning("riskrouter-recorder: the decision was made but not recorded: %s", e)
                return result
            return evidenced
        return wrap


def _digest_of(value):
    try:
        text = canonical_record({"value": value})
    except (RecordError, TypeError):
        text = json.dumps(value, default=repr, sort_keys=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -------------------------------------------------------- drop-in: logging

class EvidenceHandler(logging.Handler):
    """A logging handler: a log call with extra={"evidence": record} records it. Other records pass by.

        log.info("referred", extra={"evidence": {"kind": "ai.decision", "record_id": "dec-2292", "outcome": "refer"}})
    """

    def __init__(self, recorder, level=logging.NOTSET):
        super().__init__(level)
        self.recorder = recorder

    def emit(self, log_record):
        evidence = getattr(log_record, "evidence", None)
        if evidence is None:
            return
        try:
            self.recorder.record(evidence)
        except Exception:
            self.handleError(log_record)

    def flush(self):
        self.recorder.flush()


# ------------------------------------------------- drop-in: OpenTelemetry spans

def _record_key(name):
    k = re.sub(r"[^a-z0-9_]", "_", name.lower())
    k = re.sub(r"^[^a-z]+", "", k)[:64]
    return k if _RECORD_KEY.match(k) else None


def _record_value(v):
    if isinstance(v, float) and not v.is_integer():
        return repr(v)
    if isinstance(v, (list, tuple)):
        return [_record_value(x) for x in v]
    return v


def _ns_iso(ns):
    return datetime.fromtimestamp(ns / 1e9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ns else None


try:  # the SDK's own base class when it is installed, so hooks it adds later have defaults; never required
    from opentelemetry.sdk.trace import SpanProcessor as _SpanProcessorBase
except ImportError:  # pragma: no cover
    _SpanProcessorBase = object


class EvidenceSpanProcessor(_SpanProcessorBase):
    """An OpenTelemetry span processor (on_start, on_end, shutdown, force_flush). A span with the
    attribute evidence.kind becomes a record: its name, trace and span ids, times, status, and every
    other evidence.* attribute. Other attributes are not recorded.

        provider.add_span_processor(EvidenceSpanProcessor(recorder))
        span.set_attribute("evidence.kind", "ai.decision")
    """

    def __init__(self, recorder):
        self.recorder = recorder

    def _on_ending(self, span):
        pass

    def on_start(self, span, parent_context=None):
        pass

    def on_end(self, span):
        try:
            attrs = dict(span.attributes or {})
            kind = attrs.get("evidence.kind")
            if not kind:
                return
            fields = {}
            for name, value in attrs.items():
                if name.startswith("evidence.") and name != "evidence.kind":
                    key = _record_key(name[len("evidence."):])
                    if key:
                        fields[key] = _record_value(value)
            ctx = span.get_span_context()
            status = getattr(getattr(span, "status", None), "status_code", None)
            self.recorder.record({
                "kind": kind, "name": span.name, "trace_id": format(ctx.trace_id, "032x"), "span_id": format(ctx.span_id, "016x"),
                "started_at": _ns_iso(span.start_time), "ended_at": _ns_iso(span.end_time),
                "status": getattr(status, "name", "UNSET"), "fields": fields}, kind=kind)
        except Exception as e:
            _log.warning("riskrouter-recorder: a span was not recorded: %s", e)

    def shutdown(self):
        self.recorder.close()

    def force_flush(self, timeout_millis=30000):
        return "error" not in self.recorder.flush()
