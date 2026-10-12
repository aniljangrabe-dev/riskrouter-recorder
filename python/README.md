# riskrouter-recorder (Python)

Evidence from where decisions are already made. Each record stays in your own journal; only
SHA-256(salt || RFC 8785 of the record) and its kind are sent, in batches from a background thread, to
a log that speaks the RiskRouter evidence API (https://riskrouter.eu/spec), or to none. Python 3.8 or
later, standard library only.

    pip install riskrouter-recorder

The same package is published at https://riskrouter.eu/kit/recorder/python/ if you would rather copy it into
your project.

```python
import logging, os
from riskrouter_recorder import Recorder, EvidenceHandler, EvidenceSpanProcessor

recorder = Recorder(api_key=os.environ.get("RISKROUTER_API_KEY"), journal="evidence.jsonl")

# 1. Directly
recorder.record({"kind": "ai.decision", "record_id": "dec-2291", "model": "credit-v4", "outcome": "refer"})

# 2. From logging: records emitted with extra={"evidence": record}
log = logging.getLogger("decisions")
log.addHandler(EvidenceHandler(recorder))
log.info("referred", extra={"evidence": {"kind": "ai.decision", "record_id": "dec-2292", "outcome": "refer"}})

# 3. Around a function that decides (digests of arguments and result by default)
@recorder.decision("ai.decision")
def score(application): ...

# 4. From OpenTelemetry: spans with evidence.kind become records
provider.add_span_processor(EvidenceSpanProcessor(recorder))

bundle = recorder.bundle(record_digest)   # what a supervisor checks offline
recorder.close()                          # sends what is pending
```

## Files you keep elsewhere

`digest_file(path)` returns the SHA-256 of a file read in chunks, for a record that names a file it does not
contain, such as a call recording (`mifid.call-recording`). The file stays where it is.

## Completeness chains

With a chain secret, every record goes in a numbered chain, so a record later left out is a gap an
auditor sees (https://riskrouter.eu/spec#chains). The recorder adds `chain_tag`, `chain_seq` and
`chain_prev` itself, and carries on from its journal after a restart. One process writes a given chain.

```python
recorder = Recorder(chain_secret=os.environ["RISKROUTER_CHAIN_SECRET"], chain="kyc-desk")
recorder.record({"kind": "aml.onboarding", "record_id": "onb-1182"})
bundle = recorder.completeness()   # the log's signed statement and every record of the chain
```

## Agents: LangChain, LangGraph and the OpenAI Agents SDK

Each agent run becomes one record, with its tool calls, model calls, handoffs, guardrails and graph
nodes as steps. Steps keep content digests (SHA-256 of the text), never the text, unless you pass
`include_content=True`, which keeps the text in your journal; it is still never sent. Neither framework
is a dependency. More: https://riskrouter.eu/integrate#recorders.

```python
from riskrouter_recorder.agents import EvidenceCallbackHandler, EvidenceTracingProcessor

fields = {"system_ref": "claims-agent", "system_version": "2.3"}
graph.invoke(state, config={"callbacks": [EvidenceCallbackHandler(recorder, fields=fields)]})   # LangChain / LangGraph

from agents import add_trace_processor                                                          # OpenAI Agents SDK
add_trace_processor(EvidenceTracingProcessor(recorder, fields=fields))
```

`add_trace_processor` keeps the SDK's own exporter, which sends traces to OpenAI; use
`set_trace_processors([...])` if nothing should go there.

The same guarantees as the Node recorder: nothing is lost (journal first, then send), nothing is
claimed (`recorded` only from the log's answer), no lock-in (any compatible log, or none), and the
journal is yours to keep and, where the law requires, to erase from.

Source: https://github.com/aniljangrabe-dev/riskrouter-recorder. Licence: Apache-2.0 (`LICENSE`), like the verifiers,
the conformance suite and the integration kit (https://github.com/aniljangrabe-dev/riskrouter-verify); the service itself is not licensed.
