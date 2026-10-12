# riskrouter-recorder

Drop-in recorders for Python and Node, with no dependencies, that turn the decision logs you already keep into
evidence. Each record and its salt stay in your own journal; only the record's salted SHA-256 and a short kind
are sent to an evidence log, so that later anyone holding the record can check it was never changed. The log can
be RiskRouter's (`https://api.riskrouter.eu`), your own instance, or none at all: with no key, nothing is sent and
the journal keeps everything.

| | Install | Read |
| --- | --- | --- |
| Python 3.8+ | `pip install riskrouter-recorder` | [`python/README.md`](python/README.md) |
| Node 20+ | `npm install riskrouter-recorder` | [`js/README.md`](js/README.md) |

What is in them:

- a recorder with a local journal, batching, retries and completeness chains;
- a Python `logging` handler, a decorator (Python) or function wrapper (Node), and OpenTelemetry span processors;
- agent adapters for LangChain and LangGraph and for the OpenAI Agents SDK: one record per run, with content
  digests, never content;
- a local MCP server (Node, `riskrouter-recorder-mcp`) that gives any MCP client a `record_decision` tool. It
  records the agent's own statement of what it decided and marks every record so; it never returns a record or a
  salt to the agent;
- `riskrouter-logseal`, which seals a log stream segment by segment, and `riskrouter-otlp-sealer`, which seals
  spans and log records at the OpenTelemetry Collector.

```sh
npx -y -p riskrouter-recorder riskrouter-recorder-mcp     # the local MCP server, over stdio
```

RiskRouter also runs a hosted MCP endpoint for reading the log and its proofs, at `https://api.riskrouter.eu/mcp`
(`eu.riskrouter/evidence-log` in the official MCP Registry). That is the service, not this package.

## Checking what was recorded

A record's bundle is checked offline, without RiskRouter, by either of the open-source verifiers at
https://github.com/aniljangrabe-dev/riskrouter-verify. The record format, the salted digest and the log's proofs
are specified at https://riskrouter.eu/spec.

## About this repository

This repository is an exact copy of `recorders/` in RiskRouter's own repository, which is private; a workflow
copies every change here when it lands there. Issues are welcome here, and a pull request is read and, if accepted,
applied at the source and copied back. Report a security problem as https://riskrouter.eu/security says, not in
an issue.

Licence: Apache-2.0 ([`LICENSE`](LICENSE)), like the verifiers, the conformance suite and the integration kit. The
RiskRouter service itself is not licensed.
