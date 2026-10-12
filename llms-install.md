# Installing the riskrouter-recorder MCP server

These steps are for an AI assistant (Cline, Claude, an IDE agent) setting up the local MCP server in this
repository, `riskrouter-recorder-mcp`. It needs Node 20 or later and nothing else: no build step, no
dependencies, no account.

## 1. Add it to the MCP settings

```json
{
  "mcpServers": {
    "riskrouter-recorder": {
      "command": "npx",
      "args": ["-y", "-p", "riskrouter-recorder", "riskrouter-recorder-mcp"],
      "env": {
        "RISKROUTER_JOURNAL": "/absolute/path/to/evidence-journal.jsonl"
      }
    }
  }
}
```

The server speaks MCP over stdio. Ask the user where the journal should live and use an absolute path; it is
the user's own file and holds every record in full.

## 2. Optional settings

| Variable | Default | What it does |
| --- | --- | --- |
| `RISKROUTER_API_KEY` | none | With a key, each record's salted digest is sent to the evidence log. Without one, nothing is sent and the journal keeps everything. Ask the user for it; never invent one. A free sandbox key is at https://riskrouter.eu/integrate#get-a-key; what it records can never be deleted. |
| `RISKROUTER_JOURNAL` | `./evidence-journal.jsonl` | Where records and their salts are kept. |
| `RISKROUTER_KINDS` | `ai.decision` | The kinds of record the agent may use, comma-separated. |
| `RISKROUTER_BASE` | `https://api.riskrouter.eu` | Another evidence log, such as a self-hosted one. |

## 3. Check it

Call `evidence_status`. It answers with the journal's counts and whether a log is configured. Then the tools are:

- `record_decision`: record a decision (`record` is an object; refer to people by reference, never by name or
  email). Returns the record's digest.
- `evidence_lookup`: where a recorded decision stands, by its digest.
- `evidence_status`: counts, and whether a log is configured.

What is recorded is the agent's own statement of what it decided, and every record is marked
`source: "mcp.agent-statement"`. The server never returns a record or a salt to the agent.
