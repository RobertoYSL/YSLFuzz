# Limitations

YSLFuzz is an evolving research-oriented API fuzzing tool. Current limitations include:

- OpenAPI support covers the subset needed by current discovery, payload generation, stateful workflows, and execution.
- GraphQL supports local SDL, local introspection JSON, and live remote introspection via HTTP.
- GraphQL execution uses JSON POST requests only; WebSocket subscriptions, batching, and multipart uploads are not supported.
- Attack-classified probes use safe, inert markers only. YSLFuzz does not generate operational exploit payloads.
- Analysis is signal-based and conservative. It is not proof of a confirmed vulnerability without manual verification.
- Interactive OAuth browser flows and browser automation are not supported.
- Query-string credentials are intentionally not supported as an auth mode to prevent credential leakage in URLs.
- Persistent resume, distributed scanning, and multi-process execution are not implemented.
- Executive Markdown (`--markdown`) and JSON reports are supported; interactive HTML dashboards are not implemented.
- Third-party baseline comparison and thesis experiment orchestration are handled externally.
- YSLFuzz does not replace manual security review.
