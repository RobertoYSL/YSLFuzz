# Limitations

YSLFuzz is an evolving research-oriented API fuzzing tool. Current limitations include:

- OpenAPI support covers the subset needed by current discovery, payload generation, and execution.
- GraphQL support focuses on local SDL and local introspection JSON inputs, not live remote introspection.
- GraphQL execution uses JSON POST requests only.
- GraphQL batching, subscriptions, WebSockets, and multipart upload are not supported.
- Attack-classified SQL, NoSQL, command, and SSRF coverage uses inert markers only.
- Analysis is conservative and signal-based. It is not proof of a confirmed vulnerability.
- OAuth browser flows, token refresh, and browser automation are not implemented.
- Query-string credentials are intentionally not documented as a supported auth mode.
- Persistent resume, distributed scanning, and multi-process execution are not implemented.
- HTML report finalization and advanced Markdown report finalization are not documented as complete.
- CI/CD, packaging automation, and release automation are not documented as complete.
- Third-party baseline comparison and thesis experiment orchestration are outside the core product.
- YSLFuzz does not replace manual security review.
