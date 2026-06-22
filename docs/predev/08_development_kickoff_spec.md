# YSLFuzz — Development Kickoff Specification

Versione: 1.0  
Progetto: YSLFuzz

---

## 1. Scopo

Questo documento definisce come iniziare concretamente lo sviluppo di YSLFuzz. Include:

- struttura repository;
- stack tecnologico;
- standard di codice;
- configurazione VS Code;
- uso consigliato di agenti AI;
- prime attività implementative;
- convenzioni di commit e branch.

---

## 2. Stack tecnologico

### Linguaggio

```text
Python 3.12+
```

### Librerie core consigliate

| Area | Libreria |
|---|---|
| HTTP async | httpx |
| Data model | pydantic |
| CLI | typer |
| YAML | pyyaml / ruamel.yaml |
| JSON path | jsonpath-ng |
| Testing | pytest |
| Async testing | pytest-asyncio |
| Lint | ruff |
| Type checking | mypy |
| Formatting | ruff format |
| GraphQL | graphql-core |
| OpenAPI parsing | parser custom iniziale + librerie leggere se utili |

---

## 3. Repository structure

Struttura consigliata:

```text
yslfuzz/
├── README.md
├── pyproject.toml
├── .gitignore
├── .env.example
├── docs/
│   ├── predev/
│   ├── uml/
│   └── thesis_notes/
├── yslfuzz/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── enums.py
│   │   ├── project.py
│   │   ├── schema.py
│   │   ├── auth.py
│   │   ├── dependency.py
│   │   ├── payload.py
│   │   ├── execution.py
│   │   ├── analysis.py
│   │   └── reporting.py
│   ├── discovery/
│   │   ├── __init__.py
│   │   ├── openapi_loader.py
│   │   ├── openapi_parser.py
│   │   └── graphql_parser.py
│   ├── schema/
│   │   ├── __init__.py
│   │   └── schema_builder.py
│   ├── dependency/
│   │   ├── __init__.py
│   │   ├── graph_builder.py
│   │   └── workflow_builder.py
│   ├── payloads/
│   │   ├── __init__.py
│   │   ├── valid_generator.py
│   │   ├── boundary_generator.py
│   │   ├── mutation_engine.py
│   │   └── graphql_generator.py
│   ├── execution/
│   │   ├── __init__.py
│   │   ├── request_builder.py
│   │   ├── executor.py
│   │   ├── workflow_executor.py
│   │   ├── scope.py
│   │   └── rate_limit.py
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   └── detectors/
│   │       ├── __init__.py
│   │       ├── differential.py
│   │       ├── error_leakage.py
│   │       ├── sensitive_data.py
│   │       ├── mass_assignment.py
│   │       ├── authz.py
│   │       └── graphql.py
│   └── reporting/
│       ├── __init__.py
│       ├── json_reporter.py
│       ├── markdown_reporter.py
│       └── metrics.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── fixtures/
├── benchmarks/
│   ├── labs/
│   └── runner.py
└── scripts/
```

---

## 4. pyproject.toml minimo

```toml
[project]
name = "yslfuzz"
version = "0.1.0"
description = "Schema-aware stateful fuzzer for REST and GraphQL APIs"
requires-python = ">=3.12"
dependencies = [
    "httpx",
    "pydantic",
    "typer",
    "pyyaml",
    "jsonpath-ng",
    "graphql-core",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "pytest-asyncio",
    "ruff",
    "mypy",
]

[project.scripts]
yslfuzz = "yslfuzz.cli:app"

[tool.ruff]
line-length = 100

[tool.mypy]
python_version = "3.12"
strict = true
```

---

## 5. VS Code setup

Estensioni consigliate:

- Python;
- Pylance;
- Ruff;
- YAML;
- Docker;
- Markdown All in One;
- PlantUML;
- Continue o Cline per agente AI;
- GitHub Pull Requests.

Impostazioni consigliate `.vscode/settings.json`:

```json
{
  "python.analysis.typeCheckingMode": "strict",
  "editor.formatOnSave": true,
  "ruff.enable": true,
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "files.exclude": {
    "**/__pycache__": true,
    "**/.pytest_cache": true,
    "**/.mypy_cache": true
  }
}
```

---

## 6. AI agent usage policy

L'agente AI deve essere usato come sviluppatore assistente, non come sostituto del design.

Regole:

- una issue alla volta;
- fornire sempre file di contesto;
- chiedere test insieme al codice;
- non accettare refactor enormi non richiesti;
- non far generare payload offensivi completi fuori dai template astratti;
- verificare ogni modifica con test;
- tenere commit piccoli.

---

## 7. Prompt base per agente AI

Prompt consigliato per Cline/Continue/DeepSeek:

```text
You are helping implement YSLFuzz, a Python 3.12 schema-aware stateful fuzzer for REST and GraphQL APIs.

Follow the existing documentation in docs/predev.
Implement only the current issue.
Use Pydantic for data models.
Use type hints everywhere.
Add unit tests for every public function.
Do not introduce unsafe default behavior.
Do not store secrets in logs or reports.
Do not generate destructive payloads.
Keep the implementation minimal and testable.
Before editing, summarize the files you will touch.
After editing, explain how to run the tests.
```

---

## 8. First implementation order

Ordine esatto consigliato:

1. creare repository;
2. creare `pyproject.toml`;
3. creare package `yslfuzz`;
4. implementare enum;
5. implementare modelli Pydantic base;
6. implementare fixture OpenAPI minimale;
7. implementare OpenAPI loader;
8. implementare OpenAPI parser;
9. implementare valid payload generator;
10. implementare request builder;
11. implementare executor;
12. implementare JSON report;
13. ottenere primo scan end-to-end.

---

## 9. Coding standards

### Type hints

Ogni funzione pubblica deve avere type hints completi.

### Error handling

Gli errori devono essere espliciti e tracciabili.

Preferire:

```python
raise SchemaParseError("Missing paths section")
```

Evita:

```python
raise Exception("error")
```

### Logging

I log non devono contenere segreti.

### Determinismo

I generatori devono accettare seed.

### Testabilità

Ogni modulo deve essere testabile senza target reale, usando fixture o mock.

---

## 10. Branch strategy

Semplice:

```text
main
feature/core-models
feature/openapi-parser
feature/payload-generator
feature/executor
feature/reporting
feature/dependency-graph
feature/graphql
feature/benchmark
```

---

## 11. Commit convention

Formato:

```text
type(scope): description
```

Esempi:

```text
feat(models): add endpoint and schema models
test(payloads): add deterministic valid payload tests
fix(execution): redact authorization header in request records
docs(predev): add attack coverage matrix
```

---

## 12. Definition of first working demo

La prima demo è pronta quando puoi eseguire:

```bash
yslfuzz scan \
  --schema tests/fixtures/openapi/minimal_valid.yaml \
  --target http://localhost:8000 \
  --output reports/demo
```

e ottenere:

```text
reports/demo/report.json
reports/demo/report.md
```

con:

- endpoint importati;
- payload generati;
- richieste registrate;
- risposte registrate;
- metriche base;
- nessun segreto nel report.

---

## 13. Conclusione

Questa specifica è il punto di partenza operativo. Lo sviluppo deve procedere in modo incrementale, sempre mantenendo un percorso end-to-end funzionante. La priorità assoluta è evitare di costruire moduli isolati molto complessi senza una pipeline completa.
