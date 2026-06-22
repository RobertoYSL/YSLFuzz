# YSLFuzz — Product Backlog & Three-Month Milestones

Versione: 1.0  
Progetto: YSLFuzz

---

## 1. Scopo

Questo documento definisce il backlog operativo di YSLFuzz, pensato per una roadmap realistica di circa tre mesi, in parallelo ad altri progetti. Il backlog è organizzato in milestone, epiche e issue implementabili direttamente su GitHub o tramite agente AI in VS Code.

---

## 2. Principio di pianificazione

Dato il tempo limitato, YSLFuzz deve essere sviluppato come **MVP scientificamente valido**, non come prodotto completo.

Il criterio guida è:

```text
prima ottenere uno scan end-to-end funzionante, poi aumentare profondità e copertura.
```

Priorità:

| Priorità | Significato |
|---|---|
| P0 | Necessario per MVP e tesi |
| P1 | Utile se il tempo lo consente |
| P2 | Futuro sviluppo |

---

## 3. Milestone complessive

| Milestone | Durata stimata | Obiettivo |
|---|---:|---|
| M0 — Project Setup | 2-3 giorni | Repository, tooling, modelli base |
| M1 — Schema Import | 1 settimana | Import OpenAPI e modello interno |
| M2 — Payload Generation | 1-2 settimane | Payload validi e mutati |
| M3 — Execution Engine | 1-2 settimane | Invio richieste e recording |
| M4 — Detection & Reporting | 1-2 settimane | Detector base e report |
| M5 — Stateful Workflows | 2 settimane | Dependency graph e workflow |
| M6 — GraphQL Support | 1-2 settimane | GraphQL introspection/query generation base |
| M7 — Benchmark & Thesis Data | 2 settimane | Esperimenti, metriche, tabelle |
| M8 — Stabilization | ultima settimana | Fix, documentazione, demo |

---

## 4. MVP scope

### Incluso nel MVP

- CLI base;
- modelli Pydantic;
- import OpenAPI 3.x;
- import GraphQL schema/introspection base;
- generazione payload validi;
- generazione payload boundary/mutati;
- HTTP executor async;
- gestione header/token semplice;
- request/response recording;
- detector base;
- report JSON e Markdown;
- dependency graph basilare;
- workflow create/read per REST;
- GraphQL introspection exposure;
- GraphQL depth behavior controllato;
- benchmark su target custom.

### Escluso dal MVP

- OAuth2 completo;
- plugin system;
- distributed fuzzing;
- UI web;
- dashboard;
- integrazione LLM nel core;
- exploit automatici;
- payload distruttivi;
- crawling web generico;
- SOAP/gRPC/WebSocket.

---

## 5. Epiche

### EPIC-001 — Core Models

Obiettivo: implementare il Data Model Specification.

Issue:

#### ISSUE-001 — Create enum definitions

Priority: P0  
Path: `yslfuzz/models/enums.py`

Acceptance criteria:

- tutti gli enum principali sono implementati;
- serializzabili come stringhe;
- test unitari presenti.

---

#### ISSUE-002 — Create schema models

Priority: P0  
Path: `yslfuzz/models/schema.py`

Acceptance criteria:

- ApiSchema, Endpoint, Parameter, FieldDefinition, Constraint implementati;
- validazione REST/GraphQL base;
- test fixture OpenAPI minimal.

---

#### ISSUE-003 — Create execution and finding models

Priority: P0  
Path: `yslfuzz/models/execution.py`, `yslfuzz/models/analysis.py`

Acceptance criteria:

- ScanRun, RequestRecord, ResponseRecord, ExecutionResult implementati;
- SecurityFinding, Evidence, DetectorResult implementati;
- serialization JSON testata.

---

### EPIC-002 — OpenAPI Discovery

#### ISSUE-004 — Load OpenAPI file or URL

Priority: P0  
Path: `yslfuzz/discovery/openapi_loader.py`

Acceptance criteria:

- carica YAML/JSON locale;
- carica URL opzionale;
- errori leggibili;
- hash del contenuto calcolato.

---

#### ISSUE-005 — Parse OpenAPI paths and operations

Priority: P0  
Path: `yslfuzz/discovery/openapi_parser.py`

Acceptance criteria:

- estrae path;
- estrae metodi;
- estrae parametri path/query/header;
- estrae requestBody JSON;
- estrae response definitions.

---

#### ISSUE-006 — Convert OpenAPI schema to internal ApiSchema

Priority: P0  
Path: `yslfuzz/schema/schema_builder.py`

Acceptance criteria:

- crea ApiSchema normalizzato;
- mappa tipi e constraints;
- supporta nested object e arrays;
- almeno tre fixture passano.

---

### EPIC-003 — Payload Engine

#### ISSUE-007 — Valid payload generation

Priority: P0  
Path: `yslfuzz/payloads/valid_generator.py`

Acceptance criteria:

- genera valori per STRING, INTEGER, BOOLEAN, EMAIL, UUID, URI, ENUM;
- rispetta required fields;
- rispetta min/max length;
- deterministic con seed.

---

#### ISSUE-008 — Boundary payload generation

Priority: P0  
Path: `yslfuzz/payloads/boundary_generator.py`

Acceptance criteria:

- genera valori al limite;
- genera valori appena fuori limite;
- collega ogni valore al Constraint sorgente.

---

#### ISSUE-009 — Attack mutation families P0

Priority: P0  
Path: `yslfuzz/payloads/mutation_engine.py`

Acceptance criteria:

- implementa mutazioni astratte per SQLi, NoSQLi, SSRF, Mass Assignment, Info Disclosure;
- non include payload distruttivi;
- ogni payload attack ha attack_category.

---

### EPIC-004 — Execution Engine

#### ISSUE-010 — HTTP request builder

Priority: P0  
Path: `yslfuzz/execution/request_builder.py`

Acceptance criteria:

- costruisce URL con path params;
- aggiunge query params;
- aggiunge headers e JSON body;
- supporta content-type JSON.

---

#### ISSUE-011 — Async HTTP executor

Priority: P0  
Path: `yslfuzz/execution/executor.py`

Acceptance criteria:

- usa client async;
- timeout configurabile;
- registra RequestRecord;
- registra ResponseRecord;
- gestisce errori senza crash.

---

#### ISSUE-012 — Scope enforcement and rate limit

Priority: P0  
Path: `yslfuzz/execution/scope.py`, `yslfuzz/execution/rate_limit.py`

Acceptance criteria:

- blocca host fuori scope;
- blocca path vietati;
- blocca metodi distruttivi se disabilitati;
- rispetta rate limit.

---

### EPIC-005 — Analysis Engine

#### ISSUE-013 — Differential response detector

Priority: P0  
Path: `yslfuzz/analysis/detectors/differential.py`

Acceptance criteria:

- confronta baseline e mutated response;
- misura status code delta;
- misura body hash delta;
- produce DetectorResult.

---

#### ISSUE-014 — Error and sensitive data detector

Priority: P0  
Path: `yslfuzz/analysis/detectors/error_leakage.py`, `sensitive_data.py`

Acceptance criteria:

- rileva stack trace-like evidence;
- rileva token-like e secret-like pattern;
- redige evidence preview.

---

#### ISSUE-015 — Mass Assignment detector

Priority: P0  
Path: `yslfuzz/analysis/detectors/mass_assignment.py`

Acceptance criteria:

- confronta campi extra inviati e risposta;
- supporta verifica read-after-write se workflow disponibile;
- produce finding con confidence.

---

### EPIC-006 — Reporting

#### ISSUE-016 — JSON report exporter

Priority: P0  
Path: `yslfuzz/reporting/json_reporter.py`

Acceptance criteria:

- esporta scan metadata;
- esporta metrics;
- esporta findings;
- output JSON valido.

---

#### ISSUE-017 — Markdown report exporter

Priority: P0  
Path: `yslfuzz/reporting/markdown_reporter.py`

Acceptance criteria:

- report leggibile;
- tabella findings;
- summary severity;
- redaction attiva.

---

#### ISSUE-018 — Metrics calculator

Priority: P0  
Path: `yslfuzz/reporting/metrics.py`

Acceptance criteria:

- calcola endpoint coverage;
- calcola payload validity;
- calcola total requests;
- calcola findings by severity.

---

### EPIC-007 — Dependency Graph & Stateful Workflows

#### ISSUE-019 — Dependency graph builder

Priority: P0/P1  
Path: `yslfuzz/dependency/graph_builder.py`

Acceptance criteria:

- identifica producer e consumer di ID;
- crea DependencyNode e DependencyEdge;
- assegna confidence.

---

#### ISSUE-020 — Workflow builder

Priority: P1  
Path: `yslfuzz/dependency/workflow_builder.py`

Acceptance criteria:

- genera workflow create → read;
- supporta output extractor JSON;
- supporta variable binding path param.

---

#### ISSUE-021 — Workflow executor

Priority: P1  
Path: `yslfuzz/execution/workflow_executor.py`

Acceptance criteria:

- esegue step ordinati;
- salva valori estratti;
- passa valori agli step successivi;
- produce ExecutionResult per step.

---

### EPIC-008 — GraphQL Support

#### ISSUE-022 — GraphQL schema import

Priority: P1  
Path: `yslfuzz/discovery/graphql_parser.py`

Acceptance criteria:

- importa schema file;
- importa introspection JSON;
- estrae queries e mutations;
- mappa tipi base.

---

#### ISSUE-023 — GraphQL valid query generation

Priority: P1  
Path: `yslfuzz/payloads/graphql_generator.py`

Acceptance criteria:

- genera query base per operation;
- genera variables valide;
- limita profondità.

---

#### ISSUE-024 — GraphQL detectors

Priority: P1  
Path: `yslfuzz/analysis/detectors/graphql.py`

Acceptance criteria:

- rileva introspection exposure;
- rileva depth behavior anomalo;
- genera finding.

---

### EPIC-009 — CLI & Developer Experience

#### ISSUE-025 — CLI scan command

Priority: P0  
Path: `yslfuzz/cli.py`

Acceptance criteria:

- comando `yslfuzz scan --schema openapi.yaml --target http://localhost:8000`;
- supporta output directory;
- supporta config YAML.

---

#### ISSUE-026 — Config loader

Priority: P0  
Path: `yslfuzz/config.py`

Acceptance criteria:

- carica YAML;
- valida ScanConfiguration;
- applica default sicuri.

---

### EPIC-010 — Benchmark

#### ISSUE-027 — REST vulnerable lab

Priority: P0  
Path: `benchmarks/labs/rest_lab/`

Acceptance criteria:

- Docker compose avviabile;
- OpenAPI schema incluso;
- ground_truth.yaml incluso;
- almeno tre vulnerabilità controllate.

---

#### ISSUE-028 — Benchmark runner

Priority: P1  
Path: `benchmarks/runner.py`

Acceptance criteria:

- esegue YSLFuzz su target lab;
- salva report;
- calcola TP/FP/FN rispetto a ground truth.

---

## 6. Timeline consigliata

### Settimana 1

- ISSUE-001, 002, 003;
- setup repository;
- test infrastructure;
- CLI skeleton.

### Settimana 2

- ISSUE-004, 005, 006;
- OpenAPI import end-to-end.

### Settimana 3

- ISSUE-007, 008;
- valid/boundary payload generation.

### Settimana 4

- ISSUE-010, 011, 012;
- primo scan HTTP senza detector avanzati.

### Settimana 5

- ISSUE-013, 014, 016, 018;
- primo report JSON con finding base.

### Settimana 6

- ISSUE-009, 015, 017;
- attack mutation P0 e report Markdown.

### Settimana 7

- ISSUE-019, 020;
- dependency graph e workflow builder.

### Settimana 8

- ISSUE-021;
- stateful execution MVP.

### Settimana 9

- ISSUE-022, 023, 024;
- GraphQL support base.

### Settimana 10

- ISSUE-027;
- target lab custom.

### Settimana 11

- ISSUE-028;
- benchmark e raccolta dati.

### Settimana 12

- stabilizzazione;
- bug fix;
- tabelle risultati;
- demo;
- scrittura tesi.

---

## 7. MVP release criteria

YSLFuzz MVP è completato quando:

- importa OpenAPI;
- genera payload validi;
- esegue richieste;
- registra request/response;
- produce almeno un finding;
- genera report JSON/Markdown;
- rispetta scope e redaction;
- esegue almeno un workflow stateful;
- produce metriche sperimentali;
- funziona su almeno un target lab.

---

## 8. Conclusione

Il backlog è pensato per essere eseguibile con supporto di un agente AI in VS Code. Ogni issue deve essere implementata con test, documentazione minima e commit separato. In caso di ritardo, la priorità assoluta rimane ottenere uno scan REST end-to-end funzionante prima di completare GraphQL e workflow avanzati.
