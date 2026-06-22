# YSLFuzz — Architecture Decision Record (ADR)

**Project:** YSLFuzz  
**Subtitle:** Schema-Aware Stateful Fuzzer for REST and GraphQL APIs  
**Version:** 1.0  
**Author:** Christian Ruzza  
**Status:** Draft operativo pre-sviluppo  

---

## 1. Purpose

Questo documento raccoglie le decisioni architetturali principali per il progetto **YSLFuzz**.  
Lo scopo è fissare le scelte tecniche, motivarle, indicare le alternative scartate e rendere il progetto più difendibile sia dal punto di vista ingegneristico sia dal punto di vista sperimentale.

YSLFuzz non deve essere progettato come un generico vulnerability scanner, ma come un framework di fuzzing **schema-aware**, **stateful** e **dependency-aware** per API REST e GraphQL.

---

## ADR-001 — Nome del progetto

### Decisione

Il progetto si chiamerà **YSLFuzz**.

### Motivazione

Il nome è breve, riconoscibile e adatto sia a un repository Git sia a un tool CLI.

### Conseguenze

Il nome verrà usato in:

- repository;
- package Python;
- CLI;
- documentazione;
- report;
- tesi;
- eventuale paper o poster.

---

## ADR-002 — Linguaggio di sviluppo

### Decisione

YSLFuzz verrà sviluppato in **Python 3.12+**.

### Motivazione

Python permette un'elevata produttività e dispone di librerie mature per:

- parsing OpenAPI;
- GraphQL;
- richieste HTTP asincrone;
- validazione dati;
- test automation;
- reportistica;
- security tooling.

### Alternative valutate

#### Go

Vantaggi:

- performance elevate;
- binario statico;
- ottima concorrenza.

Svantaggi:

- minore rapidità di prototipazione;
- ecosistema meno flessibile per parsing, modelli dati e test sperimentali.

#### Rust

Vantaggi:

- sicurezza della memoria;
- ottime performance.

Svantaggi:

- curva di apprendimento più alta;
- tempo di sviluppo non ideale per una tesi con deadline di circa tre mesi.

### Conseguenze

Python sacrifica performance massime ma massimizza produttività, testabilità e rapidità di iterazione.

---

## ADR-003 — Tipologie di API supportate

### Decisione

La prima versione di YSLFuzz supporterà:

- REST tramite OpenAPI/Swagger;
- GraphQL tramite schema/introspection.

### Esclusioni MVP

- SOAP;
- gRPC;
- WebSocket;
- GraphQL subscriptions;
- crawling generico di applicazioni web.

### Motivazione

REST e GraphQL sono le due superfici API più coerenti con l'obiettivo scientifico del progetto: usare informazioni strutturali dello schema per migliorare la qualità del fuzzing.

### Conseguenze

Il progetto resta focalizzato e misurabile.

---

## ADR-004 — Discovery strategy

### Decisione

YSLFuzz userà una discovery basata su schema:

- OpenAPI file;
- OpenAPI URL;
- Swagger file;
- Swagger URL;
- GraphQL introspection;
- GraphQL schema file.

### Motivazione

La tesi intende dimostrare il vantaggio di un approccio schema-aware rispetto ad approcci black-box o path discovery puramente sintattici.

### Alternative scartate

- spidering HTML;
- crawling passivo;
- bruteforce path discovery.

### Conseguenze

Il tool funzionerà meglio quando la specifica API è disponibile. Questo è coerente con il posizionamento scientifico del progetto.

---

## ADR-005 — Modello interno normalizzato

### Decisione

REST e GraphQL verranno convertiti in un modello interno comune basato su:

- `ApiSchema`;
- `Endpoint`;
- `Parameter`;
- `FieldDefinition`;
- `TypeDefinition`;
- `Constraint`;
- `Workflow`;
- `PayloadCandidate`;
- `RequestRecord`;
- `ResponseRecord`;
- `SecurityFinding`.

### Motivazione

Un modello comune permette di implementare payload generation, execution e analysis una sola volta, riducendo duplicazioni e differenze artificiali tra REST e GraphQL.

### Conseguenze

Serve una fase di normalizzazione iniziale più complessa, ma il resto del framework diventa più pulito.

---

## ADR-006 — Schema-aware fuzzing

### Decisione

Il core del progetto sarà basato su **schema-aware fuzzing**.

### Motivazione

Gli strumenti tradizionali spesso generano input casuali o poco coerenti con la struttura dell'API. Questo porta a:

- molte richieste scartate dalla validazione;
- bassa coverage;
- rumore elevato;
- minore probabilità di raggiungere la logica applicativa reale.

YSLFuzz genererà payload coerenti con:

- tipi;
- required fields;
- enum;
- formati;
- constraint;
- esempi;
- valori osservati.

### Conseguenze

Il payload generator diventa uno dei moduli centrali del progetto.

---

## ADR-007 — Stateful fuzzing

### Decisione

YSLFuzz supporterà l'esecuzione stateful di workflow multi-step.

### Motivazione

Molte vulnerabilità API non emergono testando singoli endpoint isolati. Spesso servono sequenze del tipo:

```text
login → create resource → read resource → update resource → delete resource
```

### Conseguenze

Il framework deve modellare:

- sessioni;
- token;
- cookie;
- valori prodotti da endpoint precedenti;
- binding tra output e input successivi.

---

## ADR-008 — Dependency graph

### Decisione

YSLFuzz userà un **Endpoint Dependency Graph**.

### Motivazione

Il grafo consente di rappresentare dipendenze tra endpoint, ad esempio:

```text
POST /users  produces  user_id
GET /users/{id} consumes user_id
```

### Conseguenze

Il grafo sarà usato da:

- workflow builder;
- payload generator;
- execution planner;
- evaluation metrics.

---

## ADR-009 — Vulnerability scope MVP

### Decisione

La prima versione supporterà vulnerabilità rilevabili automaticamente e misurabili:

- SQL Injection euristica;
- NoSQL Injection euristica;
- SSRF probe controllato;
- Mass Assignment;
- Broken Access Control basilare;
- GraphQL depth abuse;
- GraphQL introspection exposure;
- Information Disclosure;
- Input Validation weakness.

### Esclusioni MVP

- business logic generica;
- race condition;
- exploitation manuale;
- chain complesse non inferibili;
- RCE reale;
- test distruttivi aggressivi.

### Conseguenze

Il progetto resta difendibile sperimentalmente e più sicuro da eseguire.

---

## ADR-010 — No LLM nel core MVP

### Decisione

Il core MVP di YSLFuzz non dipenderà da LLM esterni.

### Motivazione

Una dipendenza obbligatoria da LLM introdurrebbe:

- costi;
- latenza;
- non determinismo;
- minore riproducibilità sperimentale;
- problemi nella valutazione comparativa.

### Estensione futura

Un modulo opzionale potrà supportare:

- LLM-assisted payload generation;
- LLM-assisted response triage;
- LLM-assisted workflow inference.

### Conseguenze

Il progetto rimane deterministico e riproducibile.

---

## ADR-011 — Librerie principali

### Decisione

Stack iniziale consigliato:

- `pydantic` per modelli dati;
- `httpx` per HTTP client async;
- `typer` per CLI;
- `rich` per output CLI;
- `pytest` per test;
- `pytest-asyncio` per test async;
- `ruff` per linting;
- `mypy` per type checking;
- `coverage.py` per coverage test;
- `pyyaml` per OpenAPI YAML;
- `graphql-core` per GraphQL.

### Conseguenze

Lo stack è moderno, testabile e adatto a sviluppo assistito da agenti AI.

---

## ADR-012 — Concorrenza

### Decisione

YSLFuzz userà `asyncio` e client HTTP asincrono.

### Motivazione

Il fuzzing HTTP è prevalentemente I/O-bound.

### Conseguenze

Il progetto dovrà gestire:

- timeout;
- rate limiting;
- retry;
- cancellation;
- backpressure;
- limiti di concorrenza.

---

## ADR-013 — Sicurezza operativa

### Decisione

YSLFuzz dovrà includere vincoli di sicurezza operativa:

- scope restriction;
- allowed hosts;
- blocked paths;
- rate limiting;
- disabilitazione default dei metodi distruttivi;
- redazione automatica dei segreti;
- audit log.

### Motivazione

Un fuzzer API può causare danni se configurato male.

### Conseguenze

La sicurezza del tool stesso è parte integrante del progetto.

---

## ADR-014 — Report format

### Decisione

Il formato primario di output sarà JSON.  
In seguito saranno supportati Markdown e HTML.

### Motivazione

JSON è facile da validare, confrontare e usare nei benchmark.

### Conseguenze

Il report JSON diventa il formato canonico per evaluation e regressioni.

---

## ADR-015 — Benchmark e riproducibilità

### Decisione

YSLFuzz sarà valutato usando applicazioni vulnerabili controllate e strumenti baseline.

### Target suggeriti

- OWASP crAPI;
- OWASP Juice Shop, limitatamente alle API;
- Damn Vulnerable REST API;
- applicazione GraphQL vulnerabile locale;
- API sintetica sviluppata ad hoc per test specifici.

### Baseline suggerite

- Schemathesis;
- OWASP ZAP;
- Burp Suite, se disponibile;
- strumenti GraphQL specializzati, se compatibili.

### Metriche

- endpoint coverage;
- payload validity rate;
- vulnerabilities detected;
- false positive rate;
- execution time;
- request efficiency.

---

## 2. Sintesi architetturale finale

Pipeline logica:

```text
Schema Source
    ↓
Discovery Engine
    ↓
Schema Normalization
    ↓
Dependency Graph
    ↓
Workflow Builder
    ↓
Payload Generator
    ↓
Execution Engine
    ↓
Response Analyzer
    ↓
Finding Repository
    ↓
Report Builder
```

---

## 3. Decisione di scope finale per tre mesi

Per una timeline di circa tre mesi, lo scope finale consigliato è:

### Must have

- OpenAPI import;
- modello interno API;
- payload validi schema-aware;
- mutazioni base;
- execution engine async;
- request/response recording;
- detector basilari;
- JSON report;
- test unitari;
- benchmark minimo.

### Should have

- GraphQL import;
- dependency graph;
- workflow semplice;
- Markdown report;
- metriche di coverage.

### Could have

- HTML report;
- plugin system;
- detector avanzati;
- GraphQL depth abuse;
- multi-profile auth.

### Won't have nel MVP

- LLM nel core;
- distributed fuzzing;
- crawling black-box;
- OAuth2 completo;
- race condition testing;
- business logic detection generica.
