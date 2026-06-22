# YSLFuzz — Test Strategy & Quality Plan

Versione: 1.0  
Progetto: YSLFuzz

---

## 1. Scopo

Questo documento definisce la strategia di test e qualità per YSLFuzz. L'obiettivo è garantire che il framework sia:

- corretto;
- riproducibile;
- sicuro nei default;
- testabile modulo per modulo;
- adatto a una valutazione sperimentale.

---

## 2. Livelli di test

| Livello | Scopo | Esempio |
|---|---|---|
| Unit test | Verificare singole classi/funzioni | Parser OpenAPI, generatori payload |
| Integration test | Verificare moduli combinati | schema → payload → request |
| End-to-end test | Verificare scan completo | target lab Docker |
| Regression test | Evitare bug già risolti | finding dedup, redaction |
| Security test | Testare sicurezza del tool | scope enforcement, secret redaction |
| Performance test | Misurare throughput e limiti | concorrenza, timeout |

---

## 3. Test per componente

### 3.1 Discovery Engine

Test obbligatori:

- importa OpenAPI 3.x valido;
- rifiuta schema invalido con errore leggibile;
- normalizza path e metodi;
- estrae parametri path/query/header;
- estrae request body JSON;
- estrae response schema;
- estrae security schemes;
- importa schema GraphQL semplice;
- gestisce tipi GraphQL object, scalar, enum.

Acceptance criteria:

- almeno 90% branch principali parser coperti;
- nessun crash su schema parzialmente incompleto;
- errori sempre tracciati con messaggio utile.

---

### 3.2 Schema Engine

Test obbligatori:

- converte tipi OpenAPI in FieldType interno;
- converte tipi GraphQL in FieldType interno;
- estrae constraints;
- identifica campi sensitive;
- gestisce nested object;
- gestisce array;
- gestisce enum;
- marca read_only/write_only.

Acceptance criteria:

- modelli serializzabili in JSON;
- validazione Pydantic attiva;
- nessun field required perso nel mapping.

---

### 3.3 Dependency Engine

Test obbligatori:

- identifica `POST /users` come producer di `user_id`;
- identifica `GET /users/{id}` come consumer;
- costruisce edge PRODUCES e CONSUMES;
- genera workflow create → read;
- evita workflow distruttivi se disabilitati;
- gestisce endpoint senza dipendenze.

Acceptance criteria:

- workflow generati ordinati correttamente;
- confidence assegnata a ogni edge;
- nessun workflow fuori scope.

---

### 3.4 Payload Engine

Test obbligatori:

- genera payload validi per string, integer, boolean, enum, email, uuid, uri;
- rispetta min/max length;
- rispetta enum;
- genera boundary values;
- genera mutation astratte per categorie P0;
- collega ogni payload a endpoint_id;
- mantiene seed riproducibile;
- redige valori sensibili nei log.

Acceptance criteria:

- stesso seed produce stessi payload;
- payload attack ha sempre attack_category;
- payload validi rispettano schema interno.

---

### 3.5 Execution Engine

Test obbligatori:

- costruisce URL con path params;
- aggiunge query params;
- invia JSON body;
- aggiunge header auth;
- mantiene cookie/sessione;
- rispetta timeout;
- rispetta rate limit;
- blocca richieste fuori scope;
- blocca metodi distruttivi se disabilitati;
- salva RequestRecord e ResponseRecord.

Acceptance criteria:

- nessuna richiesta fuori scope in test;
- ogni request ha request_id;
- ogni response ha response_id o ExecutionResult failed.

---

### 3.6 Analysis Engine

Test obbligatori:

- rileva status code anomaly;
- rileva error message pattern generico;
- rileva differenza tra baseline e mutated response;
- rileva sensitive data pattern e redige output;
- rileva field reflected/persisted per Mass Assignment;
- deduplica finding simili;
- assegna severity e confidence.

Acceptance criteria:

- ogni finding ha evidence;
- ogni finding ha request_id associato;
- nessun token in evidence preview.

---

### 3.7 Reporting Engine

Test obbligatori:

- esporta JSON;
- esporta Markdown;
- include summary metrics;
- include findings;
- redige segreti;
- non salva body completo se disabilitato;
- report riproducibile con scan metadata.

Acceptance criteria:

- report JSON validabile;
- report Markdown leggibile;
- redaction test superati.

---

## 4. Test data

Struttura consigliata:

```text
tests/fixtures/
├── openapi/
│   ├── minimal_valid.yaml
│   ├── nested_objects.yaml
│   ├── auth_jwt.yaml
│   └── invalid_schema.yaml
├── graphql/
│   ├── minimal_schema.graphql
│   ├── nested_schema.graphql
│   └── introspection_response.json
├── responses/
│   ├── normal_response.json
│   ├── error_response.json
│   └── sensitive_response.json
└── configs/
    ├── safe_scan.yaml
    └── destructive_disabled.yaml
```

---

## 5. Local vulnerable lab tests

Struttura consigliata:

```text
benchmarks/labs/
├── rest_lab/
│   ├── docker-compose.yml
│   ├── openapi.yaml
│   └── ground_truth.yaml
└── graphql_lab/
    ├── docker-compose.yml
    ├── schema.graphql
    └── ground_truth.yaml
```

Vulnerabilità minime del lab REST:

- Mass Assignment;
- BOLA/IDOR;
- Information Disclosure;
- Input Validation Bypass;
- SQLi-like error simulato non distruttivo.

Vulnerabilità minime del lab GraphQL:

- Introspection exposed;
- missing depth limit;
- overbroad query access.

---

## 6. CI pipeline consigliata

Per MVP:

```text
1. lint
2. type check
3. unit tests
4. integration tests
5. redaction tests
6. report generation smoke test
```

Comandi previsti:

```bash
ruff check .
mypy yslfuzz
pytest
pytest tests/security
```

---

## 7. Quality gates

| Gate | Criterio |
|---|---|
| QG-001 | Unit test core passano |
| QG-002 | Nessun secret nei report test |
| QG-003 | Scope enforcement test passa |
| QG-004 | OpenAPI fixture importata correttamente |
| QG-005 | Payload generation riproducibile con seed |
| QG-006 | End-to-end smoke scan produce report |
| QG-007 | Almeno un finding su target lab rilevato |

---

## 8. Definition of quality per MVP

Il MVP è considerato di qualità sufficiente se:

- tutti i moduli P0 hanno test unitari;
- almeno un test end-to-end completo passa;
- il report non contiene segreti;
- le metriche vengono calcolate automaticamente;
- ogni finding è riproducibile tramite request_id/payload_id;
- il tool non invia richieste fuori scope nei test.

---

## 9. Testing priorities for three-month timeline

### Fase 1

- models;
- parser OpenAPI;
- payload valid generator;
- report JSON.

### Fase 2

- executor;
- scope enforcement;
- request/response records;
- detector base.

### Fase 3

- stateful workflow;
- mass assignment detector;
- BOLA detector;
- benchmark tests.

---

## 10. Conclusione

La strategia di test è progettata per evitare che YSLFuzz diventi un prototipo fragile. La tesi non richiede un prodotto industriale completo, ma richiede risultati credibili. Per questo motivo la qualità minima deve concentrarsi su riproducibilità, sicurezza dei default, tracciabilità dei finding e benchmark affidabili.
