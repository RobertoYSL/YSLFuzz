# YSLFuzz — Evaluation Plan

Versione: 1.0  
Progetto: YSLFuzz  
Obiettivo: valutazione sperimentale della tesi

---

## 1. Scopo

Questo documento definisce il piano di valutazione sperimentale di YSLFuzz. L'obiettivo è dimostrare, con metriche misurabili, se un approccio schema-aware e stateful migliora il fuzzing di API REST e GraphQL rispetto a strumenti baseline o approcci black-box.

---

## 2. Ipotesi sperimentali

### H1 — Endpoint Coverage

YSLFuzz raggiunge una copertura degli endpoint maggiore rispetto a un fuzzer black-box generico quando è disponibile uno schema OpenAPI o GraphQL.

### H2 — Payload Validity

YSLFuzz genera una percentuale maggiore di payload validi grazie all'uso dei vincoli dichiarati nello schema.

### H3 — Vulnerability Detection

YSLFuzz individua vulnerabilità API-specific, come Mass Assignment e Broken Object Level Authorization, con maggiore efficacia rispetto a scanner che non modellano dipendenze tra endpoint.

### H4 — Request Efficiency

YSLFuzz richiede meno richieste inutili per ottenere finding significativi, rispetto ad approcci casuali o puramente black-box.

---

## 3. Research questions

| ID | Domanda |
|---|---|
| RQ1 | Lo schema-aware fuzzing aumenta la copertura degli endpoint? |
| RQ2 | L'uso dei vincoli dello schema migliora la validità dei payload? |
| RQ3 | Lo stateful fuzzing migliora il rilevamento di vulnerabilità legate ad autorizzazione e stato? |
| RQ4 | YSLFuzz produce meno rumore rispetto a strumenti baseline? |
| RQ5 | Quali categorie di vulnerabilità beneficiano maggiormente dell'approccio proposto? |

---

## 4. Target di benchmark

Per una tesi in tre mesi, è preferibile usare target vulnerabili noti e riproducibili in locale.

### 4.1 Target REST

| Target | Uso | Priorità |
|---|---|---|
| OWASP crAPI | API moderne vulnerabili, workflow, BOLA, auth | P0 |
| OWASP Juice Shop API | Security testing generale, auth, injection, disclosure | P1 |
| Damn Vulnerable REST API | Test REST controllato | P1 |
| API mock custom | Ground truth controllata | P0 |

### 4.2 Target GraphQL

| Target | Uso | Priorità |
|---|---|---|
| GraphQL vulnerable lab locale | Introspection, depth, schema leakage | P0 |
| API GraphQL mock custom | Ground truth controllata | P0 |
| DVGA-like environment | Test GraphQL security | P1 |

### 4.3 Target custom consigliato

È fortemente consigliato sviluppare una piccola API vulnerabile custom con:

- OpenAPI 3.x completo;
- endpoint user/order/admin;
- login JWT;
- vulnerabilità controllate;
- ground truth nota;
- dataset piccolo;
- Docker compose.

Questo permette di calcolare metriche affidabili anche se i target pubblici cambiano o risultano difficili da automatizzare.

---

## 5. Baseline tools

La valutazione dovrebbe confrontare YSLFuzz con almeno due baseline.

| Baseline | Motivazione | Priorità |
|---|---|---|
| Schemathesis | Baseline schema-aware per OpenAPI | P0 |
| OWASP ZAP | Baseline scanner web/API ampiamente usato | P0 |
| Burp Suite Community/Professional | Baseline manuale/active scan se disponibile | P1 |
| Fuzzer black-box minimale custom | Baseline controllata | P0 |

Se il tempo è limitato, il confronto minimo è:

1. YSLFuzz;
2. Schemathesis;
3. Black-box fuzzer minimale.

---

## 6. Metriche

### 6.1 Endpoint Coverage

```text
endpoint_coverage = tested_endpoints / total_endpoints
```

Un endpoint è considerato testato se riceve almeno una richiesta valida o una richiesta mutata riconducibile allo schema.

---

### 6.2 Payload Validity Rate

```text
payload_validity_rate = valid_payloads_accepted / payloads_sent
```

Un payload è considerato valido se il server risponde con un codice coerente con l'operazione attesa, ad esempio:

- 2xx;
- 3xx previsto;
- 4xx atteso per permessi mancanti ma non per validazione sintattica.

---

### 6.3 Vulnerability Detection Rate

```text
vdr = vulnerabilities_detected / vulnerabilities_present
```

Questa metrica richiede ground truth. È quindi fondamentale avere almeno un target custom con vulnerabilità note.

---

### 6.4 False Positive Rate

```text
fpr = false_positives / reported_findings
```

Un finding è false positive se non corrisponde a una vulnerabilità reale secondo ground truth o verifica manuale.

---

### 6.5 Request Efficiency

```text
request_efficiency = confirmed_findings / total_requests
```

Misura quanti finding confermati vengono prodotti rispetto al numero di richieste inviate.

---

### 6.6 Time to First Finding

```text
time_to_first_finding = timestamp_first_finding - scan_start_time
```

Utile per valutare rapidità pratica dello strumento.

---

### 6.7 Stateful Finding Ratio

```text
stateful_finding_ratio = stateful_findings / total_findings
```

Misura quanti finding richiedono correlazione tra più richieste.

---

## 7. Disegno sperimentale

### 7.1 Esperimento A — REST schema-aware coverage

Obiettivo: misurare endpoint coverage e payload validity su API REST.

Target:

- API custom OpenAPI;
- crAPI se disponibile.

Confronto:

- YSLFuzz;
- Schemathesis;
- Black-box fuzzer minimale.

Metriche:

- endpoint coverage;
- payload validity;
- total requests;
- request efficiency.

---

### 7.2 Esperimento B — Stateful workflow detection

Obiettivo: valutare vulnerabilità che richiedono stato.

Target:

- API custom con login, create resource, read resource, update resource;
- BOLA controllata;
- Mass Assignment controllato.

Confronto:

- YSLFuzz stateful;
- YSLFuzz stateless ablated;
- baseline black-box.

Metriche:

- BOLA detection;
- Mass Assignment detection;
- request efficiency;
- false positives.

---

### 7.3 Esperimento C — GraphQL schema-aware fuzzing

Obiettivo: valutare introspection, query generation e depth behavior.

Target:

- GraphQL mock vulnerable;
- eventuale DVGA-like lab.

Confronto:

- YSLFuzz GraphQL mode;
- baseline manuale/script statico.

Metriche:

- operation coverage;
- query validity;
- depth anomaly detection;
- schema leakage detection.

---

### 7.4 Esperimento D — Ablation study

Obiettivo: dimostrare il contributo dei componenti.

Configurazioni:

| Configurazione | Schema-aware | Stateful | Dependency graph |
|---|---:|---:|---:|
| YSLFuzz full | sì | sì | sì |
| YSLFuzz no-state | sì | no | no |
| YSLFuzz no-schema | no | no | no |

Metriche:

- coverage;
- payload validity;
- findings;
- false positives;
- total requests.

Questo esperimento è molto importante per la tesi perché dimostra il valore architetturale dei moduli.

---

## 8. Ground truth

Per ogni target custom bisogna mantenere un file `ground_truth.yaml`.

Esempio:

```yaml
vulnerabilities:
  - id: GT-001
    category: MASS_ASSIGNMENT
    endpoint: POST /users
    parameter: is_admin
    severity: HIGH
  - id: GT-002
    category: BROKEN_ACCESS_CONTROL
    endpoint: GET /orders/{id}
    parameter: id
    severity: HIGH
```

Il ground truth permette di calcolare:

- true positives;
- false positives;
- false negatives;
- detection rate.

---

## 9. Risultati attesi

YSLFuzz dovrebbe ottenere:

- maggiore payload validity rispetto a fuzzer black-box;
- migliore rilevazione di Mass Assignment e BOLA rispetto a scanner non stateful;
- performance comparabile a strumenti esistenti in termini di tempo, entro limiti accettabili;
- minor numero di richieste inutili per endpoint documentati.

---

## 10. Tabelle risultato da produrre

### 10.1 Coverage table

| Tool | Target | Endpoint totali | Endpoint testati | Coverage |
|---|---:|---:|---:|---:|
| YSLFuzz | Custom REST | | | |
| Schemathesis | Custom REST | | | |
| Black-box | Custom REST | | | |

### 10.2 Detection table

| Tool | Target | TP | FP | FN | VDR | FPR |
|---|---:|---:|---:|---:|---:|---:|
| YSLFuzz | | | | | | |
| Baseline | | | | | | |

### 10.3 Efficiency table

| Tool | Requests | Findings confirmed | Requests per finding | Time to first finding |
|---|---:|---:|---:|---:|
| YSLFuzz | | | | |
| Baseline | | | | |

---

## 11. Reproducibility requirements

Ogni esperimento deve salvare:

- versione YSLFuzz;
- commit git;
- target version;
- Docker image tag;
- scan configuration;
- random seed;
- schema input hash;
- report JSON;
- metriche aggregate.

---

## 12. Acceptance criteria valutazione

La valutazione è sufficiente per la tesi se produce:

- almeno due target REST;
- almeno un target GraphQL;
- almeno un confronto con baseline;
- almeno una tabella coverage;
- almeno una tabella detection;
- almeno una tabella false positives;
- almeno un ablation study;
- almeno tre finding confermati su ground truth.

---

## 13. Conclusione

Il piano sperimentale è progettato per essere realistico in tre mesi. L'obiettivo non è battere ogni scanner esistente in assoluto, ma dimostrare in modo rigoroso che l'uso combinato di schema, stato e dependency graph produce un miglioramento misurabile nel fuzzing di API moderne.
