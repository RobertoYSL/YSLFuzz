# YSLFuzz — Definition of Done & Development Readiness Checklist

Versione: 1.0  
Progetto: YSLFuzz

---

## 1. Scopo

Questo documento definisce:

- cosa deve essere completato prima di iniziare il codice;
- quando una issue può essere considerata conclusa;
- quando un modulo è pronto;
- quando il MVP è pronto per benchmark e tesi.

---

## 2. Readiness checklist prima dello sviluppo

Prima della prima riga di codice devono essere disponibili:

| Documento | Stato richiesto |
|---|---|
| ADR | Completato |
| SDD | Completato |
| Data Model Specification | Completato |
| Attack Coverage Matrix | Completato |
| Threat Model | Completato |
| Evaluation Plan | Completato |
| Test Strategy | Completato |
| Product Backlog | Completato |
| Development Kickoff Spec | Completato |

Checklist operativa:

- [ ] repository creato;
- [ ] documentazione inserita in `docs/predev/`;
- [ ] Python 3.12 installato;
- [ ] ambiente virtuale creato;
- [ ] VS Code configurato;
- [ ] agente AI configurato;
- [ ] pyproject iniziale creato;
- [ ] pytest configurato;
- [ ] ruff configurato;
- [ ] mypy configurato;
- [ ] fixture OpenAPI minimale pronta;
- [ ] target lab pianificato.

---

## 3. Global Definition of Done

Una issue è completata solo se:

- il codice implementa esattamente lo scope dell'issue;
- sono presenti test automatici;
- i test passano;
- il codice è tipizzato;
- ruff non segnala errori;
- non sono presenti segreti hardcoded;
- i default sono sicuri;
- la documentazione minima è aggiornata;
- l'implementazione non rompe la pipeline end-to-end.

---

## 4. Module Definition of Done

### 4.1 Models

Completato quando:

- tutti gli enum P0 sono implementati;
- i modelli Pydantic P0 sono implementati;
- serializzazione JSON testata;
- validazione base testata;
- i modelli sono coerenti con Data Model Specification.

---

### 4.2 Discovery Engine

Completato quando:

- importa OpenAPI YAML/JSON;
- crea ApiSchema interno;
- estrae endpoint, parametri, request body, response;
- gestisce errori;
- fixture principali passano;
- almeno uno schema reale/lab viene importato.

---

### 4.3 Schema Engine

Completato quando:

- normalizza tipi;
- estrae vincoli;
- gestisce nested object;
- gestisce arrays;
- marca campi sensibili;
- produce modello usabile dal payload engine.

---

### 4.4 Payload Engine

Completato quando:

- genera payload validi;
- genera payload boundary;
- genera payload attack astratti P0;
- usa seed;
- collega payload a endpoint;
- non produce payload distruttivi di default;
- ha test di validità.

---

### 4.5 Execution Engine

Completato quando:

- costruisce richieste HTTP corrette;
- invia richieste async;
- gestisce timeout;
- gestisce errori;
- applica scope enforcement;
- applica rate limit;
- registra RequestRecord e ResponseRecord.

---

### 4.6 Dependency Engine

Completato quando:

- crea dependency graph;
- identifica producer/consumer ID;
- genera almeno workflow create/read;
- supporta variable binding;
- produce workflow eseguibile.

---

### 4.7 Analysis Engine

Completato quando:

- esegue detector base;
- produce DetectorResult;
- produce SecurityFinding;
- ogni finding ha evidence;
- severity e confidence sono valorizzate;
- deduplica finding simili.

---

### 4.8 Reporting Engine

Completato quando:

- esporta JSON;
- esporta Markdown;
- calcola metriche;
- redige segreti;
- include findings;
- include request/response references;
- non salva body completi salvo configurazione esplicita.

---

### 4.9 GraphQL Module

Completato quando:

- importa schema GraphQL;
- estrae query/mutation;
- genera query valida a profondità limitata;
- rileva introspection exposure;
- rileva comportamento anomalo su depth controllata.

---

## 5. Security Definition of Done

Ogni release deve soddisfare:

- [ ] Authorization header redatto;
- [ ] Cookie redatti;
- [ ] token-like values redatti;
- [ ] password redatte;
- [ ] scan fuori scope bloccato;
- [ ] DELETE bloccato se destructive methods disabled;
- [ ] max concurrency rispettato;
- [ ] timeout rispettato;
- [ ] GraphQL depth limit rispettato;
- [ ] report privo di segreti nei test.

---

## 6. MVP Definition of Done

YSLFuzz MVP è completo quando:

- [ ] importa almeno uno schema OpenAPI 3.x;
- [ ] importa almeno uno schema GraphQL o introspection JSON;
- [ ] genera payload validi per REST;
- [ ] genera payload mutati P0;
- [ ] esegue richieste HTTP;
- [ ] registra request/response;
- [ ] produce report JSON;
- [ ] produce report Markdown;
- [ ] calcola endpoint coverage;
- [ ] calcola payload validity;
- [ ] genera almeno un finding confermabile;
- [ ] esegue almeno un workflow stateful semplice;
- [ ] funziona su target lab;
- [ ] ha benchmark minimo contro una baseline;
- [ ] documenta limitazioni note.

---

## 7. Thesis readiness checklist

La parte sperimentale della tesi può iniziare quando:

- [ ] target lab custom funzionante;
- [ ] ground_truth.yaml definito;
- [ ] YSLFuzz esegue scan completo;
- [ ] report JSON contiene metriche;
- [ ] baseline selezionata;
- [ ] script benchmark disponibile;
- [ ] risultati esportabili in CSV/Markdown;
- [ ] almeno una tabella comparativa generata;
- [ ] almeno un finding stateful rilevato;
- [ ] false positives valutabili manualmente.

---

## 8. Stop conditions

Durante lo sviluppo, fermarsi e correggere se:

- il tool invia richieste fuori scope;
- i report contengono segreti;
- i test end-to-end non passano per più di una milestone;
- il payload engine genera input non riproducibili;
- i finding non sono collegati a request/response;
- l'architettura richiede refactor eccessivo prima di avere MVP.

---

## 9. Risk management

| Rischio | Probabilità | Impatto | Mitigazione |
|---|---:|---:|---|
| Scope troppo ampio | Alta | Alto | Tagliare P1/P2, completare REST MVP |
| GraphQL richiede troppo tempo | Media | Medio | Limitare a introspection + depth |
| Stateful workflow complesso | Alta | Alto | Implementare solo create/read iniziale |
| Benchmark difficile | Media | Alto | Usare target custom con ground truth |
| Troppi falsi positivi | Alta | Medio | Confidence model e manual verification |
| Mancanza tempo | Alta | Alto | Priorità pipeline end-to-end |

---

## 10. Final readiness decision

Si può iniziare lo sviluppo del codice quando:

```text
ADR + SDD + Data Model + Attack Matrix + Threat Model + Evaluation Plan + Backlog
sono completati e accettati.
```

A quel punto il primo obiettivo non è implementare tutti i detector, ma ottenere entro pochi giorni:

```text
OpenAPI schema → ApiSchema → Payload valido → HTTP request → ResponseRecord → JSON report
```

Questo è il primo asse verticale del progetto e deve rimanere sempre funzionante.
