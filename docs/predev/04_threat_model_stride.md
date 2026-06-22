# YSLFuzz — Threat Model & Security Architecture

Versione: 1.0  
Metodo: STRIDE + Abuse Case Analysis  
Progetto: YSLFuzz

---

## 1. Scopo

Questo documento definisce il threat model di YSLFuzz. Anche se YSLFuzz è uno strumento di sicurezza offensiva, il framework stesso introduce rischi che devono essere controllati:

- abuso contro target non autorizzati;
- perdita di token o credenziali;
- DoS accidentale;
- esecuzione di test distruttivi;
- report contenenti dati sensibili;
- errata classificazione di vulnerabilità.

Il threat model serve a progettare il framework in modo sicuro, controllabile e difendibile in sede accademica.

---

## 2. Asset

| Asset | Descrizione | Sensibilità |
|---|---|---|
| Target API | Sistema analizzato | Alta |
| Schema API | OpenAPI/GraphQL schema | Media/Alta |
| Credenziali | Token, API key, password | Critica |
| Sessione HTTP | Cookie, header, token runtime | Critica |
| Payload generati | Input inviati al target | Media |
| Request/Response record | Traffico registrato | Alta |
| Finding | Vulnerabilità rilevate | Alta |
| Report | Output finale | Alta |
| Configurazione scan | Scope, rate limit, attack category | Media |
| Log applicativi | Eventi e debug | Media/Alta |

---

## 3. Attori

| Attore | Descrizione | Obiettivo |
|---|---|---|
| Security Researcher | Usa YSLFuzz in lab o tesi | Valutare vulnerabilità |
| Penetration Tester autorizzato | Usa YSLFuzz in assessment | Identificare finding |
| Developer | Usa YSLFuzz in CI locale | Migliorare sicurezza API |
| Malicious User | Usa impropriamente il tool | Attaccare sistemi non autorizzati |
| Target Owner | Proprietario del sistema | Ricevere report accurato |

---

## 4. Trust boundaries

### 4.1 Boundary 1 — User / YSLFuzz CLI

Input utente:

- target URL;
- schema source;
- credenziali;
- scope;
- configurazione payload;
- configurazione rate limit.

Rischi:

- scope troppo ampio;
- credenziali inserite in chiaro;
- configurazione distruttiva accidentale.

Mitigazioni:

- validazione configurazione;
- warning per metodi distruttivi;
- default sicuri;
- redazione automatica.

---

### 4.2 Boundary 2 — YSLFuzz / Target API

YSLFuzz invia richieste al target.

Rischi:

- traffico eccessivo;
- richieste fuori scope;
- mutazioni troppo aggressive;
- alterazione dati.

Mitigazioni:

- rate limiting;
- allowlist host/path;
- timeout;
- max request count;
- dry-run mode;
- disabilitazione default dei metodi distruttivi.

---

### 4.3 Boundary 3 — Runtime / Persistent Storage

YSLFuzz salva risultati.

Rischi:

- salvataggio token;
- salvataggio dati personali;
- report non redatti.

Mitigazioni:

- redaction layer;
- body preview limitato;
- body hash invece del body completo;
- secret reference invece di secret value.

---

### 4.4 Boundary 4 — YSLFuzz / External Services opzionali

Eventuali servizi esterni:

- callback server per SSRF test;
- LLM provider opzionale futuro;
- dashboard o storage remoto.

Rischi:

- leakage dati;
- non riproducibilità;
- dipendenza esterna.

Mitigazioni:

- non usare servizi esterni nel core MVP;
- feature opt-in;
- esplicitare dati inviati fuori dal processo locale.

---

## 5. STRIDE Analysis

### 5.1 Spoofing

| Threat | Scenario | Impatto | Mitigazione |
|---|---|---|---|
| Uso di credenziali errate o rubate | Utente configura token non autorizzato | Alto | Richiedere esplicita conferma autorizzazione; non salvare token |
| Target spoofing | URL simile al target reale | Medio | Mostrare target effettivo prima dello scan; scope allowlist |
| Session confusion | Token A usato al posto di token B | Medio | Separare SessionState per profilo auth |

---

### 5.2 Tampering

| Threat | Scenario | Impatto | Mitigazione |
|---|---|---|---|
| Modifica dati target | Payload mutato altera risorse reali | Alto | `allow_destructive_methods=false` default; safe mode |
| Report alterato | Finding modificato manualmente | Medio | Hash report opzionale; metadata scan_run |
| Payload non tracciabile | Impossibile riprodurre finding | Medio | Collegare payload_id, request_id, response_id |

---

### 5.3 Repudiation

| Threat | Scenario | Impatto | Mitigazione |
|---|---|---|---|
| Utente nega uno scan | Mancanza audit trail | Medio | Audit log locale con timestamp |
| Finding non riproducibile | Mancano request/response correlate | Alto | Salvare seed, config, payload metadata |
| Mancata distinzione tra errore tool e vulnerabilità | False claim | Alto | Confidence model e detector reason |

---

### 5.4 Information Disclosure

| Threat | Scenario | Impatto | Mitigazione |
|---|---|---|---|
| Token nel report | Header Authorization serializzato | Critico | Redaction automatica |
| PII nel body | API restituisce dati personali | Alto | body preview limitato e redatto |
| Schema privato esposto | Report condiviso contiene schema interno | Medio/Alto | Warning export; report sanitization |
| Errori target salvati integralmente | Stack trace con path interni | Medio | Hash body + preview redatto |

---

### 5.5 Denial of Service

| Threat | Scenario | Impatto | Mitigazione |
|---|---|---|---|
| Concorrenza eccessiva | Troppe richieste parallele | Alto | max_concurrency e rate_limit |
| GraphQL depth abuse accidentale | Query troppo profonde | Alto | max_depth hard cap |
| Payload oversize | Body troppo grandi | Medio/Alto | max_payload_size |
| Retry storm | Retry su timeout continui | Medio | retry limit e backoff |

---

### 5.6 Elevation of Privilege

| Threat | Scenario | Impatto | Mitigazione |
|---|---|---|---|
| Tool usato per bypass auth | Uso improprio su target reale | Critico | Authorized-use banner; scope; logging |
| Secrets accessibili da plugin futuri | Plugin legge credenziali | Alto | Nessun plugin system nel MVP; secret isolation |
| Esecuzione comandi locali | Template malevoli futuri | Critico | Nessuna esecuzione shell da payload engine |

---

## 6. Abuse cases

### AC-001 — Scansione non autorizzata

Un utente tenta di usare YSLFuzz contro un dominio pubblico senza autorizzazione.

Mitigazioni:

- banner di uso autorizzato;
- configurazione esplicita dello scope;
- possibilità di bloccare host pubblici salvo conferma;
- log locale della configurazione.

---

### AC-002 — DoS accidentale su ambiente di test

Uno scan GraphQL genera query troppo profonde o troppe richieste concorrenti.

Mitigazioni:

- limiti hardcoded nel MVP;
- `max_depth <= 5` default;
- `max_concurrency <= 10` default;
- timeout e stop conditions.

---

### AC-003 — Leakage di credenziali nel report

Un report Markdown include header Authorization.

Mitigazioni:

- redaction centralizzata;
- test unitari specifici;
- denylist di chiavi sensibili;
- report non salva body completo by default.

---

### AC-004 — Mutazioni distruttive

YSLFuzz usa DELETE su dati reali.

Mitigazioni:

- metodi distruttivi disabilitati di default;
- allowlist metodi;
- conferma esplicita;
- preferire ambienti lab.

---

## 7. Security requirements

| ID | Requisito | Priorità |
|---|---|---|
| SR-001 | Il tool deve rispettare ScopeDefinition per ogni richiesta | P0 |
| SR-002 | Il tool deve redigere token, cookie e segreti nei report | P0 |
| SR-003 | I metodi distruttivi devono essere disabilitati di default | P0 |
| SR-004 | Ogni richiesta deve essere tracciata con request_id | P0 |
| SR-005 | Ogni finding deve essere collegato a evidence | P0 |
| SR-006 | GraphQL depth deve avere limite massimo | P0 |
| SR-007 | Deve esistere un rate limiter | P0 |
| SR-008 | I template high-risk devono essere opt-in | P1 |
| SR-009 | I report devono supportare sanitizzazione | P0 |
| SR-010 | Le credenziali devono essere referenziate tramite SecretReference | P1 |

---

## 8. Secure defaults

Configurazione iniziale consigliata:

```yaml
allow_destructive_methods: false
max_concurrency: 10
rate_limit_per_second: 5
request_timeout_seconds: 10
store_raw_responses: false
redact_sensitive_data: true
max_graphql_depth: 3
follow_redirects: false
verify_tls: true
```

---

## 9. Security testing del tool

YSLFuzz deve avere test dedicati per:

- redaction di header Authorization;
- redaction cookie;
- blocco richieste fuori scope;
- blocco metodi distruttivi;
- rispetto rate limit;
- timeout;
- max depth GraphQL;
- deduplica finding;
- assenza di segreti nei report.

---

## 10. Conclusioni

Il threat model di YSLFuzz evidenzia che il rischio principale non è solo tecnico, ma operativo: uno strumento di fuzzing deve evitare abusi, scansioni accidentali e leakage di informazioni. Per questo motivo il progetto adotta secure defaults, scope restriction, redaction, logging e limiti di esecuzione come requisiti core e non come funzionalità accessorie.
