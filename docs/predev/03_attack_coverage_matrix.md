# YSLFuzz — Attack Coverage Matrix

Versione: 1.0  
Stato: Draft operativo per implementazione  
Progetto: YSLFuzz — Schema-Aware Stateful Fuzzer for REST and GraphQL APIs

---

## 1. Scopo del documento

Questo documento definisce la **Attack Coverage Matrix** di YSLFuzz, cioè la matrice che collega:

- categorie di vulnerabilità;
- prerequisiti di test;
- tipi di endpoint coinvolti;
- famiglie di payload;
- strategia di generazione;
- detector associati;
- evidenze attese;
- severità e confidenza;
- priorità di implementazione per MVP.

La matrice non contiene payload offensivi completi o istruzioni di exploit operative. I payload vengono descritti in forma astratta come **template di test** e **famiglie di mutazione**, in modo da guidare l'implementazione in un contesto autorizzato e controllato.

---

## 2. Principi di sicurezza

YSLFuzz deve essere usato esclusivamente su target autorizzati, ambienti locali, CTF, laboratorio, applicazioni volutamente vulnerabili o sistemi per i quali il tester possiede esplicita autorizzazione.

Per ridurre rischi operativi:

- i test distruttivi sono disabilitati di default;
- i metodi `DELETE`, `PUT`, `PATCH` devono essere controllabili da configurazione;
- ogni scan deve rispettare `ScopeDefinition`;
- ogni richiesta deve essere tracciata;
- credenziali e token devono essere redatti nei report;
- i template ad alto rischio devono essere opt-in;
- rate limiting e timeout sono obbligatori.

---

## 3. Livelli di priorità

| Priorità | Significato | Uso nel progetto |
|---|---|---|
| P0 | Obbligatorio per MVP | Deve essere implementato nella prima versione |
| P1 | Importante ma non bloccante | Implementabile dopo MVP base |
| P2 | Estensione futura | Utile per tesi avanzata o sviluppo successivo |

---

## 4. Detector confidence model

| Confidenza | Descrizione |
|---|---|
| LOW | Comportamento sospetto ma non conclusivo |
| MEDIUM | Evidenza tecnica significativa, ma non confermata da confronto differenziale |
| HIGH | Evidenza forte con confronto tra payload controllo e payload mutato |
| CONFIRMED | Evidenza riproducibile con più richieste coerenti |

---

## 5. Severity model

| Severità | Criterio generale |
|---|---|
| INFO | Informazione utile ma non vulnerabilità diretta |
| LOW | Impatto limitato o solo comportamento anomalo |
| MEDIUM | Possibile vulnerabilità sfruttabile con impatto moderato |
| HIGH | Accesso non autorizzato, leakage significativo, manipolazione dati |
| CRITICAL | Compromissione grave, accesso amministrativo, esecuzione remota, esposizione massiva |

---

## 6. Attack Coverage Matrix — MVP

### 6.1 SQL Injection

| Campo | Specifica |
|---|---|
| ID | ACM-001 |
| Categoria | SQL_INJECTION |
| Priorità | P0 |
| Target | REST endpoint con input stringa, query param, path param, JSON body; GraphQL arguments stringa |
| Prerequisiti | Endpoint raggiungibile; input controllabile; risposta osservabile |
| Payload family | Boolean-style probe, syntax-disruption probe, error-oriented probe, time-behavior probe astratto |
| Strategia schema-aware | Applicare mutazioni solo a campi `STRING`, `EMAIL`, `UUID`, `UNKNOWN` convertibili a stringa |
| Baseline richiesta | Payload valido generato dallo schema |
| Mutazione | Sostituzione/alterazione controllata del valore del campo con template SQLi astratto |
| Detector | SQLiErrorDetector, DifferentialStatusDetector, TimingAnomalyDetector |
| Evidenza attesa | Errori DB, variazione status code, variazione significativa della risposta, aumento temporale anomalo |
| Falsi positivi probabili | Errori generici 500, instabilità del server, rate limiting |
| Confidence rule | HIGH se differenza riproducibile tra controllo e mutazione; MEDIUM se solo errore DB-like |
| Severity default | HIGH |
| Note implementative | Non eseguire escalation; limitarsi a detection non distruttiva |

---

### 6.2 NoSQL Injection

| Campo | Specifica |
|---|---|
| ID | ACM-002 |
| Categoria | NOSQL_INJECTION |
| Priorità | P0 |
| Target | JSON body, GraphQL variables, parametri object-like |
| Prerequisiti | Endpoint che accetta JSON o oggetti annidati |
| Payload family | Operator-shape probe, type-confusion probe, object-injection probe |
| Strategia schema-aware | Applicare mutazioni a campi `OBJECT`, `STRING`, `BOOLEAN`, `UNKNOWN` in body JSON |
| Baseline richiesta | Payload valido con struttura conforme |
| Mutazione | Inserimento controllato di strutture oggetto inattese o operator-like astratti |
| Detector | NoSQLShapeDetector, DifferentialResponseDetector, AuthBypassSignalDetector |
| Evidenza attesa | Login bypass sospetto, cambiamento cardinalità risposta, validazione bypassata |
| Falsi positivi probabili | API che accetta filtri avanzati legittimi |
| Confidence rule | HIGH se payload controllo fallisce e payload mutato produce accesso/risposta più ampia |
| Severity default | HIGH |
| Note implementative | Conservare sempre payload controllo per confronto |

---

### 6.3 Server-Side Request Forgery

| Campo | Specifica |
|---|---|
| ID | ACM-003 |
| Categoria | SSRF |
| Priorità | P0/P1 |
| Target | Campi URL, URI, webhook, callback, avatar, image, import, fetch, redirect |
| Prerequisiti | Campo classificato come `URI` o nome semanticamente collegato a URL remoti |
| Payload family | Internal-address probe, metadata-address probe astratto, controlled-callback probe |
| Strategia schema-aware | Applicare solo a campi `URI`, `STRING` con nome semanticamente compatibile |
| Baseline richiesta | URL esterno benigno controllato o placeholder sicuro |
| Mutazione | Sostituzione con destinazioni interne o canali controllati in ambiente lab |
| Detector | SSRFResponseDetector, OutOfBandCallbackDetector, ErrorMessageDetector |
| Evidenza attesa | Errore di fetch interno, differenza temporale, callback ricevuta da server controllato |
| Falsi positivi probabili | URL validation error, proxy aziendale, blocchi firewall |
| Confidence rule | CONFIRMED solo con callback controllata; MEDIUM con errori coerenti |
| Severity default | HIGH |
| Note implementative | Out-of-band opzionale e disabilitato di default |

---

### 6.4 Mass Assignment

| Campo | Specifica |
|---|---|
| ID | ACM-004 |
| Categoria | MASS_ASSIGNMENT |
| Priorità | P0 |
| Target | Endpoint create/update con JSON body |
| Prerequisiti | Presenza di campi read-only, role, is_admin, permissions, owner_id, balance, status |
| Payload family | Extra-field injection, privilege-field probe, read-only-field probe |
| Strategia schema-aware | Usare differenza tra response schema e request schema; provare campi presenti in output ma assenti in input |
| Baseline richiesta | Create/update valido |
| Mutazione | Aggiunta di campi inattesi ad alto valore semantico |
| Detector | ReflectedFieldDetector, PrivilegeChangeDetector, DifferentialObjectDetector |
| Evidenza attesa | Campo extra riflesso o persistito; variazione stato utente/risorsa |
| Falsi positivi probabili | API che riflette input senza persistenza |
| Confidence rule | HIGH se valore riappare in GET successiva; MEDIUM se solo riflesso nella risposta immediata |
| Severity default | MEDIUM/HIGH |
| Note implementative | Richiede stateful workflow: create → mutate → read |

---

### 6.5 Broken Object Level Authorization / IDOR basilare

| Campo | Specifica |
|---|---|
| ID | ACM-005 |
| Categoria | BROKEN_ACCESS_CONTROL |
| Priorità | P0 |
| Target | Endpoint con path/query/body id: user_id, account_id, order_id, resource_id |
| Prerequisiti | Almeno due identità o almeno due risorse create nel workflow |
| Payload family | Identifier swapping, ownership mismatch, cross-user resource access |
| Strategia schema-aware | Usare dependency graph per scoprire id prodotti e consumati |
| Baseline richiesta | Utente A accede a risorsa A; Utente B accede a risorsa B |
| Mutazione | Usare token/sessione A con id risorsa B |
| Detector | UnauthorizedAccessDetector, DifferentialStatusDetector, SensitiveObjectExposureDetector |
| Evidenza attesa | 200/2xx dove atteso 403/404; presenza dati altrui nella risposta |
| Falsi positivi probabili | Risorse pubbliche, ruoli admin, dataset non isolato |
| Confidence rule | HIGH se il contenuto appartiene chiaramente a un'altra identità |
| Severity default | HIGH |
| Note implementative | Per MVP può essere limitato a due sessioni configurate manualmente |

---

### 6.6 Broken Function Level Authorization basilare

| Campo | Specifica |
|---|---|
| ID | ACM-006 |
| Categoria | BROKEN_ACCESS_CONTROL |
| Priorità | P1 |
| Target | Endpoint admin, management, role, permission, settings |
| Prerequisiti | Sessione low-privilege e endpoint protetto |
| Payload family | Low-privilege access attempt, unauthenticated access attempt |
| Strategia schema-aware | Classificare endpoint sensibili da path, tag, description, auth_required |
| Baseline richiesta | Accesso con token valido privilegiato o aspettativa da schema |
| Mutazione | Chiamata senza token o con token low-privilege |
| Detector | UnauthorizedAccessDetector, StatusExpectationDetector |
| Evidenza attesa | 2xx su endpoint sensibile senza autorizzazione adeguata |
| Falsi positivi probabili | Endpoint effettivamente pubblici |
| Confidence rule | MEDIUM se classificazione solo semantica; HIGH se schema dichiara security requirement |
| Severity default | HIGH |
| Note implementative | P1 perché richiede profili utente multipli |

---

### 6.7 GraphQL Depth Abuse

| Campo | Specifica |
|---|---|
| ID | ACM-007 |
| Categoria | GRAPHQL_DEPTH_ABUSE |
| Priorità | P0/P1 |
| Target | GraphQL query con tipi annidabili o relazioni ricorsive |
| Prerequisiti | Schema GraphQL disponibile o introspection abilitata |
| Payload family | Deep nesting query, recursive type traversal, repeated fragment shape astratto |
| Strategia schema-aware | Costruire grafo dei tipi e generare query con profondità incrementale controllata |
| Baseline richiesta | Query valida a profondità bassa |
| Mutazione | Incremento progressivo della profondità fino a max_depth configurato |
| Detector | GraphQLDepthLimitDetector, TimingAnomalyDetector, ErrorMessageDetector |
| Evidenza attesa | Nessun depth limit, tempi crescenti, errori server, risposte molto grandi |
| Falsi positivi probabili | Endpoint volutamente permissivi in lab |
| Confidence rule | HIGH se la crescita di latenza/dimensione è monotona e significativa |
| Severity default | MEDIUM/HIGH |
| Note implementative | Impostare hard cap per evitare DoS accidentale |

---

### 6.8 GraphQL Introspection Exposure

| Campo | Specifica |
|---|---|
| ID | ACM-008 |
| Categoria | GRAPHQL_INTROSPECTION_ABUSE |
| Priorità | P0 |
| Target | Endpoint GraphQL |
| Prerequisiti | Endpoint GraphQL raggiungibile |
| Payload family | Introspection availability check |
| Strategia schema-aware | Verificare se introspection è disponibile in ambienti non-dev |
| Baseline richiesta | Richiesta GraphQL valida minima |
| Mutazione | Richiesta di introspection standard astratta |
| Detector | GraphQLIntrospectionDetector, SchemaLeakageDetector |
| Evidenza attesa | Schema, types, queries, mutations esposti |
| Falsi positivi probabili | Ambienti di test dove introspection è intenzionale |
| Confidence rule | CONFIRMED se schema completo restituito |
| Severity default | LOW/MEDIUM |
| Note implementative | Non è sempre vulnerabilità; classificare come exposure |

---

### 6.9 GraphQL Batching Abuse

| Campo | Specifica |
|---|---|
| ID | ACM-009 |
| Categoria | GRAPHQL_BATCHING_ABUSE |
| Priorità | P2 |
| Target | Endpoint GraphQL che accetta batch request |
| Prerequisiti | Server supporta batch di query/mutation |
| Payload family | Repeated operation batch, mixed operation batch |
| Strategia schema-aware | Generare più operazioni valide e inviarle in batch controllato |
| Baseline richiesta | Singola operation valida |
| Mutazione | Batch incrementale entro limiti configurati |
| Detector | BatchLimitDetector, TimingAnomalyDetector, RateLimitBypassDetector |
| Evidenza attesa | Assenza di limiti, moltiplicazione operazioni con singola richiesta |
| Falsi positivi probabili | Batch legittimo e correttamente limitato |
| Confidence rule | MEDIUM/HIGH in base all'impatto osservato |
| Severity default | MEDIUM |
| Note implementative | Fuori MVP salvo tempo disponibile |

---

### 6.10 Information Disclosure

| Campo | Specifica |
|---|---|
| ID | ACM-010 |
| Categoria | INFORMATION_DISCLOSURE |
| Priorità | P0 |
| Target | Tutti gli endpoint |
| Prerequisiti | Risposta osservabile |
| Payload family | Valid request, malformed request, unauthorized request |
| Strategia schema-aware | Generare richieste valide e non valide controllate |
| Baseline richiesta | Richiesta valida e richiesta non autorizzata |
| Mutazione | Input malformato o auth mancante |
| Detector | SensitiveDataDetector, ErrorLeakageDetector, StackTraceDetector |
| Evidenza attesa | Stack trace, path interni, versioni, token, email, dati personali, schema interno |
| Falsi positivi probabili | Messaggi diagnostici intenzionali in ambiente dev |
| Confidence rule | HIGH se dati sensibili identificabili; MEDIUM per stack trace generico |
| Severity default | MEDIUM |
| Note implementative | Redigere automaticamente i dati sensibili nel report |

---

### 6.11 Input Validation Bypass

| Campo | Specifica |
|---|---|
| ID | ACM-011 |
| Categoria | INPUT_VALIDATION |
| Priorità | P1 |
| Target | Parametri con vincoli di lunghezza, formato, enum, range |
| Prerequisiti | Schema con vincoli oppure vincoli inferiti |
| Payload family | Boundary values, invalid enum, type confusion, oversized input |
| Strategia schema-aware | Usare Constraint per generare valori al limite e fuori limite |
| Baseline richiesta | Payload valido entro vincoli |
| Mutazione | Violazione controllata di un singolo vincolo per volta |
| Detector | ValidationBypassDetector, StatusExpectationDetector |
| Evidenza attesa | Accettazione di input non valido, persistenza di valore fuori vincolo |
| Falsi positivi probabili | Schema non aggiornato rispetto all'implementazione reale |
| Confidence rule | HIGH se valore fuori vincolo è persistito o produce effetto osservabile |
| Severity default | LOW/MEDIUM |
| Note implementative | Ottimo per dimostrare valore schema-aware |

---

### 6.12 Command Injection — solo detection prudente

| Campo | Specifica |
|---|---|
| ID | ACM-012 |
| Categoria | COMMAND_INJECTION |
| Priorità | P2 |
| Target | Campi filename, path, command-like, host, script, import/export |
| Prerequisiti | Endpoint semanticamente associato a operazioni sistema/file |
| Payload family | Syntax-disruption probe, harmless marker probe |
| Strategia schema-aware | Applicare solo a campi semanticamente compatibili, con payload non distruttivi |
| Baseline richiesta | Payload valido |
| Mutazione | Inserimento marker innocuo o input che produce errore controllato |
| Detector | CommandErrorDetector, DifferentialErrorDetector |
| Evidenza attesa | Messaggi shell-like, errori di comando, path leak |
| Falsi positivi probabili | Errori applicativi generici |
| Confidence rule | MEDIUM salvo evidenza molto specifica |
| Severity default | HIGH se confermato |
| Note implementative | Fuori MVP per evitare rischio e complessità |

---

### 6.13 Reflected XSS — API context only

| Campo | Specifica |
|---|---|
| ID | ACM-013 |
| Categoria | XSS |
| Priorità | P2 |
| Target | API che restituiscono contenuto consumato da frontend |
| Prerequisiti | Input riflesso in risposta testuale/HTML/JSON |
| Payload family | Harmless reflection marker, encoded marker |
| Strategia schema-aware | Usare marker non eseguibili per verificare reflection e encoding |
| Baseline richiesta | Input valido |
| Mutazione | Valore stringa con marker speciale non esecutivo |
| Detector | ReflectionDetector, EncodingDetector |
| Evidenza attesa | Marker riflesso senza encoding adeguato |
| Falsi positivi probabili | JSON API dove reflection non implica XSS |
| Confidence rule | LOW/MEDIUM salvo contesto HTML confermato |
| Severity default | LOW/MEDIUM |
| Note implementative | Non centrale per API fuzzer; estensione futura |

---

## 7. Coverage per componente YSLFuzz

| Categoria | Discovery | Schema Engine | Dependency | Payload Engine | Executor | Analyzer | Reporter |
|---|---:|---:|---:|---:|---:|---:|---:|
| SQLi | sì | sì | no | sì | sì | sì | sì |
| NoSQLi | sì | sì | no | sì | sì | sì | sì |
| SSRF | sì | sì | no | sì | sì | sì | sì |
| Mass Assignment | sì | sì | sì | sì | sì | sì | sì |
| BOLA/IDOR | sì | sì | sì | sì | sì | sì | sì |
| BFLA | sì | sì | sì | sì | sì | sì | sì |
| GraphQL Depth | sì | sì | sì | sì | sì | sì | sì |
| GraphQL Introspection | sì | sì | no | sì | sì | sì | sì |
| Info Disclosure | sì | sì | no | sì | sì | sì | sì |
| Input Validation | sì | sì | no | sì | sì | sì | sì |

---

## 8. MVP detector list

Per la prima versione sono sufficienti i seguenti detector:

1. `StatusCodeAnomalyDetector`
2. `DifferentialResponseDetector`
3. `ErrorMessageDetector`
4. `SensitiveDataExposureDetector`
5. `MassAssignmentDetector`
6. `UnauthorizedAccessDetector`
7. `GraphQLIntrospectionDetector`
8. `GraphQLDepthBehaviorDetector`
9. `TimingAnomalyDetector`
10. `ValidationBypassDetector`

---

## 9. MVP payload generator list

Per la prima versione sono sufficienti i seguenti generatori:

1. `ValidPayloadGenerator`
2. `BoundaryPayloadGenerator`
3. `StringMutationGenerator`
4. `ObjectMutationGenerator`
5. `AuthMutationGenerator`
6. `GraphQLDepthQueryGenerator`
7. `MassAssignmentPayloadGenerator`
8. `IdentifierSwapPayloadGenerator`

---

## 10. Minimal acceptance criteria

La Attack Coverage Matrix è considerata implementata in MVP se YSLFuzz è in grado di:

- importare almeno uno schema OpenAPI 3.x;
- importare almeno uno schema GraphQL via introspection o file;
- generare payload validi per almeno il 70% degli endpoint compatibili;
- generare mutazioni per almeno cinque categorie P0;
- eseguire richieste HTTP con sessione e token;
- correlare payload, richiesta, risposta e finding;
- produrre report JSON e Markdown;
- rilevare almeno una vulnerabilità nota su un target vulnerabile di laboratorio;
- confrontare i risultati con almeno uno strumento baseline.

---

## 11. Output atteso per ogni finding

Ogni finding deve includere almeno:

```text
finding_id
scan_run_id
endpoint_id
title
description
attack_category
severity
confidence
affected_parameter
payload_id
request_ids
response_ids
evidence
recommendation
```

---

## 12. Note finali

La matrice è progettata per supportare una tesi sperimentale in tre mesi. Il focus non è coprire tutte le vulnerabilità possibili, ma dimostrare che l'approccio schema-aware e stateful migliora:

- validità dei payload;
- copertura endpoint;
- qualità dei finding;
- capacità di testare workflow multi-step;
- riduzione del rumore rispetto a fuzzing puramente black-box.
