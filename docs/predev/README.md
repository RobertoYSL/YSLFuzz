# YSLFuzz Complete Documentation Package

Questo pacchetto contiene la documentazione pre-sviluppo completa per **YSLFuzz**, un framework schema-aware e stateful per il fuzzing di API REST e GraphQL.

## Contenuto

0. `00_adr_architecture_decision_record.md`  
   Decisioni architetturali principali: linguaggio, scope, schema-aware fuzzing, stateful execution, benchmark, sicurezza operativa.

1. `01_sdd_software_design_document.md`  
   Documento di progettazione software: architettura, componenti, moduli, UML PlantUML, repository structure e MVP path.

2. `02_dms_data_model_specification.md`  
   Specifica del modello dati: entità, enum, relazioni, regole di validazione, lifecycle dati e mapping Python/Pydantic.

3. `03_attack_coverage_matrix.md`  
   Matrice vulnerabilità → payload family → comportamento atteso → detector → evidenza → severità.

4. `04_threat_model_stride.md`  
   Threat model STRIDE del tool: asset, trust boundary, abuse case, mitigazioni e vincoli di sicurezza.

5. `05_evaluation_plan.md`  
   Piano sperimentale: metriche, benchmark target, baseline, ipotesi e metodologia di confronto.

6. `06_test_strategy_and_quality_plan.md`  
   Strategia di test e qualità: unit, integration, regression, security, performance e acceptance testing.

7. `07_product_backlog_milestones.md`  
   Backlog operativo con milestone compatibili con una timeline di circa tre mesi.

8. `08_development_kickoff_spec.md`  
   Specifica per avvio sviluppo: struttura repo, standard, toolchain, VS Code, agent prompts e primo vertical slice.

9. `09_definition_of_done_and_readiness_checklist.md`  
   Checklist di readiness e definition of done per moduli e milestone.

## Posizionamento consigliato nel repository

Copiare i file in:

```text
yslfuzz/
├── docs/
│   ├── predev/
│   │   ├── 00_adr_architecture_decision_record.md
│   │   ├── 01_sdd_software_design_document.md
│   │   ├── 02_dms_data_model_specification.md
│   │   ├── 03_attack_coverage_matrix.md
│   │   ├── 04_threat_model_stride.md
│   │   ├── 05_evaluation_plan.md
│   │   ├── 06_test_strategy_and_quality_plan.md
│   │   ├── 07_product_backlog_milestones.md
│   │   ├── 08_development_kickoff_spec.md
│   │   └── 09_definition_of_done_and_readiness_checklist.md
│   └── uml/
├── yslfuzz/
├── tests/
├── benchmarks/
└── pyproject.toml
```

## Ordine consigliato di lettura

1. ADR
2. SDD
3. DMS
4. Attack Coverage Matrix
5. Threat Model
6. Evaluation Plan
7. Test Strategy
8. Backlog
9. Kickoff Spec
10. Definition of Done

## Primo vertical slice di sviluppo

```text
OpenAPI schema
→ ApiSchema interno
→ Payload valido
→ HTTP request
→ ResponseRecord
→ JSON report
```

Questo vertical slice permette di validare subito l'architettura senza perdersi nei moduli avanzati.
