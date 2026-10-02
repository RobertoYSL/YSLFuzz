# YSLFuzz Scan Report

## Target

- Target ID: `target_279fe3f8788d4d5ebad8fcbb89b0167c`
- Name: `127.0.0.1`
- Base URL: `http://127.0.0.1:5013`
- API style: `GRAPHQL`

## Scan Summary

- Scan run: `scan_8418cbcb0aea4c41a677ad0f81ccf871`
- Findings: `33`
- Requests: `279`

## Severity Summary

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 1 |
| INFO | 0 |
| LOW | 21 |
| MEDIUM | 11 |

## Endpoint Summary

| Method | Path | Tested | Requests | Findings | Highest Severity |
|---|---|---:|---:|---:|---|
| POST | /graphql (query: pastes) | True | 22 | 18 | HIGH |
| POST | /graphql (query: paste) | True | 18 | 0 |  |
| POST | /graphql (query: systemUpdate) | True | 3 | 0 |  |
| POST | /graphql (query: systemDiagnostics) | True | 18 | 0 |  |
| POST | /graphql (query: systemDebug) | True | 14 | 0 |  |
| POST | /graphql (query: systemHealth) | True | 3 | 0 |  |
| POST | /graphql (query: users) | True | 14 | 10 | MEDIUM |
| POST | /graphql (query: readAndBurn) | True | 14 | 0 |  |
| POST | /graphql (query: search) | True | 14 | 0 |  |
| POST | /graphql (query: audits) | True | 3 | 0 |  |
| POST | /graphql (query: deleteAllPastes) | True | 3 | 0 |  |
| POST | /graphql (query: me) | True | 10 | 0 |  |
| POST | /graphql (mutation: createPaste) | True | 26 | 3 | MEDIUM |
| POST | /graphql (mutation: editPaste) | True | 22 | 0 |  |
| POST | /graphql (mutation: deletePaste) | True | 14 | 0 |  |
| POST | /graphql (mutation: uploadPaste) | True | 18 | 0 |  |
| POST | /graphql (mutation: importPaste) | True | 26 | 1 | LOW |
| POST | /graphql (mutation: createUser) | True | 23 | 1 | LOW |
| POST | /graphql (mutation: login) | True | 14 | 0 |  |
| POST | /graphql (subscription: paste) | False | 0 | 0 |  |

## Findings

### Possible Boolean-based SQL Injection in GraphQL Query

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `SQL_INJECTION`
- Detector: `GraphQLBooleanSqlInjectionDetector`
- Requests: `request_fd74456b5dce4102a4cf234d92d8b1be`
- Evidence:
  - `GRAPHQL_BOOLEAN_SQL_INJECTION`: Injected boolean SQL condition expanded result list from 16 to 35 items under 'data.pastes'.
    Preview: `path='data.pastes', baseline_count=16, attack_count=35`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0261734c4df84a949656455a1c6060c2, request_0434a67c8e7d4322ba6c673d62064ec8, request_05a80d561a674ffc9dad01dafc872f0e, request_0768f6d18885454e9d0127e7faf50393, request_078d45da6a204998bdbfff32e95d76aa, request_080f548c13bf48d3bef9f04391a83731, request_099c885b19d0449eb3a782f8da9187c1, request_0cd630ec8bcf47ca8e93334cb32c58c8, request_0e5b135da58f4dbabc916dfe87626d16, request_10fb51624eb645a88bb300183b383ae0, request_1a817035f7c54f3e9af2f7b8b0faa9c7, request_20264731d507424c8168daf4f7d49aab, request_205ac667a1744187a4acbfcf2d54cf9a, request_29206d8752b442f794b1d5e895cc249b, request_29209e6adc414479949fd622de2ca2b0, request_2f0aa3099ec147eba4b3381e2041aca0, request_32eed905fad64fabb06cfbc37960aa6e, request_35c4a8a3dc70439e84169c52584c5ebd, request_36866d88eece468a89cb399de836c94c, request_3acd419e0e1443dda62827820e4dbbab, request_3ffe559ada934313957ed94a757c4985, request_458e6a138b22446089a8492d7f505355, request_4adcce7c07d24f5fad2ef1299e4214b3, request_4aff29fdc689496b84ab2cc18d7cee85, request_4fc622adf3db4db1b97529799f665e4d, request_52f292618dec47d8b4ff537899dbec9a, request_541e47e4c3ab40099f08e9a236329a0a, request_61f45d700e764933b02c611ddacafdb4, request_63a5a58a4a5c44c786c9f5571e486675, request_69bf7d2dd5274c44b4f9278472725921, request_6b2c272ce916430e888b220cd2416fd2, request_71746f91df6642b6a72aab0e0939a886, request_71df7fd989734771a0faf5ab18ac7599, request_77ae17e9f09343caaf6258c2923b0a9f, request_77ec830fe812439ca263ac8296e7c73b, request_7a6eb74255074c30a66ff501defedfa4, request_7f473af72bc14cfcafd44f9678cad473, request_807238721adb40b9a9b4815b77c59ea8, request_828df15bc6cd412c8bba903c9cd30f0d, request_8bb7797ec14e4cfcad86714a1791b60e, request_8bfd314354474134beb3d0c6ba597d9f, request_8c945b52926040a98741ccfd9d6b4f70, request_9035789a867e47ffbf656d10e6cbe018, request_917b9cc50790423f8ac8c371205485b6, request_947ddcd60d3347ccaae11ddee97dd034, request_987129fad39945df977aeb770a9601db, request_9ecb2f73d1fe4f92bee525b351870935, request_a0cae7068dd348ce9728e3b3cb352033, request_a100206f8eec4ba7ab9d4f873ad43e7e, request_a115c3e51a084661bfc2957a3b50007a, request_a506f5ff2ed94dafad2193273969a770, request_a6491645994c4377b216a752a980118b, request_a7d399a354fc44a6816e2c9b91903835, request_aaf252b224f04c8c89d87a07d01ece0a, request_ab25ed385d25490cb4b58b9ecc5daf39, request_ad0df19f2d94443da2ce3d434c723232, request_ae3ee5f887aa4237ac09d1674e0abb3e, request_af0cd3f5f3074027a082427f4a4531bf, request_af52caa88e7b4626915deacc4293ef17, request_b3b472dd8d834cb5bbece81ea3ae13a4, request_bb68273176494fa896d818bf044332a8, request_c4bb7c3f11bf4d7681114e36ea891ea4, request_c57ad596639c4f7db08c7fffbbd51fb9, request_caade25e30e24cbea1bf63d8eaff25d0, request_cb6769755664467b9a58df2a3ccb26b1, request_ccec35c2c0f64b33be68a58e42d2bcee, request_cd9aac2ecfab433f8a63aeebb90fd6f7, request_cdd838b4f7d847cc9b083e51662cadd1, request_d050d6d9d4444af291d2624e1c76180f, request_da018ae96bf1422eba80930ac52b54e9, request_df60d345d0ad42b5b63bd28a36b723e3, request_e4d5049305b04576ab925c852ecd2cbf, request_e69bbe8a30b041d7aa36ad070d89b6f6, request_e7b6b43ac0f642c69c068e35686f3721, request_e874e2dd9f9f49d399d2e3a6e9cdfa5b, request_ea3dee0d3301467580f3e344d6ec6637, request_f65f04ccf78f4011a051afd95a46db2a, request_f6e1066f200f43e69a84af5f71edb12d, request_f7f5e371bb7642008caa936865728092, request_fdd84e1245b44eb9bd98a05f4350a553`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### Possible GraphQL Command Injection Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `COMMAND_INJECTION`
- Detector: `GraphQLInjectionMarkerDetector`
- Requests: `request_03b3b7ae3d06480caa23545f63605ae6, request_707c2578c10847ada7546d34bfcaef78, request_73d7b4d98e764f819d676ec3c733c2fa, request_847c74d8b2534ace94fda3ebfca97afb, request_a522795fbe6343ba81f90fa67c86805c, request_c4d553d2c3cb4d3cadcebdb25977823e, request_fa5057868f72440ca924e74e5b5aa7a4`
- Evidence:
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
- Recommendation: Parameterize data access, validate resolver inputs, and avoid passing user-controlled GraphQL values into database or system APIs.

### Possible GraphQL Command Injection Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `COMMAND_INJECTION`
- Detector: `GraphQLInjectionMarkerDetector`
- Requests: `request_0768f6d18885454e9d0127e7faf50393, request_0cd630ec8bcf47ca8e93334cb32c58c8, request_ccec35c2c0f64b33be68a58e42d2bcee, request_d050d6d9d4444af291d2624e1c76180f`
- Evidence:
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_COMMAND_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_command_marker`
- Recommendation: Parameterize data access, validate resolver inputs, and avoid passing user-controlled GraphQL values into database or system APIs.

### Possible GraphQL Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INPUT_VALIDATION`
- Detector: `GraphQLValidationBypassDetector`
- Requests: `request_00e219d6d2054abe9fc7a7a94732681d, request_02ad8b2c462f4a2ea63ff3ea57901aba, request_04b20f19c474431ca57e9ba32238249f, request_062815736ab84799bf6356f078186328, request_09bbe23a41464c5cb5d0a78e3b46c971, request_09c2c77bd312437c907cd4529fb77c57, request_0d602dc78ff2456280e6a4b0f79346bf, request_0faaff920e7044d2bc2cd15960f6dcf2, request_2ad98673b0fd44c39fa389aa467b75c2, request_2cd4c145e86a4189907aa0a01cdc1204, request_305b64bcaaca459195b1ac3d1644cd26, request_3fac4949dae74c07b829bcfc10c3d1a8, request_457e54e541374f80a8faa805befa2ad0, request_46044f7c48bd4182ba00c75dd52de544, request_4c260b7546de43cb8eeb11841148b064, request_4fa829d5a5474d59a004fc22d606af09, request_538b4fc28d774c38aa141647f4fbc879, request_5bb4541f2ff240dda52fddd61752c64a, request_62067078257c453591290dee76b8cd42, request_6989d46efdb242e59d71211d42126cbb, request_6cb4552303c04bc2af2ec873925b943b, request_6fd9d2f3c6a9434d89276d6dddbea95e, request_7649210520f745f4bff7de0dac104942, request_7d3fb2089f7040c7b8a2e2ea0f26c310, request_889db73574744ca0828c83ccae5c436a, request_8fb95addaca442949a3a214cad2f8b84, request_951ca5678577416d88f59735b647649c, request_a0f5cbf867e64b62b83ec3616eb031f7, request_a2d75b0b06c94ee4a41fb5ebe7175f6f, request_ace66b65718e423aad42f8d72605b293, request_bf525b42983a4f4192586546942ebe79, request_c15906add9104538bda5301e30895f22, request_c2c9aac05d9f4b30a1618053c059cf6d, request_c2f186f70dcb474eb05bf0e036d4abdd, request_c9ccc4785f8c4918aa62e76d27a60e33, request_ce73839b5e8a46db96fda74292024759, request_cf198ed7724b4bcd9b35b5f56a5c2415, request_d037cf72f6ca4382900594f41c5221d3, request_d18dffd4e4f94664a0c6aef46a09e98f, request_d208d70e89d54c5aa18ec29658c2f7a5, request_d6b771ad8bb245eb949e1dae9686f8ae, request_db0e4a4e3d444449b61ffe075c010670, request_dbd7f6d2c97941719b4b077301f27dd7, request_df2964d08928433db35d835c72656435, request_e171451c0d2a4caea21a8e1fc373c938, request_e55579f41aff451684f1e82549b504c3, request_ecdf581f3e0a4f22895c9bf9eca5bc64, request_f445ab2034d840f7b66c864a3332d333, request_f6792e4435d64e4581488bcedc14f86c, request_f68763e9091c46b3940473003324c26f, request_fa8cd739e70348cb945510d3dbb79fce, request_fb6afae5026e4dc78f5d0edf55212b29`
- Evidence:
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
  - `GRAPHQL_VALIDATION_BYPASS`: Invalid or boundary GraphQL payload received data without GraphQL errors.
    Preview: `status=200`
- Recommendation: Enforce GraphQL schema validation and resolver-level business validation before processing variables.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_00e219d6d2054abe9fc7a7a94732681d, request_02ad8b2c462f4a2ea63ff3ea57901aba, request_04b20f19c474431ca57e9ba32238249f, request_062815736ab84799bf6356f078186328, request_09bbe23a41464c5cb5d0a78e3b46c971, request_09c2c77bd312437c907cd4529fb77c57, request_0d602dc78ff2456280e6a4b0f79346bf, request_0eeba7b58e0c4af8aa8881b4e59ded6f, request_0faaff920e7044d2bc2cd15960f6dcf2, request_2ad98673b0fd44c39fa389aa467b75c2, request_2cd4c145e86a4189907aa0a01cdc1204, request_2efa332f429d4bbaa5e9e1eaa971e6a9, request_305b64bcaaca459195b1ac3d1644cd26, request_34e74d13038e4dc2bc939144cc020f86, request_37b968efe894468eb1124be4385c8490, request_3fac4949dae74c07b829bcfc10c3d1a8, request_457e54e541374f80a8faa805befa2ad0, request_46044f7c48bd4182ba00c75dd52de544, request_4c260b7546de43cb8eeb11841148b064, request_4fa829d5a5474d59a004fc22d606af09, request_538b4fc28d774c38aa141647f4fbc879, request_5bb4541f2ff240dda52fddd61752c64a, request_62067078257c453591290dee76b8cd42, request_6989d46efdb242e59d71211d42126cbb, request_6cb4552303c04bc2af2ec873925b943b, request_6fd9d2f3c6a9434d89276d6dddbea95e, request_71d5a842a0994ad3b441adbda2e02592, request_7649210520f745f4bff7de0dac104942, request_7d3fb2089f7040c7b8a2e2ea0f26c310, request_852b67a167444d8ab0ffc017cc1fbf63, request_87dfbfcac0d04d9d961e41a0222094c3, request_889db73574744ca0828c83ccae5c436a, request_8fb95addaca442949a3a214cad2f8b84, request_951ca5678577416d88f59735b647649c, request_a0f5cbf867e64b62b83ec3616eb031f7, request_a2d75b0b06c94ee4a41fb5ebe7175f6f, request_ace66b65718e423aad42f8d72605b293, request_b5b2513cb0eb42cd9bb3aafa0bb14bfe, request_bf525b42983a4f4192586546942ebe79, request_c15906add9104538bda5301e30895f22, request_c2c9aac05d9f4b30a1618053c059cf6d, request_c2f186f70dcb474eb05bf0e036d4abdd, request_c9ccc4785f8c4918aa62e76d27a60e33, request_ce73839b5e8a46db96fda74292024759, request_cf198ed7724b4bcd9b35b5f56a5c2415, request_d037cf72f6ca4382900594f41c5221d3, request_d18dffd4e4f94664a0c6aef46a09e98f, request_d208d70e89d54c5aa18ec29658c2f7a5, request_d6b771ad8bb245eb949e1dae9686f8ae, request_db0e4a4e3d444449b61ffe075c010670, request_dbd7f6d2c97941719b4b077301f27dd7, request_df2964d08928433db35d835c72656435, request_e171451c0d2a4caea21a8e1fc373c938, request_e55579f41aff451684f1e82549b504c3, request_e8d10cbb72774278be95fae6b2134229, request_ecdf581f3e0a4f22895c9bf9eca5bc64, request_f445ab2034d840f7b66c864a3332d333, request_f6792e4435d64e4581488bcedc14f86c, request_f68763e9091c46b3940473003324c26f, request_fa8cd739e70348cb945510d3dbb79fce, request_fb6afae5026e4dc78f5d0edf55212b29`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible GraphQL NoSQL Injection Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `NOSQL_INJECTION`
- Detector: `GraphQLInjectionMarkerDetector`
- Requests: `request_2e7516f0d620484bbae2f41f1ee76956, request_35879d7d01044e24b0d28ae33205b3fc, request_42f6806798f84ab4a1d04c3226dc400a, request_ccc8864cab7b4d67bb405974081da496, request_d26a2da5cefd431da0d57383d9f84a68, request_d979e0cf6b87457eb3cee92429d4abfb, request_f33747f5df1046d7a2fd123b007b6d5f`
- Evidence:
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
- Recommendation: Parameterize data access, validate resolver inputs, and avoid passing user-controlled GraphQL values into database or system APIs.

### Possible GraphQL NoSQL Injection Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `NOSQL_INJECTION`
- Detector: `GraphQLInjectionMarkerDetector`
- Requests: `request_099c885b19d0449eb3a782f8da9187c1, request_9ecb2f73d1fe4f92bee525b351870935, request_a6491645994c4377b216a752a980118b, request_ab25ed385d25490cb4b58b9ecc5daf39`
- Evidence:
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_NOSQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_nosql_marker`
- Recommendation: Parameterize data access, validate resolver inputs, and avoid passing user-controlled GraphQL values into database or system APIs.

### Possible GraphQL SQL Injection Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `SQL_INJECTION`
- Detector: `GraphQLInjectionMarkerDetector`
- Requests: `request_078d45da6a204998bdbfff32e95d76aa, request_2f0aa3099ec147eba4b3381e2041aca0, request_32eed905fad64fabb06cfbc37960aa6e, request_71746f91df6642b6a72aab0e0939a886, request_71df7fd989734771a0faf5ab18ac7599, request_a0cae7068dd348ce9728e3b3cb352033, request_a100206f8eec4ba7ab9d4f873ad43e7e, request_da018ae96bf1422eba80930ac52b54e9`
- Evidence:
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
- Recommendation: Parameterize data access, validate resolver inputs, and avoid passing user-controlled GraphQL values into database or system APIs.

### Possible GraphQL SQL Injection Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `SQL_INJECTION`
- Detector: `GraphQLInjectionMarkerDetector`
- Requests: `request_02f708a5f2e64b018f7bf52c84fc6e37, request_05b85b05e2124a098ad97ffe16d84058, request_176c0601d022489795e776994e2418b0, request_7582119c3bdd43dabc8dc03ebac8af8b, request_80b3b4cf22e34ecfbd896cc7385fd777, request_8d65324f17174e42ae512ef6cf099868, request_baf86733342744f5814dee8b79fce8e9, request_bbdb06d1cee0461c95983207cdb61b09, request_bcf9707460da44ebb2f3da2567678be5, request_d274de3119e34b18992c1c8576b5458e, request_d8df7df97731481a86ff80c7b09cf4c1, request_e814bbb7732f44dc8e8f922f46db24f2, request_fb1174f4e13d417c84dfb5853ca6be59, request_fd74456b5dce4102a4cf234d92d8b1be`
- Evidence:
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_SQL_INJECTION_MARKER`: Inert GraphQL injection marker produced a conservative response signal.
    Preview: `yslfuzz_graphql_sql_marker`
- Recommendation: Parameterize data access, validate resolver inputs, and avoid passing user-controlled GraphQL values into database or system APIs.

### Possible GraphQL SSRF Handling Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (mutation: createPaste)`
- Attack category: `SSRF`
- Detector: `GraphQLSSRFMarkerDetector`
- Requests: `request_0baadd957be947238ce6e6b0bb7d37cc, request_3c3e1d191f13472cb4b8773bbbce5a0b, request_44229a70a3454287bcfbdec65b800774`
- Evidence:
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
- Recommendation: Validate URL-like GraphQL inputs server-side and block internal, link-local, and metadata destinations.

### Possible GraphQL SSRF Handling Signal

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `SSRF`
- Detector: `GraphQLSSRFMarkerDetector`
- Requests: `request_05a80d561a674ffc9dad01dafc872f0e, request_61f45d700e764933b02c611ddacafdb4, request_a506f5ff2ed94dafad2193273969a770, request_bb68273176494fa896d818bf044332a8`
- Evidence:
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_SSRF_MARKER`: Safe GraphQL SSRF marker produced URL-handling response signal.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
- Recommendation: Validate URL-like GraphQL inputs server-side and block internal, link-local, and metadata destinations.

### GraphQL Field Suggestions Information Disclosure

- Severity: `LOW`
- Confidence: `HIGH`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INFORMATION_DISCLOSURE`
- Detector: `GraphQLFieldSuggestionDetector`
- Requests: `request_0261734c4df84a949656455a1c6060c2, request_4fc622adf3db4db1b97529799f665e4d, request_6b2c272ce916430e888b220cd2416fd2, request_7f473af72bc14cfcafd44f9678cad473, request_8bfd314354474134beb3d0c6ba597d9f, request_9035789a867e47ffbf656d10e6cbe018, request_af0cd3f5f3074027a082427f4a4531bf, request_caade25e30e24cbea1bf63d8eaff25d0, request_cb6769755664467b9a58df2a3ccb26b1, request_ea3dee0d3301467580f3e344d6ec6637`
- Evidence:
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "audits"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "readAndBurn"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "search"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "systemHealth", "systemUpdate" or "systemDebug"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "pastes" or "paste"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "users"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "deleteAllPastes"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "me"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "pastes" or "paste"?`
  - `GRAPHQL_FIELD_SUGGESTION`: GraphQL engine leaked schema field names via field suggestions ('Did you mean...').
    Preview: `Did you mean "deleteAllPastes"?`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### Possible GraphQL Marker Reflection

- Severity: `LOW`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (mutation: createPaste)`
- Attack category: `XSS`
- Detector: `GraphQLReflectionDetector`
- Requests: `request_02f708a5f2e64b018f7bf52c84fc6e37, request_0baadd957be947238ce6e6b0bb7d37cc, request_2e7516f0d620484bbae2f41f1ee76956, request_3c3e1d191f13472cb4b8773bbbce5a0b, request_42f6806798f84ab4a1d04c3226dc400a, request_44229a70a3454287bcfbdec65b800774, request_492e17fa8f94423a8898a026c112ade0, request_70609e63cf7546eba251ab1c539ff0c8, request_707c2578c10847ada7546d34bfcaef78, request_73d7b4d98e764f819d676ec3c733c2fa, request_7582119c3bdd43dabc8dc03ebac8af8b, request_bbdb06d1cee0461c95983207cdb61b09, request_c4d553d2c3cb4d3cadcebdb25977823e, request_cc8398360f7142dabc2a50c97cf2a0cc, request_f33747f5df1046d7a2fd123b007b6d5f`
- Evidence:
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
- Recommendation: Avoid reflecting untrusted GraphQL variable values, or encode them for the response context before returning them.

### Possible GraphQL Marker Reflection

- Severity: `LOW`
- Confidence: `MEDIUM`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `XSS`
- Detector: `GraphQLReflectionDetector`
- Requests: `request_05a80d561a674ffc9dad01dafc872f0e, request_0768f6d18885454e9d0127e7faf50393, request_099c885b19d0449eb3a782f8da9187c1, request_0cd630ec8bcf47ca8e93334cb32c58c8, request_0e5b135da58f4dbabc916dfe87626d16, request_1a817035f7c54f3e9af2f7b8b0faa9c7, request_20264731d507424c8168daf4f7d49aab, request_205ac667a1744187a4acbfcf2d54cf9a, request_3acd419e0e1443dda62827820e4dbbab, request_3ffe559ada934313957ed94a757c4985, request_458e6a138b22446089a8492d7f505355, request_4adcce7c07d24f5fad2ef1299e4214b3, request_4aff29fdc689496b84ab2cc18d7cee85, request_541e47e4c3ab40099f08e9a236329a0a, request_61f45d700e764933b02c611ddacafdb4, request_71746f91df6642b6a72aab0e0939a886, request_71df7fd989734771a0faf5ab18ac7599, request_7a6eb74255074c30a66ff501defedfa4, request_917b9cc50790423f8ac8c371205485b6, request_9ecb2f73d1fe4f92bee525b351870935, request_a0cae7068dd348ce9728e3b3cb352033, request_a506f5ff2ed94dafad2193273969a770, request_a6491645994c4377b216a752a980118b, request_ab25ed385d25490cb4b58b9ecc5daf39, request_b3b472dd8d834cb5bbece81ea3ae13a4, request_bb68273176494fa896d818bf044332a8, request_ccec35c2c0f64b33be68a58e42d2bcee, request_cd9aac2ecfab433f8a63aeebb90fd6f7, request_d050d6d9d4444af291d2624e1c76180f, request_da018ae96bf1422eba80930ac52b54e9, request_e4d5049305b04576ab925c852ecd2cbf, request_e69bbe8a30b041d7aa36ad070d89b6f6, request_e7b6b43ac0f642c69c068e35686f3721, request_f65f04ccf78f4011a051afd95a46db2a, request_f6e1066f200f43e69a84af5f71edb12d, request_fdd84e1245b44eb9bd98a05f4350a553`
- Evidence:
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_nosql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `https://yslfuzz-ssrf-marker.invalid/resource`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_reflection_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_command_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_graphql_sql_marker`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
  - `GRAPHQL_MARKER_REFLECTION`: Inert YSLFuzz GraphQL marker appeared in the response preview.
    Preview: `yslfuzz_unknown_field`
- Recommendation: Avoid reflecting untrusted GraphQL variable values, or encode them for the response context before returning them.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `COMMAND_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_03b3b7ae3d06480caa23545f63605ae6, request_707c2578c10847ada7546d34bfcaef78, request_73d7b4d98e764f819d676ec3c733c2fa, request_847c74d8b2534ace94fda3ebfca97afb, request_a522795fbe6343ba81f90fa67c86805c, request_c4d553d2c3cb4d3cadcebdb25977823e, request_fa5057868f72440ca924e74e5b5aa7a4`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `COMMAND_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0768f6d18885454e9d0127e7faf50393, request_0cd630ec8bcf47ca8e93334cb32c58c8, request_ccec35c2c0f64b33be68a58e42d2bcee, request_d050d6d9d4444af291d2624e1c76180f`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INFORMATION_DISCLOSURE`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0261734c4df84a949656455a1c6060c2, request_0e5b135da58f4dbabc916dfe87626d16, request_20264731d507424c8168daf4f7d49aab, request_205ac667a1744187a4acbfcf2d54cf9a, request_3acd419e0e1443dda62827820e4dbbab, request_458e6a138b22446089a8492d7f505355, request_4adcce7c07d24f5fad2ef1299e4214b3, request_4fc622adf3db4db1b97529799f665e4d, request_52f292618dec47d8b4ff537899dbec9a, request_541e47e4c3ab40099f08e9a236329a0a, request_69bf7d2dd5274c44b4f9278472725921, request_6b2c272ce916430e888b220cd2416fd2, request_7a6eb74255074c30a66ff501defedfa4, request_7f473af72bc14cfcafd44f9678cad473, request_807238721adb40b9a9b4815b77c59ea8, request_8bfd314354474134beb3d0c6ba597d9f, request_8c945b52926040a98741ccfd9d6b4f70, request_9035789a867e47ffbf656d10e6cbe018, request_917b9cc50790423f8ac8c371205485b6, request_ae3ee5f887aa4237ac09d1674e0abb3e, request_af0cd3f5f3074027a082427f4a4531bf, request_b3b472dd8d834cb5bbece81ea3ae13a4, request_c57ad596639c4f7db08c7fffbbd51fb9, request_caade25e30e24cbea1bf63d8eaff25d0, request_cb6769755664467b9a58df2a3ccb26b1, request_e4d5049305b04576ab925c852ecd2cbf, request_e69bbe8a30b041d7aa36ad070d89b6f6, request_e7b6b43ac0f642c69c068e35686f3721, request_ea3dee0d3301467580f3e344d6ec6637, request_f65f04ccf78f4011a051afd95a46db2a, request_f6e1066f200f43e69a84af5f71edb12d, request_fdd84e1245b44eb9bd98a05f4350a553`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible GraphQL Error Disclosure

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (mutation: importPaste)`
- Attack category: `INFORMATION_DISCLOSURE`
- Detector: `GraphQLErrorDisclosureDetector`
- Requests: `request_078d45da6a204998bdbfff32e95d76aa, request_099c885b19d0449eb3a782f8da9187c1, request_2f0aa3099ec147eba4b3381e2041aca0, request_32eed905fad64fabb06cfbc37960aa6e, request_63a5a58a4a5c44c786c9f5571e486675, request_71746f91df6642b6a72aab0e0939a886, request_71df7fd989734771a0faf5ab18ac7599, request_9ecb2f73d1fe4f92bee525b351870935, request_a0cae7068dd348ce9728e3b3cb352033, request_a100206f8eec4ba7ab9d4f873ad43e7e, request_a6491645994c4377b216a752a980118b, request_ab25ed385d25490cb4b58b9ecc5daf39, request_da018ae96bf1422eba80930ac52b54e9`
- Evidence:
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
- Recommendation: Normalize GraphQL error responses and keep stack traces, resolver details, and internal exception messages in protected logs.

### Possible GraphQL Error Disclosure

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INFORMATION_DISCLOSURE`
- Detector: `GraphQLErrorDisclosureDetector`
- Requests: `request_e8d10cbb72774278be95fae6b2134229`
- Evidence:
  - `GRAPHQL_ERROR_DISCLOSURE`: GraphQL error response contained internal-looking implementation detail.
    Preview: `[REDACTED]`
- Recommendation: Normalize GraphQL error responses and keep stack traces, resolver details, and internal exception messages in protected logs.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_00e219d6d2054abe9fc7a7a94732681d, request_02ad8b2c462f4a2ea63ff3ea57901aba, request_04b20f19c474431ca57e9ba32238249f, request_062815736ab84799bf6356f078186328, request_08c5f1a48a0646618d82acc47a96e616, request_09bbe23a41464c5cb5d0a78e3b46c971, request_09c2c77bd312437c907cd4529fb77c57, request_0d602dc78ff2456280e6a4b0f79346bf, request_0eeba7b58e0c4af8aa8881b4e59ded6f, request_0faaff920e7044d2bc2cd15960f6dcf2, request_2410e27b20dd4f799241d82bbf597616, request_2ad98673b0fd44c39fa389aa467b75c2, request_2cd4c145e86a4189907aa0a01cdc1204, request_2efa332f429d4bbaa5e9e1eaa971e6a9, request_305b64bcaaca459195b1ac3d1644cd26, request_34e74d13038e4dc2bc939144cc020f86, request_37b968efe894468eb1124be4385c8490, request_3853f76a01284077b35c6c96b735d32c, request_3fac4949dae74c07b829bcfc10c3d1a8, request_457e54e541374f80a8faa805befa2ad0, request_46044f7c48bd4182ba00c75dd52de544, request_4693fa1f27ec49ec8b6138eed113d6ea, request_4c260b7546de43cb8eeb11841148b064, request_4ebf43659c8f4e9b936089a43477ecce, request_4fa829d5a5474d59a004fc22d606af09, request_5b48d4f6713a43ba9e1a1b9094c253da, request_5bb4541f2ff240dda52fddd61752c64a, request_5be3a85e3472419fa2af5ce9c8057fff, request_5fe4731bdc1e47a2be0f676fdcb9c6fd, request_682547a4888749c79234a579aff14d1b, request_6989d46efdb242e59d71211d42126cbb, request_6c5758be38364c1e880d90f6d2e1b78a, request_6cb4552303c04bc2af2ec873925b943b, request_6f3d4fb3aed44d819dcf52bf4fdeafad, request_6fd9d2f3c6a9434d89276d6dddbea95e, request_71d5a842a0994ad3b441adbda2e02592, request_7649210520f745f4bff7de0dac104942, request_783660753e1340399f997bc30ae9c4cc, request_7d3fb2089f7040c7b8a2e2ea0f26c310, request_7d638fed750e4a06a081dbaecf95955d, request_852b67a167444d8ab0ffc017cc1fbf63, request_87dfbfcac0d04d9d961e41a0222094c3, request_889db73574744ca0828c83ccae5c436a, request_8c85524808c54dcf872666281751433d, request_8fb95addaca442949a3a214cad2f8b84, request_9115ac1f663244d09b062ff18002776a, request_99819fc5220b446ab5e0a749dacbcce4, request_a0f5cbf867e64b62b83ec3616eb031f7, request_a2d75b0b06c94ee4a41fb5ebe7175f6f, request_a37be004e29a4f3c9f78491c90d6376a, request_ace66b65718e423aad42f8d72605b293, request_af73cf18285544b4b3492c83d9a4f98e, request_b5b2513cb0eb42cd9bb3aafa0bb14bfe, request_bbb8c94e80d24441a4dc02c38340622c, request_bf525b42983a4f4192586546942ebe79, request_c2c9aac05d9f4b30a1618053c059cf6d, request_c9ccc4785f8c4918aa62e76d27a60e33, request_cf198ed7724b4bcd9b35b5f56a5c2415, request_d18dffd4e4f94664a0c6aef46a09e98f, request_d67a67d00ce84755b2e793973e80a59b, request_db0e4a4e3d444449b61ffe075c010670, request_df2964d08928433db35d835c72656435, request_e171451c0d2a4caea21a8e1fc373c938, request_e55579f41aff451684f1e82549b504c3, request_e8d10cbb72774278be95fae6b2134229, request_ecdf581f3e0a4f22895c9bf9eca5bc64, request_f248405470cc425f9dea3940a1c15ac1, request_f554b17ce97c4fe1b60bebbc0f7da280, request_f6792e4435d64e4581488bcedc14f86c, request_f68763e9091c46b3940473003324c26f, request_fa4bf21624e74088bd00a06ae4912d94, request_fa8cd739e70348cb945510d3dbb79fce, request_faaaf5a21cf746258b34978a6f3dce96, request_fb6afae5026e4dc78f5d0edf55212b29`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_080f548c13bf48d3bef9f04391a83731, request_10fb51624eb645a88bb300183b383ae0, request_29206d8752b442f794b1d5e895cc249b, request_29209e6adc414479949fd622de2ca2b0, request_35c4a8a3dc70439e84169c52584c5ebd, request_36866d88eece468a89cb399de836c94c, request_63a5a58a4a5c44c786c9f5571e486675, request_77ae17e9f09343caaf6258c2923b0a9f, request_77ec830fe812439ca263ac8296e7c73b, request_828df15bc6cd412c8bba903c9cd30f0d, request_8bb7797ec14e4cfcad86714a1791b60e, request_947ddcd60d3347ccaae11ddee97dd034, request_987129fad39945df977aeb770a9601db, request_a115c3e51a084661bfc2957a3b50007a, request_a7d399a354fc44a6816e2c9b91903835, request_aaf252b224f04c8c89d87a07d01ece0a, request_ad0df19f2d94443da2ce3d434c723232, request_af52caa88e7b4626915deacc4293ef17, request_c4bb7c3f11bf4d7681114e36ea891ea4, request_cdd838b4f7d847cc9b083e51662cadd1, request_df60d345d0ad42b5b63bd28a36b723e3, request_e874e2dd9f9f49d399d2e3a6e9cdfa5b, request_f7f5e371bb7642008caa936865728092`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (mutation: createUser)`
- Attack category: `MASS_ASSIGNMENT`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0434a67c8e7d4322ba6c673d62064ec8`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_2e7516f0d620484bbae2f41f1ee76956, request_35879d7d01044e24b0d28ae33205b3fc, request_42f6806798f84ab4a1d04c3226dc400a, request_ccc8864cab7b4d67bb405974081da496, request_d26a2da5cefd431da0d57383d9f84a68, request_d979e0cf6b87457eb3cee92429d4abfb, request_f33747f5df1046d7a2fd123b007b6d5f`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_099c885b19d0449eb3a782f8da9187c1, request_9ecb2f73d1fe4f92bee525b351870935, request_a6491645994c4377b216a752a980118b, request_ab25ed385d25490cb4b58b9ecc5daf39`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `SQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_02f708a5f2e64b018f7bf52c84fc6e37, request_05b85b05e2124a098ad97ffe16d84058, request_176c0601d022489795e776994e2418b0, request_7582119c3bdd43dabc8dc03ebac8af8b, request_80b3b4cf22e34ecfbd896cc7385fd777, request_8d65324f17174e42ae512ef6cf099868, request_baf86733342744f5814dee8b79fce8e9, request_bbdb06d1cee0461c95983207cdb61b09, request_bcf9707460da44ebb2f3da2567678be5, request_d274de3119e34b18992c1c8576b5458e, request_d8df7df97731481a86ff80c7b09cf4c1, request_e814bbb7732f44dc8e8f922f46db24f2, request_fb1174f4e13d417c84dfb5853ca6be59, request_fd74456b5dce4102a4cf234d92d8b1be`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `SQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_078d45da6a204998bdbfff32e95d76aa, request_2f0aa3099ec147eba4b3381e2041aca0, request_32eed905fad64fabb06cfbc37960aa6e, request_71746f91df6642b6a72aab0e0939a886, request_71df7fd989734771a0faf5ab18ac7599, request_a0cae7068dd348ce9728e3b3cb352033, request_a100206f8eec4ba7ab9d4f873ad43e7e, request_da018ae96bf1422eba80930ac52b54e9`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (mutation: createPaste)`
- Attack category: `SQL_INJECTION`
- Detector: `ReflectionDetector`
- Requests: `request_176c0601d022489795e776994e2418b0, request_80b3b4cf22e34ecfbd896cc7385fd777, request_bcf9707460da44ebb2f3da2567678be5`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `SQL_INJECTION`
- Detector: `ReflectionDetector`
- Requests: `request_078d45da6a204998bdbfff32e95d76aa, request_2f0aa3099ec147eba4b3381e2041aca0, request_32eed905fad64fabb06cfbc37960aa6e, request_a100206f8eec4ba7ab9d4f873ad43e7e`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `SSRF`
- Detector: `DifferentialResponseDetector`
- Requests: `request_05a80d561a674ffc9dad01dafc872f0e, request_61f45d700e764933b02c611ddacafdb4, request_a506f5ff2ed94dafad2193273969a770, request_bb68273176494fa896d818bf044332a8`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `SSRF`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0baadd957be947238ce6e6b0bb7d37cc, request_3817fe2a0f164d17b9abbd5d98581fba, request_3c3e1d191f13472cb4b8773bbbce5a0b, request_44229a70a3454287bcfbdec65b800774, request_44d500e32ee14d7c99ed9fe245118fdd, request_dcddf315caf54b168757e5267e28e1ae, request_fa0edc218337400bb0ce566e52257e60`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: users)`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_1a817035f7c54f3e9af2f7b8b0faa9c7, request_3ffe559ada934313957ed94a757c4985, request_4aff29fdc689496b84ab2cc18d7cee85, request_cd9aac2ecfab433f8a63aeebb90fd6f7`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /graphql (query: pastes)`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_492e17fa8f94423a8898a026c112ade0, request_682bb5217c4e461d83a7f80bc2bb0abd, request_70609e63cf7546eba251ab1c539ff0c8, request_93340c37b03d4d999a66c54c94536962, request_af53589d4ae74514b035a9100b4234d1, request_cc8398360f7142dabc2a50c97cf2a0cc, request_ce82848b78d84faba95fd7fd196dd426`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]


## Reproducibility

- yslfuzz_version: `0.1.0`
- scan_run_id: `scan_8418cbcb0aea4c41a677ad0f81ccf871`
- target_id: `target_279fe3f8788d4d5ebad8fcbb89b0167c`
- api_schema_id: `api_schema_1b485c4e8a67480ebce631d5ebfb728f`
- random_seed: `0`
- started_at: `2026-10-02T13:59:54.427486+00:00`
- finished_at: `None`
- generated_at: `2026-10-02T14:00:42.153710+00:00`
- dry_run: `False`
- attack_execution_enabled: `True`
- mutation_execution_enabled: `True`
- destructive_methods_enabled: `False`
