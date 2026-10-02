# YSLFuzz Scan Report

## Target

- Target ID: `target_fc9710098dac455886d2b0b274defe8d`
- Name: `127.0.0.1`
- Base URL: `http://127.0.0.1:8888`
- API style: `REST`

## Scan Summary

- Scan run: `scan_1d5f42b046bf4629bdcee2f9e796f9f5`
- Findings: `343`
- Requests: `476`

## Severity Summary

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 64 |
| INFO | 0 |
| LOW | 153 |
| MEDIUM | 126 |

## Stateful Workflows

- Enabled: `True`
- Workflows detected: `7`
- Workflows executed: `7`
- Dynamic parameters propagated: `3`

## Endpoint Summary

| Method | Path | Tested | Requests | Findings | Highest Severity |
|---|---|---:|---:|---:|---|
| POST | /community/api/v2/community/posts | True | 15 | 12 | MEDIUM |
| GET | /community/api/v2/community/posts/recent | True | 13 | 18 | HIGH |
| GET | /community/api/v2/community/posts/{postId} | True | 8 | 10 | MEDIUM |
| POST | /community/api/v2/community/posts/{postId}/comment | True | 14 | 18 | HIGH |
| POST | /community/api/v2/coupon/new-coupon | True | 13 | 2 | LOW |
| POST | /community/api/v2/coupon/validate-coupon | True | 7 | 6 | MEDIUM |
| POST | [REDACTED] | True | 7 | 5 | MEDIUM |
| POST | /identity/api/auth/login | True | 7 | 6 | MEDIUM |
| POST | /identity/api/auth/signup | True | 19 | 12 | MEDIUM |
| POST | [REDACTED] | True | 7 | 12 | HIGH |
| POST | /identity/api/auth/v2/check-otp | True | 13 | 8 | HIGH |
| POST | /identity/api/auth/v3/check-otp | True | 13 | 12 | HIGH |
| POST | [REDACTED] | True | 7 | 1 | LOW |
| DELETE | /identity/api/v2/admin/videos/{video_id} | True | 7 | 2 | MEDIUM |
| POST | /identity/api/v2/user/change-email | True | 13 | 13 | MEDIUM |
| GET | /identity/api/v2/user/dashboard | True | 1 | 1 | LOW |
| POST | /identity/api/v2/user/pictures | True | 1 | 4 | HIGH |
| POST | [REDACTED] | True | 7 | 3 | MEDIUM |
| POST | [REDACTED] | True | 13 | 10 | HIGH |
| POST | /identity/api/v2/user/videos | True | 1 | 4 | HIGH |
| GET | /identity/api/v2/user/videos/convert_video | True | 7 | 5 | MEDIUM |
| DELETE | /identity/api/v2/user/videos/{video_id} | True | 7 | 7 | MEDIUM |
| GET | /identity/api/v2/user/videos/{video_id} | True | 7 | 9 | MEDIUM |
| PUT | /identity/api/v2/user/videos/{video_id} | True | 31 | 15 | MEDIUM |
| POST | /identity/api/v2/vehicle/add_vehicle | True | 13 | 7 | MEDIUM |
| POST | /identity/api/v2/vehicle/resend_email | True | 1 | 0 |  |
| GET | /identity/api/v2/vehicle/vehicles | True | 1 | 0 |  |
| GET | /identity/api/v2/vehicle/{vehicleId}/location | True | 6 | 11 | MEDIUM |
| GET | /workshop/api/management/users/all | True | 13 | 5 | MEDIUM |
| GET | /workshop/api/mechanic/ | True | 1 | 0 |  |
| GET | /workshop/api/mechanic/mechanic_report | True | 7 | 5 | MEDIUM |
| GET | /workshop/api/mechanic/receive_report | True | 19 | 10 | HIGH |
| GET | /workshop/api/mechanic/service_requests | True | 13 | 6 | MEDIUM |
| POST | /workshop/api/mechanic/signup | True | 24 | 10 | MEDIUM |
| POST | /workshop/api/merchant/contact_mechanic | True | 35 | 10 | MEDIUM |
| POST | /workshop/api/shop/apply_coupon | True | 13 | 2 | MEDIUM |
| POST | /workshop/api/shop/orders | True | 16 | 16 | HIGH |
| GET | /workshop/api/shop/orders/all | True | 13 | 7 | MEDIUM |
| POST | /workshop/api/shop/orders/return_order | True | 8 | 9 | HIGH |
| GET | /workshop/api/shop/orders/{order_id} | True | 8 | 18 | HIGH |
| PUT | /workshop/api/shop/orders/{order_id} | True | 20 | 22 | HIGH |
| GET | /workshop/api/shop/products | True | 1 | 1 | LOW |
| POST | /workshop/api/shop/products | True | 19 | 4 | LOW |
| GET | /workshop/api/shop/return_qr_code | True | 7 | 5 | MEDIUM |

## Findings

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_1c2b7f448ce04f81b18ec4bada7a5ad8`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_4459c03301bf4d93844c7ffc9791551d`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_3bc3f663f65c4f62b1de336b7441eabc`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_3bc3f663f65c4f62b1de336b7441eabc`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_3bc3f663f65c4f62b1de336b7441eabc`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_3bc3f663f65c4f62b1de336b7441eabc`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_e68da9ef0c964533a820c11f4b286665`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_3bc3f663f65c4f62b1de336b7441eabc`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_e68da9ef0c964533a820c11f4b286665`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_c42cc28abae9426aac1b2a6b64fc123a`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_3bc3f663f65c4f62b1de336b7441eabc`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_31d2baf450d54a559b8df16169c2d428, request_4cc78713853a4131aba83c4987ea739a, request_603269ba25b34101aa7529bc77768b19, request_feeb2b0ebdf042919c48b1259a59393a`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_e535507f4b7f4f729f3b5f5960a0e754`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_cf8960e56a9949cfa5f0f14832f15c7a`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_fef289a41bc249f6acedb9ff89af9853`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_565b24d797524935974f6ce56ab91836`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_d79c2ee32dfe48c88d113dcd3d72026f`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0478b9fa58024840a0f856b92fe5008c`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b21388dc7cf94be58e100f60091d0f04`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b21388dc7cf94be58e100f60091d0f04`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b21388dc7cf94be58e100f60091d0f04`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b21388dc7cf94be58e100f60091d0f04`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_67bf1ca2776444da99881cad271c252b`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_67bf1ca2776444da99881cad271c252b`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_67bf1ca2776444da99881cad271c252b`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_67bf1ca2776444da99881cad271c252b`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/pictures`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_c7ab7d483f0e4145a5c83b21708f329b`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/pictures`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_c7ab7d483f0e4145a5c83b21708f329b`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/videos`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_77631b3094554417bdd06bf65a1ed719`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/videos`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_77631b3094554417bdd06bf65a1ed719`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b54cf2929df9421a9e2ab2bca71f5a09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b54cf2929df9421a9e2ab2bca71f5a09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b54cf2929df9421a9e2ab2bca71f5a09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b54cf2929df9421a9e2ab2bca71f5a09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_07b367c84586472abfd7e31c373e9a7d, request_1cfa4b8c7ecb4b9db0288f3727bb290b, request_22d55763c261442b92606a9e5744a4c0, request_2fffb6252bbe462e9828dc7d40a797dd, request_3403baade5114fb68e9f88cbd3192c05, request_4c9f6308463242638f16bc2aea58e624, request_8430520debce4bdea9d8b16aed289b56, request_ad7a7273398242cd9f96832592c05863, request_ad9542daf0de40c59963f88f85135d5f`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b54cf2929df9421a9e2ab2bca71f5a09`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0fb0c997a94c4cfea3e864b2650897be, request_12917d58260a4450bb085ee30959439d, request_4f848881b6ec4e9e835e0d1e4e40b79b, request_626faec808d941748acda2cd807a0a6e, request_a13b6a065be84c22a1b7efd5683960e4, request_ad92e8061ebc4402a4720398de73921d`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b54cf2929df9421a9e2ab2bca71f5a09`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_4232c7496c104e18aa87685778875a87, request_460cdfc6acff472d86ec29a542799b86, request_4784a430fd8841088218a44153dccf99, request_795ecd90657d46a992cc358ee1af2800, request_88e4e7e2dc564013b1f9ede4617343b1`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_01a6a5eac68e455081e17c4a04aa4c63`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b4ef7367a1bb4b31a26602d9dfecac6c, request_d5bbf2bc55484d608f47987eb5992366`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_187c3c1a34d94e858a1a69b7e7651709, request_239e22205fa04e18a26065c6af90ad4e, request_3db494160bba4d93bf17e12502f00d8b, request_e85eb42f8a344d0f8e40be5368749cef`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_35d4c24ffedb47f985980f9246dd4a88`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_dcd16217f29b4c3bbf51b2faaba461c0`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_a080cf945e0042b68cccb08695a0a05d`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_27b81551dcd141efbe2ebe3e58a16d29`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_df76b37d2d3f4146bfb702dc8092f6fe`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_35dac108fcee4d68a1636fb4e5847605`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_7edd1581bd2c4d34aae35a1affd022fa`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b89bddb4f76b4aa1a69b898de073bb09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b89bddb4f76b4aa1a69b898de073bb09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b89bddb4f76b4aa1a69b898de073bb09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_7edd1581bd2c4d34aae35a1affd022fa`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_7edd1581bd2c4d34aae35a1affd022fa`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_b89bddb4f76b4aa1a69b898de073bb09`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### BaselineCrashDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `BaselineCrashDetector`
- Requests: `request_7edd1581bd2c4d34aae35a1affd022fa`
- Evidence:
  - `baseline_5xx_crash`: Baseline request conforming to schema caused unhandled 500 server error.
    Preview: `HTTP 500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_2f135e1e28e34ea3be8399c34bda6663, request_3d0227e8c012441c986d2e8da1448f67, request_c7609bcc71db4a388d9b0a29fb4759eb`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b89bddb4f76b4aa1a69b898de073bb09`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_15475289453f4b1880e32690e1c9ddc6, request_7fb8ca19fc9b4032b8f831c81da5331b, request_9bddc5a457e44c2a92a9f56b9e9fdcc0, request_ab87e71c048742359e886b058a963d89, request_c7af6a6248e04f9d85737f62e15a914f, request_f476d21f4514437693c3196fd8fcfbdc, request_f5c1af106a0f4192bfdb005383ad877d, request_f99fd82fc1664f8b9f56d720f34e5676`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0b609d5841b74d79a98e9cd5256c1eec, request_1e33bdec9ab945acab990f6b5a2c85ab`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_7edd1581bd2c4d34aae35a1affd022fa`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b89bddb4f76b4aa1a69b898de073bb09`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_7edd1581bd2c4d34aae35a1affd022fa`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `HIGH`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_3518b03d2d214fe68552291c2cc83e09`
- Evidence:
  - `undocumented_status_code`: Undocumented 5xx status code 500 not specified in schema responses
    Preview: `500`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_67db99097daf4b9983e2f5a57d21e624`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_92f782602e5442d383d6889bb773236a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_fda0b066184c4c89944b989733c4a1f3`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_5f779432e74a4dc8aa26e08e0552c5f3`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_8fce046c14904e0f822a1bd8b3f78b8d`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b9cce24c8a63430c9feec70bfa5af5ad`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_429269abd82b4a9898fb52053243b8e6`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_d10f83f535db4353bd7c7c10610b04b2`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_158b55e70ce64cc992ee109f63d3479f`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_5f779432e74a4dc8aa26e08e0552c5f3`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_25fe5f9dd6914a6f8f42037586f718d5`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/login`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_33c79ce13b674725aa35221800f8743d, request_7bae1303f6194c3ca060bd92b783d22d`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 401 not specified in schema responses
    Preview: `401`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/login`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_03612b0cbc7046f8aa77be793850c0da, request_2a7f6f946d744d70af88ddbb7207860f, request_615fc7c276c5499e8ca5e4acf41b8f0c, request_7e3123bb41124b1f9f6f34cc28f6ecbc`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 401 not specified in schema responses
    Preview: `401`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_77558490dd434950b40ca1ce55d7c8fb, request_b2d9a700cb734512bfb93bc464e01a9c, request_d833963b85ad4b99b63d1964dc9d6543, request_ecb3447ee0f94640a353760a81bead34`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_10cff16b59384a15959160a7f180d674, request_26c55785585e4c3cb8cea57cd41cc512, request_4335dcf24ba4480cb3e0de5e7d3ade51, request_49f8da634caa480889eab74dac1e0392, request_863048697b4f4887883981ea382bb54a, request_8ac0acbe26b74bfc846df111f763d9b8, request_9913ffb3b31d411ba74ad9cadf8f744f, request_ffe11164a4a34482870f2036c7bf4644`
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
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_5e263a6d692241f3898947008fb24ceb`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_7e419925438d46628be115a2b1974b44`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_67bf1ca2776444da99881cad271c252b`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_67bf1ca2776444da99881cad271c252b`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_11d898df9c2f4dc5b9b240c756512ac6, request_329ec29711584daabb006d08d852469c, request_4d7bef71ede14855b9f4db3a6f34776a, request_5b08c5f4ed5744cfa6d9f98516033c9e, request_685a39e0354740c1943fef457c926206, request_885f6e451e8e4ea3b27696e7dddf177e, request_c69f81f95ea4417e901b0448e79a26fa, request_cd74330e52bd452d9ecb00f7625fc448`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_848954512b1d43f2a310182572650cb5, request_d0d8055aa8674c7fa232c7adcee393de, request_f484fedaaaf8463198fa8b841c3a16e9`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `DELETE /identity/api/v2/admin/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_418fb1e9dfc4493f96c48e07655ead46`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0de384b94cd44dba99e1e98f43009616, request_324c8866fe44462986c4f57cf02ca64b, request_39e26314c0464e62ad40a568931ff812, request_8f59577679954197b442573ebb52f01f, request_b1d78d177f334e4bbb2a7370299adbae, request_ea944f42edae43e8bd2484e2ad0eca1e`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_50d6e1d0334b4fc69cb94c0eb953943a, request_872b060fb7fd4ad9af99266bb58ffcc7, request_dac0dd83fd4246dd8942cbfcad42ee21`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/pictures`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_c7ab7d483f0e4145a5c83b21708f329b`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/pictures`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_c7ab7d483f0e4145a5c83b21708f329b`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/videos`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_77631b3094554417bdd06bf65a1ed719`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/user/videos`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_77631b3094554417bdd06bf65a1ed719`
- Evidence:
  - `content_type_mismatch`: Response Content-Type 'text/plain;charset=utf-8' does not match documented 'application/json'
    Preview: `text/plain;charset=utf-8`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/convert_video`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_600e4e6811f14c1b8c4dfca954d325bc`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/convert_video`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_049d5f9ff4a94bea9a0d4bdf21b3e613, request_44622dd4855a412f879f1a8bd33eba48, request_89072256191f47b0b9587cb350de81fe, request_9258da78cf0449daae16b191ccadd86f`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/convert_video`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_062d7a5da1de4ae198cdf8ce7896afaf, request_15ca1cdcb6b545e7b80f131cc156a1a5`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/convert_video`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_600e4e6811f14c1b8c4dfca954d325bc`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 403 not specified in schema responses
    Preview: `403`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_e19a6186d3cb4923820e14355ad4f3c5`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_14175c66db5d4695903e9c508a70d78a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_80d5d50859394b61b301f6553f2af9d9`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_ee8ecea0bd76406d926c5da8e426ab86`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_e1df9f6d0581441dac3ac72fc41a0148`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_1e7160920d74489d9b5327166330076a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_f0cc535a780e4a278daaea4defc86d5c`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_1e7160920d74489d9b5327166330076a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_ef31e5e97ae64c7f911b293ffb683980`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_315d4038e4f94e3d929a1d7d0b4b6e87`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_1e4ca9acf647454da3ec7d55b45cef8a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_bc093f0e5ad6436f84d061ba396f9e7a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_603d903ecf3645acb19082cde3e4bd9b`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_22933140a0e244a18aa7a6dc15976fb3, request_2d99ed9bb15a452aa0797ce8143bb715, request_2ef9d8b2fffb40efa3aefdf0a4b35b24, request_31b7d28f025441f185a09da9ed2d599b, request_5406e4107ed3488e8a6b8ada412ed2bd, request_5d3b9b266f34447581733c1b92b6e718, request_7f8e5dfb7f4643f2946f64fb7ff908c7, request_a09cb78e9ffa484eb138aae427e31917, request_b97804bb62f54510a0c626866aba761d, request_bd5ef14c759b4e63b8557ae1cab5f8fe, request_cb791a18a33e4b9e8ebdd08792cb5bbf, request_ccdd2f9e6bb1407f80b1ae8e1140e42b, request_d692a1bdc59646788dd9895ab728bab0, request_e303bdc1c1164fc9bb2bffb4d955e9b8, request_ec1fa474f707438db60f3d426e950d67, request_f35e0c388c7e4aecb3be677e2c36540c, request_f3eab00aca5b4b4db0bd9a1a71e0618e`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_5d1881a2af4248e5932f59986fd1011e`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_315d4038e4f94e3d929a1d7d0b4b6e87`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_16e267eea272446b82a69d60177e8a4d, request_40b4218d52984300aaad8e802d63a278, request_423706e5523944d8b3e7dfec3908680c, request_5ba179cd537b485ca44dca9f63eb4207, request_6416fa41a80f434ab4290e9c4e1b2e2b, request_a8dff3ad8be3484a8d00e7b83c9cc0a1, request_c576bb4072274d2db0f190b2b09becde, request_d82c9b43b351495ba199cf54fd5cd8fe`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_063ac4a13ee14a5da0a1ea583efcd21e`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0bafae3a38e848cfaa5e6faab9137fd2, request_2fff66221f914fc2845a022f198a18d3, request_3d02239792ba45cd9eef3f719ca136fd, request_a58c169261b3461d866bb7db0303c845, request_ca80999b8c9e48a9a9234c35816c4d6f, request_d3704c88ab304356952cbce4f98f78d8, request_ec949fd2d3354c898997cfb136b56e4e`
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
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_01d7e45e882346ee96e9f51019fdf7d6, request_50b2e6da82b24aedaaeabe00823fb1d2, request_9e11a0a710c84921b832556a20bbc3e0`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_44bf1caaee454de9b2fdfff5662e65d3`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_95e72d4f55e64757ab5903a308af72d9`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_b799ff51a40a40d08c7d58724dd67eda`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_09803dcfea1443d1af150d7b6921619c`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_09803dcfea1443d1af150d7b6921619c`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/mechanic_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0e8c14f50c9a4f599b11f3653c78011b, request_a38dae561c67471c886990a5b5500799`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/mechanic/mechanic_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_63df6ca0cf294db5a183f9eae8db56e4, request_84dbdc64822c4ab99fe92c18fad7bda6, request_c34097e809d8451b85981c2c1325876a, request_cfdac5ff438d4d058087fcd860c18984`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_37ad3071386c4cab9a9af85ca79e7cfc, request_4bdf00cdcae148fd8eff9c027d3161db, request_8a49b5eab4f44ce8bddb3bc760421327, request_a88320e904c448039389f61a012ad249, request_b0bd0e4aabec4dff8460318e990e23a0, request_d203422713274cd6a132738e0b2e1c71, request_e9c01fd9b5a04c3690e89a9938a0c191`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_10f501edf9b844459eea2c963a4d9cc4, request_b6ec606d50c84e4d80933377e2fcd315`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_16de8ec8842f44659e5fdb2a34ad03d8, request_1dc72d4bb667470994d76beb0509ccec, request_29c506f7cab24eb3a26637f475f4470e, request_43cc4cf63af9487f9197a353eb879138, request_4fd56e7dcd2842748be9f6d5d27dbb67, request_6496597708b648f9a703993d2e188dd8, request_b6aef4dd09514bfc9f9aa657934034e9, request_b83b7ab9b2f948ee8cf201de9922068b, request_ee43bb5d91cd41788c866e1ff7ce0917, request_fb1bdee71e764158b76a9ebb6fcaed74`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_4bb87fca438f4b9da556d26b5b5a6648`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0de51b85080143e59a4aad3b3ed147b0, request_191b9e232e5b42009c46d7fee3402cc0, request_1d5a6e75ea064eceb8662b22d61dbbd0, request_1e21df77b9c347b180554a04f1deb83d, request_33299abbb461446587ce38809657548f, request_452f5b552d7f4cf199ac4aefb79f2318, request_4f84873fb34b4fbfa979fea34c99708b, request_55e62c491b6f4bda90a5b8ba3e1ce892, request_60f89870be4e4b83aaa98e1d3b672b40, request_624a78431ce44e6b94349243f4a5574f, request_635e2740fa494c29ae50c5fc6ebace37, request_70a23749d94a4ec2b480ac4b2148256c, request_788e43576f8a417baaf60edc37423275, request_7fb84c9c87144468af78e774c538e7df, request_8698b4decf3b43b191310ccecec4a308, request_b1da43a4d6e2402a91179eb38e456ec6, request_cda85d4a92864c06ab7be6e6be2df627, request_e5e71f1e03db49b7899955e39bc2933c, request_ec3c3d7159b14f22ad0d24c1b45ed045, request_f746d42b8eb34d4eac6dd657e5da06ad`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_4bb87fca438f4b9da556d26b5b5a6648`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/shop/apply_coupon`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_7d57d2dd90cc408f87b45784aa23f57d`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for message

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_05215bf9b351402f91b41b93f4d5d420, request_37eaaa423ef84f439467c18a8ea4fd2c`
- Evidence:
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
  - `missing_required_field`: Required field 'message' missing from response body
    Preview: `message`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_60c3fc672fc74f92a579a11ba272f178`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_a8e2cd56cd2b4d81a74a95bb9051e91d`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_61b093d6c931412ab120a901ab82aa76`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for orders

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_1a750fac21d440e78dfbc6b89a3d3663`
- Evidence:
  - `missing_required_field`: Required field 'orders' missing from response body
    Preview: `orders`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for orders

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_1a750fac21d440e78dfbc6b89a3d3663`
- Evidence:
  - `missing_required_field`: Required field 'orders' missing from response body
    Preview: `orders`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal for orders

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_ce6de161b24d42dfabfa821407dae710`
- Evidence:
  - `missing_required_field`: Required field 'orders' missing from response body
    Preview: `orders`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_5ff4fdc604094ea29509f89ccfdf593f`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_9d43e62240bc451db6a1865b5950c896`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_6d38f87e07fc49b1b13502739910441a`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 404 not specified in schema responses
    Preview: `404`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/return_qr_code`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_949d4a7bcc2b4422af5cb750ae794809, request_b847d1c39aa94aff9963bb4f3dea6537`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 406 not specified in schema responses
    Preview: `406`
  - `undocumented_status_code`: Undocumented status code 406 not specified in schema responses
    Preview: `406`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `GET /workshop/api/shop/return_qr_code`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_02eaa50d69ad43959665c75253a23ddd, request_0b829f57d58d4c9ca9939f7578b27b56, request_b5d67fc5bbe0445291f52565fd7a7d3b`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 406 not specified in schema responses
    Preview: `406`
  - `undocumented_status_code`: Undocumented status code 406 not specified in schema responses
    Preview: `406`
  - `undocumented_status_code`: Undocumented status code 406 not specified in schema responses
    Preview: `406`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_8ace244b19054e88b6da577e2336ec03`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_24622e821d854c60a164a224a0d1f3d2, request_71922907de2e4b09b4180ecb135c3406, request_952fd2eb359d48c394b00d887992be91, request_faa175cbb0ca493f891b3b4fcf5c4575`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_0a99322d1c4b49d6a77e8cf3cb1101cf`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_19dee113d1e84eadac475a4007382f4d`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_6ca38d2861de42788286167d754314af, request_7d50cb845ddf43789a82f9d244dea8ce`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### SchemaConformanceDetector signal

- Severity: `MEDIUM`
- Confidence: `HIGH`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `SchemaConformanceDetector`
- Requests: `request_a7851a0acc1d4bd0b12090af5781681d, request_ff66d421b4954b82a7e68674fc4f993e`
- Evidence:
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
  - `undocumented_status_code`: Undocumented status code 400 not specified in schema responses
    Preview: `400`
- Recommendation: Review the endpoint behavior and validate server-side handling.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_3c92ea42d0064a2fa1facadeb47d3bbc, request_874364a937eb4a089c90d7aec6314864`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_2cac4424ebae4724b66e3e2c80f33057, request_73ca988e2e034735b4a204223009fb1b`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_7ecb8d6e42c94842a02fe765cdfe7e68`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_ce3cbc2ead0e49249da18d565fe30162`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_3fb36a7bea7a4f18b258bc66a8341ae4, request_40f7b168c2114ef49f917cc1909b33c9`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_6045fe816bb04dd98fc0242f23a40bb9, request_c24106201b4244ff839fcdf6ca64268d, request_e60bab0c677a4c78b9c610b17b690bf0`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_4459c03301bf4d93844c7ffc9791551d`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_1c2b7f448ce04f81b18ec4bada7a5ad8`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /community/api/v2/coupon/validate-coupon`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_67b3f16450cd414f89e60a485bc345ec, request_6b17d42095244b09aae102d98d53ff50, request_eaf8a2a454f94634b9163e0fdc5f1141, request_f7ecb412eee34fc49c283d013f64458d`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /community/api/v2/coupon/validate-coupon`
- Attack category: `NOSQL_INJECTION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_13af76c057e346b8875caad091e6204c`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /community/api/v2/coupon/validate-coupon`
- Attack category: `XSS`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_4374e1be9d9944b98efc2a48f8944c4d`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_ec6188ea15f54093a50575af205577b3`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/management/users/all`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_9b101f4513fc404ba8f0908850ab1260`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/management/users/all`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_a604816b379948fa99cd163124b93a68`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/management/users/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_d577540a0d694690af1aabfd1d054235, request_f2647b76a203420888b4b7506060d68e, request_f9e5f37851e04557ba45b6a2cdd0563b`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/management/users/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_5022f551ac2a441fa2c769d45c391fab, request_93bf7ea1d67b41aa9ee9fbf5de94bb0c, request_a96aa3bf67fd4d118242a5e899afc534`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/mechanic/service_requests`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_7fa59e3198ca4caeb91e003af7095501`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/mechanic/service_requests`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_a2e0fca1eb30468582b64895548d03b9`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/mechanic/service_requests`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_00cdce5e909c4f8884c5f54003eccdbc, request_83a7923f102f4bd883b4df3bca19df45, request_eaced9f1bf8446709334d5b1b54c5153`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/mechanic/service_requests`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_1557a6f18a754064a4e30988e8720fae, request_6499de3d7697450a85956bd77f8461fe, request_9a31ff7a47844b4baeeaaaee07137f8a`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_e9bb0b47ea5249cb83a3093a41f4df02`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_795ecd90657d46a992cc358ee1af2800`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_4232c7496c104e18aa87685778875a87, request_460cdfc6acff472d86ec29a542799b86, request_4784a430fd8841088218a44153dccf99, request_88e4e7e2dc564013b1f9ede4617343b1`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_01a6a5eac68e455081e17c4a04aa4c63`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_7d8f1eb8f5ed4b9fb4e2ac034b1ba26e`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_841990a85f2947728d3fc141df39c76d`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_62941a6d370c4ce2bef150dfa7edff07, request_cc43da6e1da9447db183bf836c16d4c3, request_e2541b1b2cec43dbbef7b647bf6d7038`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_29132aa1de494dd0ab6e56e6adda62d8, request_364e1712870c4196a03ff3e9b7ff270b, request_f066534a85c14725b45204a879d88bfd`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_b4ef7367a1bb4b31a26602d9dfecac6c`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_187c3c1a34d94e858a1a69b7e7651709, request_239e22205fa04e18a26065c6af90ad4e, request_3db494160bba4d93bf17e12502f00d8b, request_e85eb42f8a344d0f8e40be5368749cef`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_d5bbf2bc55484d608f47987eb5992366`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_a080cf945e0042b68cccb08695a0a05d`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_35d4c24ffedb47f985980f9246dd4a88`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_dcd16217f29b4c3bbf51b2faaba461c0`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Possible Broken Access Control

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_51187380d82d42099312f599942a81ea`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_df76b37d2d3f4146bfb702dc8092f6fe`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_bd0129a2b2b34eef992ffe066431b499`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_42939fe0e4064216b0e334ae6334bd3d, request_50c81b0ebca14b0fb66725dc3502906e, request_99ff76988336416e8a3659ee7e2cc2fa`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_0a7c55f500a64c448b374420a91f5bc3, request_4d265bc8542346c88d54addc210f5cd3, request_6eedccaa47c14a8ba0e0afe6d82e821b, request_72dce0b1f4b7438b9c07649e5ac4a20c`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_35dac108fcee4d68a1636fb4e5847605`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Status Code Anomaly

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_27b81551dcd141efbe2ebe3e58a16d29`
- Evidence:
  - `status_code`: Attack response returned a 5xx status while baseline did not.
    Preview: `200->500`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Possible Validation Bypass

- Severity: `MEDIUM`
- Confidence: `MEDIUM`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `ValidationBypassDetector`
- Requests: `request_527ae66b968a4ca0b9d5aba6d8ddbcba, request_5c6619ef39cb424ca1247d4e927ad089, request_c87d453eb35b49348420bb5011beaf57`
- Evidence:
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
  - `validation_bypass`: Invalid or boundary payload received a successful response.
    Preview: `200->200`
- Recommendation: Enforce schema and business validation server-side for invalid, boundary, and mutated inputs.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_d6f54bae33494b80b58f3cd116731a37`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `COMMAND_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_9f01574b23e7417cb6fc5a1c008f5a0c`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `COMMAND_INJECTION`
- Detector: `ReflectionDetector`
- Requests: `request_9f01574b23e7417cb6fc5a1c008f5a0c`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_01acc0d6d6d74070a03b6b7ee97d09ca, request_3c92ea42d0064a2fa1facadeb47d3bbc, request_874364a937eb4a089c90d7aec6314864, request_dddaccfcf2d54299a839f772b72f9385`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_2cac4424ebae4724b66e3e2c80f33057, request_73ca988e2e034735b4a204223009fb1b, request_9a2f1ba9e60d473f977c5a30dc4bc6d4, request_e4403e06e2ba4d5c8d8d030f90788fb1`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_3907a5c3bf554bdb9ede9b36000954f6`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_28da9229420a40ad9980d4b092736023`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_9a2f1ba9e60d473f977c5a30dc4bc6d4`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_67db99097daf4b9983e2f5a57d21e624`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `ReflectionDetector`
- Requests: `request_ce3cbc2ead0e49249da18d565fe30162`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `ReflectionDetector`
- Requests: `request_7ecb8d6e42c94842a02fe765cdfe7e68`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_1c2b7f448ce04f81b18ec4bada7a5ad8`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_3fb36a7bea7a4f18b258bc66a8341ae4`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_09fe1e552502497fbc8f21beb44d3768, request_6045fe816bb04dd98fc0242f23a40bb9, request_c24106201b4244ff839fcdf6ca64268d, request_e60bab0c677a4c78b9c610b17b690bf0`
- Evidence:
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
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_49edade2db9d4c138bac727d9abbc5b3`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_4459c03301bf4d93844c7ffc9791551d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_09fe1e552502497fbc8f21beb44d3768, request_6045fe816bb04dd98fc0242f23a40bb9`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_7096315dca444c6f839955bbdcd4ba48`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/recent`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_40f7b168c2114ef49f917cc1909b33c9, request_bc05814c40074b7ebf841916e36b3f06`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /community/api/v2/community/posts/{postId}`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_fda0b066184c4c89944b989733c4a1f3`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/community/posts/{postId}/comment`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_25fe5f9dd6914a6f8f42037586f718d5`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/coupon/new-coupon`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0a62977c2317488ab1efd5f9c90c0bec`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Status Code Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/coupon/new-coupon`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `StatusCodeAnomalyDetector`
- Requests: `request_0a62977c2317488ab1efd5f9c90c0bec`
- Evidence:
  - `status_code`: Attack response returned 2xx where baseline failed.
    Preview: `400->200`
- Recommendation: Review server-side error handling and return consistent expected status codes for invalid input.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/coupon/validate-coupon`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_67b3f16450cd414f89e60a485bc345ec, request_6b17d42095244b09aae102d98d53ff50, request_eaf8a2a454f94634b9163e0fdc5f1141, request_f7ecb412eee34fc49c283d013f64458d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `POST /community/api/v2/coupon/validate-coupon`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_13af76c057e346b8875caad091e6204c`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /community/api/v2/coupon/validate-coupon`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_4374e1be9d9944b98efc2a48f8944c4d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/login`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_03612b0cbc7046f8aa77be793850c0da, request_2a7f6f946d744d70af88ddbb7207860f, request_615fc7c276c5499e8ca5e4acf41b8f0c, request_7e3123bb41124b1f9f6f34cc28f6ecbc`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/login`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_2a7f6f946d744d70af88ddbb7207860f`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/login`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_7bae1303f6194c3ca060bd92b783d22d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/login`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_33c79ce13b674725aa35221800f8743d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INFORMATION_DISCLOSURE`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b2d9a700cb734512bfb93bc464e01a9c`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed; response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_10cff16b59384a15959160a7f180d674, request_26c55785585e4c3cb8cea57cd41cc512, request_4335dcf24ba4480cb3e0de5e7d3ade51, request_4d2b77724c2a43aaa637bc958b00b5d8`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_77558490dd434950b40ca1ce55d7c8fb`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_49f8da634caa480889eab74dac1e0392, request_863048697b4f4887883981ea382bb54a, request_8ac0acbe26b74bfc846df111f763d9b8, request_9913ffb3b31d411ba74ad9cadf8f744f`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_ffe11164a4a34482870f2036c7bf4644`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_26c55785585e4c3cb8cea57cd41cc512, request_4335dcf24ba4480cb3e0de5e7d3ade51`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_863048697b4f4887883981ea382bb54a, request_8ac0acbe26b74bfc846df111f763d9b8`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_d833963b85ad4b99b63d1964dc9d6543`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `SQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_ecb3447ee0f94640a353760a81bead34`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/signup`
- Attack category: `SQL_INJECTION`
- Detector: `ReflectionDetector`
- Requests: `request_ecb3447ee0f94640a353760a81bead34`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_12406e08599b4227b9c896f58fa3e9c7`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_47b093a240e04802ab7bbf172f11c2f6, request_52a769aaec5145d38318b4cccc4996b3, request_9d47bcc69e594a168f3576d7e2527515, request_a6f390c9266a4977bc1cb1e232006ab7`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/v2/check-otp`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_5e263a6d692241f3898947008fb24ceb`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_f484fedaaaf8463198fa8b841c3a16e9`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_329ec29711584daabb006d08d852469c, request_4d7bef71ede14855b9f4db3a6f34776a, request_685a39e0354740c1943fef457c926206, request_885f6e451e8e4ea3b27696e7dddf177e`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/auth/v3/check-otp`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_7e419925438d46628be115a2b1974b44`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/admin/videos/{video_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_418fb1e9dfc4493f96c48e07655ead46`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_e553c09a509141a5a8f8534aab1c5915`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Broken Access Control

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `BasicAuthzBypassDetector`
- Requests: `request_e553c09a509141a5a8f8534aab1c5915`
- Evidence:
  - `unauthorized_access`: Auth-related test returned a successful response similar to baseline.
    Preview: `200->200`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `COMMAND_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_50d6e1d0334b4fc69cb94c0eb953943a`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `COMMAND_INJECTION`
- Detector: `ReflectionDetector`
- Requests: `request_50d6e1d0334b4fc69cb94c0eb953943a`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_cmd_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0de384b94cd44dba99e1e98f43009616, request_8f59577679954197b442573ebb52f01f`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_64d52eee309249d4bc489dcfbc316708, request_ec6188ea15f54093a50575af205577b3`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_324c8866fe44462986c4f57cf02ca64b, request_39e26314c0464e62ad40a568931ff812, request_b1d78d177f334e4bbb2a7370299adbae, request_ea944f42edae43e8bd2484e2ad0eca1e`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_872b060fb7fd4ad9af99266bb58ffcc7`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `INPUT_VALIDATION`
- Detector: `ReflectionDetector`
- Requests: `request_b1d78d177f334e4bbb2a7370299adbae`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/user/change-email`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_dac0dd83fd4246dd8942cbfcad42ee21`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/user/dashboard`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_2268069185d7459c89f6d013e79b28fb`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/user/videos/convert_video`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_062d7a5da1de4ae198cdf8ce7896afaf`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_e19a6186d3cb4923820e14355ad4f3c5`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_d6f41523f9b54a548e2d4b9b46fee42b`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_701aa12017b443dc9de7ce2d5e36e6da`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_e297f3e490b747c0ad9cc8a38ccd0a5d`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_6e9e1cea376d4448aef45f1da8f197a9`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `DELETE /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_7241a691e1dc4e98825b024a66b3597b`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/user/videos/{video_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_f0cc535a780e4a278daaea4defc86d5c`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_6416fa41a80f434ab4290e9c4e1b2e2b`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_063ac4a13ee14a5da0a1ea583efcd21e`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_315d4038e4f94e3d929a1d7d0b4b6e87`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_603d903ecf3645acb19082cde3e4bd9b`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_2ef9d8b2fffb40efa3aefdf0a4b35b24`
- Evidence:
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /identity/api/v2/user/videos/{video_id}`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_5ba179cd537b485ca44dca9f63eb4207`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_50b2e6da82b24aedaaeabe00823fb1d2`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0bafae3a38e848cfaa5e6faab9137fd2, request_2fff66221f914fc2845a022f198a18d3, request_3d02239792ba45cd9eef3f719ca136fd, request_ec949fd2d3354c898997cfb136b56e4e`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_9e11a0a710c84921b832556a20bbc3e0`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_a58c169261b3461d866bb7db0303c845, request_ca80999b8c9e48a9a9234c35816c4d6f, request_d3704c88ab304356952cbce4f98f78d8`
- Evidence:
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
- Endpoint: `POST /identity/api/v2/vehicle/add_vehicle`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_01d7e45e882346ee96e9f51019fdf7d6`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b799ff51a40a40d08c7d58724dd67eda`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_52bad225a74e493bbef1eaeafb02328e`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_ec26e02b02c548af85108fb6645a2582`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_44bf1caaee454de9b2fdfff5662e65d3`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `SQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_95e72d4f55e64757ab5903a308af72d9`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Possible Input Reflection

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /identity/api/v2/vehicle/{vehicleId}/location`
- Attack category: `SQL_INJECTION`
- Detector: `ReflectionDetector`
- Requests: `request_95e72d4f55e64757ab5903a308af72d9`
- Evidence:
  - `marker_reflection`: Inert YSLFuzz marker appeared in response preview.
    Preview: `yslfuzz_probe`
- Recommendation: Validate and encode reflected input in responses according to the response context.

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/management/users/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_f9e5f37851e04557ba45b6a2cdd0563b`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/mechanic/mechanic_report`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_a38dae561c67471c886990a5b5500799`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/mechanic/mechanic_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0e8c14f50c9a4f599b11f3653c78011b`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/mechanic/mechanic_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_63df6ca0cf294db5a183f9eae8db56e4, request_84dbdc64822c4ab99fe92c18fad7bda6, request_c34097e809d8451b85981c2c1325876a, request_cfdac5ff438d4d058087fcd860c18984`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_3dd981dcc2a142ea94b70020afd84e67`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/mechanic/receive_report`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_66001497f91443a7982376fc1ae143f0, request_a85f5a8136914e7985823a3aff967586`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/mechanic/service_requests`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_eaced9f1bf8446709334d5b1b54c5153`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/mechanic/service_requests`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_c130d6e26d7740408cfc9e1f92dea478`
- Evidence:
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `COMMAND_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_c2f18cc385834a0abab6cf65ab9e5099`
- Evidence:
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_a88320e904c448039389f61a012ad249, request_e9c01fd9b5a04c3690e89a9938a0c191`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_d203422713274cd6a132738e0b2e1c71`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_37ad3071386c4cab9a9af85ca79e7cfc, request_4bdf00cdcae148fd8eff9c027d3161db`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_19eceeb948934e41a3b01f1c74bcc16c`
- Evidence:
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_14b5a34156b240129eec989b236d12c2, request_8a49b5eab4f44ce8bddb3bc760421327, request_b0bd0e4aabec4dff8460318e990e23a0`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_10f501edf9b844459eea2c963a4d9cc4`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/mechanic/signup`
- Attack category: `SQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b6ec606d50c84e4d80933377e2fcd315`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b6aef4dd09514bfc9f9aa657934034e9`
- Evidence:
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_449b7d5ebd704b379e61b6d29c109b53, request_9eb2ad87d77f4924b07816f132d4ca35, request_9f820325bb574e6fbd4336b4c31a6515, request_f746d42b8eb34d4eac6dd657e5da06ad`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
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
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b7e7a9e5a71a4c74a0d31cff9de262a9`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_1d5a6e75ea064eceb8662b22d61dbbd0, request_33299abbb461446587ce38809657548f, request_ec3c3d7159b14f22ad0d24c1b45ed045`
- Evidence:
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
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_8698b4decf3b43b191310ccecec4a308`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/merchant/contact_mechanic`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b83b7ab9b2f948ee8cf201de9922068b`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/apply_coupon`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_7d57d2dd90cc408f87b45784aa23f57d`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_37eaaa423ef84f439467c18a8ea4fd2c`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_05215bf9b351402f91b41b93f4d5d420`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_69802ffac16d4ff18e8107b9dbbc4823`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_cefa7a3ab003418f9a265a2afd3ead21`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_4232c7496c104e18aa87685778875a87, request_460cdfc6acff472d86ec29a542799b86, request_4784a430fd8841088218a44153dccf99, request_88e4e7e2dc564013b1f9ede4617343b1`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0b1d869864c745b59bf5c9d1603d8a08`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_795ecd90657d46a992cc358ee1af2800`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_07a00bd9ceb941da9666b37ebe5a4b0c, request_e9bb0b47ea5249cb83a3093a41f4df02`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_01a6a5eac68e455081e17c4a04aa4c63`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_cc43da6e1da9447db183bf836c16d4c3`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_9c26cd09c71c4e1c9c58739775907931`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/all`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_29132aa1de494dd0ab6e56e6adda62d8, request_c8f85cccb1594cf694be206c79a6c25e`
- Evidence:
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
  - `differential_response`: response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b4ef7367a1bb4b31a26602d9dfecac6c`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed; response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_187c3c1a34d94e858a1a69b7e7651709, request_239e22205fa04e18a26065c6af90ad4e, request_3db494160bba4d93bf17e12502f00d8b, request_e85eb42f8a344d0f8e40be5368749cef`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_f7b34f0a810e449ab7f179705bba5c76`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/orders/return_order`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_d5bbf2bc55484d608f47987eb5992366`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_61b093d6c931412ab120a901ab82aa76`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_dcd16217f29b4c3bbf51b2faaba461c0`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_a8e2cd56cd2b4d81a74a95bb9051e91d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_a080cf945e0042b68cccb08695a0a05d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_35d4c24ffedb47f985980f9246dd4a88`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_60c3fc672fc74f92a579a11ba272f178`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_df76b37d2d3f4146bfb702dc8092f6fe`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed; response time changed significantly
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `BROKEN_ACCESS_CONTROL`
- Detector: `DifferentialResponseDetector`
- Requests: `request_9d43e62240bc451db6a1865b5950c896`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_6d38f87e07fc49b1b13502739910441a`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_e62674edf49844858c0092fe5e769d00`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_8325820adea1454ea61253ff0d7b2ce9`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_5ff4fdc604094ea29509f89ccfdf593f`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_35dac108fcee4d68a1636fb4e5847605`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_42939fe0e4064216b0e334ae6334bd3d, request_99ff76988336416e8a3659ee7e2cc2fa, request_d005e9727aed41d4b70eccf2077c913c`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `PUT /workshop/api/shop/orders/{order_id}`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_27b81551dcd141efbe2ebe3e58a16d29`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/products`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_5fca6c34fc8741339c2dc5aa9e8da873`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/products`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_6532fc52ce7f4cbe852e5cd90725958f`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/products`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_2b0bbe336ec846caa583f42959258fce, request_3abb430ecb534fb38633db9ca9f2bf4d`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/products`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_3f82b3150e5c4133bf1a8fd95e7a91b8`
- Evidence:
  - `differential_response`: body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST /workshop/api/shop/products`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_d15758c3b4f54df8acb60cb8329c6248`
- Evidence:
  - `differential_response`: response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/return_qr_code`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_02eaa50d69ad43959665c75253a23ddd, request_0b829f57d58d4c9ca9939f7578b27b56, request_b5d67fc5bbe0445291f52565fd7a7d3b`
- Evidence:
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
- Endpoint: `GET /workshop/api/shop/return_qr_code`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_949d4a7bcc2b4422af5cb750ae794809`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `GET /workshop/api/shop/return_qr_code`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_b847d1c39aa94aff9963bb4f3dea6537`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_24622e821d854c60a164a224a0d1f3d2, request_71922907de2e4b09b4180ecb135c3406, request_952fd2eb359d48c394b00d887992be91, request_faa175cbb0ca493f891b3b4fcf5c4575`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
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
- Endpoint: `POST [REDACTED]`
- Attack category: `INPUT_VALIDATION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_6ca38d2861de42788286167d754314af, request_7d50cb845ddf43789a82f9d244dea8ce`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_0a99322d1c4b49d6a77e8cf3cb1101cf`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_a7851a0acc1d4bd0b12090af5781681d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_8ace244b19054e88b6da577e2336ec03`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_19dee113d1e84eadac475a4007382f4d`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `NOSQL_INJECTION`
- Detector: `DifferentialResponseDetector`
- Requests: `request_73c9f206ecb44a6da8fc002cf1a9e6a5`
- Evidence:
  - `differential_response`: status code changed; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]

### Differential Response Anomaly

- Severity: `LOW`
- Confidence: `LOW`
- Endpoint: `POST [REDACTED]`
- Attack category: `XSS`
- Detector: `DifferentialResponseDetector`
- Requests: `request_ff66d421b4954b82a7e68674fc4f993e`
- Evidence:
  - `differential_response`: status code changed; response size changed significantly; body hash changed
    Preview: `[REDACTED]`
- Recommendation: [REDACTED]


## Reproducibility

- yslfuzz_version: `0.1.0`
- scan_run_id: `scan_1d5f42b046bf4629bdcee2f9e796f9f5`
- target_id: `target_fc9710098dac455886d2b0b274defe8d`
- api_schema_id: `api_schema_ade2d321848640bb913d2a17ad6c9dee`
- random_seed: `0`
- started_at: `2026-10-02T15:14:27.508085+00:00`
- finished_at: `None`
- generated_at: `2026-10-02T15:15:39.924994+00:00`
- dry_run: `False`
- attack_execution_enabled: `True`
- mutation_execution_enabled: `True`
- destructive_methods_enabled: `False`
