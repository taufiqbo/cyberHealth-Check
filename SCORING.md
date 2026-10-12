# CyberHealth Score v1.0

The method behind the number, as `runner/scoring.py` computes it. If you change one, change the other and bump the version.

## 1. Result of each control

| Result | Points | In the score? |
|---|---|---|
| Pass | 1.0 | yes |
| Partial | 0.5 | yes |
| Fail | 0.0 | yes |
| Needs review, Inconclusive | – | no, and sign-off is blocked until a reviewer decides |
| Information, Not tested | – | no, but they count against coverage |
| Not applicable | – | no, and not counted in coverage |

## 2. Weight of each control (by severity)

| Severity | Weight |
|---|---|
| Critical | 10 |
| High | 6 |
| Medium | 3 |
| Low | 1 |

The control list and severities are in `runner/controls.py`.

## 3. Module scores

Module score = 100 × Σ(weight × points) ÷ Σ(weight), over the module's scored controls.
A module with no scored control has no score and drops out of step 4.

## 4. Overall score

Weighted average of the module scores:

| Module | Weight |
|---|---|
| Discovery | 10 |
| TLS | 15 |
| Email | 15 |
| Web | 10 |
| Brand | 5 |
| Services | 20 |
| Lifecycle | 10 |
| Vulnerabilities | 15 |

Modules without a score are left out and the remaining weights are used as they are.

## 5. Caps

Applied after step 4, lowest cap wins:

- Any known exploited vulnerability (VUL-03 Fail): score at most **49**.
- Any critical-severity control failed: score at most **69**.

## 6. Grade

| Score | Grade |
|---|---|
| 90–100 | A, Strong |
| 80–89 | B, Good |
| 70–79 | C, Fair |
| 60–69 | D, Weak |
| 0–59 | F, Poor |

## 7. Coverage

Coverage = weight of scored controls ÷ weight of all applicable controls. Below 60% the score is labelled **provisional**
(typical when Services and Vulnerabilities were not approved).

The score is frozen when a reviewer signs off; the report always shows the frozen value.
