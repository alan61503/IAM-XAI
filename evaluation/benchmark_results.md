# External Benchmark: Known IAM Privilege-Escalation Techniques

Detected = some attack path rated HIGH or CRITICAL. Cells show the worst label over the scenario's paths.

| Method | Attacks detected | Detection rate | False alarms on benign controls |
|---|---:|---:|---:|
| random_forest | 18/26 | 69.2% | 0/6 |
| hybrid | 18/26 | 69.2% | 0/6 |
| rules | 18/26 | 69.2% | 0/6 |

Attack scenarios with at least one attack path discovered: 26/26.

| ID | Technique | Paths | Random Forest | Hybrid | Static rules |
|---|---|---:|---|---|---|
| R01 | iam:CreatePolicyVersion | 1 | CRITICAL | CRITICAL | CRITICAL |
| R02 | iam:SetDefaultPolicyVersion | 1 | CRITICAL | CRITICAL | CRITICAL |
| R03 | iam:PassRole + ec2:RunInstances | 3 | CRITICAL | CRITICAL | HIGH |
| R04 | iam:CreateAccessKey (other user) | 1 | MEDIUM | MEDIUM | LOW |
| R05 | iam:CreateLoginProfile | 1 | MEDIUM | MEDIUM | LOW |
| R06 | iam:UpdateLoginProfile | 1 | MEDIUM | MEDIUM | LOW |
| R07 | iam:AttachUserPolicy | 1 | CRITICAL | CRITICAL | CRITICAL |
| R08 | iam:AttachGroupPolicy | 1 | CRITICAL | CRITICAL | CRITICAL |
| R09 | iam:AttachRolePolicy + sts:AssumeRole | 1 | MEDIUM | MEDIUM | MEDIUM |
| R10 | iam:PutUserPolicy | 1 | CRITICAL | CRITICAL | CRITICAL |
| R11 | iam:PutGroupPolicy | 1 | CRITICAL | CRITICAL | CRITICAL |
| R12 | iam:PutRolePolicy + sts:AssumeRole | 1 | MEDIUM | MEDIUM | MEDIUM |
| R13 | iam:AddUserToGroup | 1 | MEDIUM | MEDIUM | LOW |
| R14 | iam:UpdateAssumeRolePolicy + sts:AssumeRole | 2 | CRITICAL | CRITICAL | CRITICAL |
| R15 | iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction | 3 | CRITICAL | CRITICAL | HIGH |
| R16 | iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping | 3 | CRITICAL | CRITICAL | HIGH |
| R17 | lambda:UpdateFunctionCode (privileged function) | 1 | MEDIUM | MEDIUM | LOW |
| R18 | iam:PassRole + glue:CreateDevEndpoint | 3 | CRITICAL | CRITICAL | HIGH |
| R19 | glue:UpdateDevEndpoint | 1 | MEDIUM | MEDIUM | MEDIUM |
| R20 | iam:PassRole + cloudformation:CreateStack | 3 | CRITICAL | CRITICAL | HIGH |
| R21 | iam:PassRole + datapipeline:CreatePipeline | 3 | CRITICAL | CRITICAL | HIGH |
| C01 | Policy version rollback (cf. CloudGoat iam_privesc_by_rollback) | 1 | CRITICAL | CRITICAL | CRITICAL |
| C02 | Assume manager role, pass admin role to Lambda (cf. CloudGoat lambda_privesc) | 2 | CRITICAL | CRITICAL | HIGH |
| C03 | Pass admin role to an EC2 instance profile (cf. CloudGoat iam_privesc_by_attachment) | 3 | CRITICAL | CRITICAL | HIGH |
| C04 | Cross-account trust without ExternalId to restricted data (confused deputy) | 1 | CRITICAL | CRITICAL | CRITICAL |
| C05 | Role assumable by any principal, reads restricted bucket | 1 | CRITICAL | CRITICAL | HIGH |
| N01 | MFA-gated role reads public assets | 1 | LOW | LOW | LOW |
| N02 | User reads internal inventory table | 1 | MEDIUM | MEDIUM | LOW |
| N03 | Role reads public Lambda configuration | 1 | LOW | LOW | LOW |
| N04 | Role lists public bucket | 1 | LOW | LOW | LOW |
| N05 | Source-IP restricted role queries internal table | 1 | LOW | LOW | LOW |
| N06 | Write access to public bucket blocked by explicit Deny | 1 | LOW | LOW | MEDIUM |
