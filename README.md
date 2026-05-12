# aws-supply-chain-security

[![Terraform](https://img.shields.io/badge/Terraform-1.7%2B-7B42BC?logo=terraform)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-Inspector%20v2-FF9900?logo=amazonaws)](https://aws.amazon.com/inspector/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

End-to-end **container supply-chain security** on AWS — image scanning, SBOM
generation, image signing, and admission-time enforcement on EKS.

## What this repository delivers

| Stage              | Mechanism                                                 |
|--------------------|-----------------------------------------------------------|
| Storage            | Amazon ECR private registries with immutable tags         |
| Scanning           | Inspector v2 enhanced scanning + Trivy / Grype locally    |
| SBOM               | Syft, generated during CodeBuild and attached to image    |
| Signing            | Cosign + AWS Signer profile                               |
| Policy enforcement | Gatekeeper constraints on EKS (signed + low-CVE only)     |
| Aggregation        | Security Hub + EventBridge -> SNS / Slack                 |

## Repository layout

```
terraform/      Terraform stacks: ECR, Inspector, Signer, Security Hub, ...
pipelines/      CodeBuild buildspecs and pipeline manifests
policies/       Gatekeeper Rego policies and constraints
scripts/        Local helper scripts (scan-local, generate-sbom, ...)
docs/           Architecture notes, SLSA mapping, runbooks
.github/        CI workflows
```

## Quick start

```bash
make init
make plan
make apply
```

See `docs/` for architecture and runbooks once published.

## Status

Active development. See the `60-day-aws-plan.md` (parent repo `Git automation`)
for the day-by-day delivery schedule (Days 49-54).
