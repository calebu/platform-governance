# Platform Governance Policy

This package enforces a baseline platform governance policy for Kubernetes workloads. It is intended to be used as policy-as-code for admission control and CI/CD validation.

## What this policy enforces

- Approved container registries only.
- CPU and memory requests and limits on every container.
- Non-root execution and no privileged containers.
- Team and workload namespace controls.
- Required metadata labels.
- Ingress requirements for approved classes, TLS, and trusted hostnames.

## Policy layout

- `main.rego` exposes the top-level `allow` decision.
- `common.rego` centralizes shared constants and helper functions.
- `registry.rego` validates image sources.
- `resources.rego` validates resource requests and limits.
- `security.rego` validates runtime security settings.
- `metadata.rego` validates required labels.
- `namespace.rego` validates namespace access by team and application.
- `ingress.rego` validates ingress configuration rules.

## Decision model

The package evaluates all policy violations and surfaces them as `deny` entries. A workload is allowed only when no deny rules match.

```rego
package platform.governance

default allow := true

allow if {
    count(deny) == 0
}
```

## Recommended usage

Use this package in OPA or Gatekeeper as a standard admission policy. In a real environment, you would typically add namespace-specific exceptions, override rules, or a stronger `deny` message contract for your platform team.

## Notes

This is intentionally simple and explicit so the rules remain easy to review, test, and maintain. The policy is designed to reflect common enterprise platform guardrails without adding unnecessary abstraction.

## Validation

The package can be validated with OPA directly:

```bash
opa eval -d . 'data.platform.governance'
```
