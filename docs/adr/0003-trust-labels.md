# ADR 0003: trust labels for VMI

Status: accepted for v1.0.

## Context

VMI reads guest state from the hypervisor side. On a single machine the hypervisor and the guard share one trust domain. Calling that `out-of-band` would overstate the guarantee.

## Decision

- `trust: lab` when the hypervisor and the guard run on the same host.
- `trust: out-of-band` only when the VMI host and the guard are separate trust domains.
- Alerts carry the label in `extras.trust`. The Logs and Audit screen shows the raw record, so the label is visible there.

## Consequences

- Tests and demos on one machine always report `lab`.
- The honest label is part of the docs and the raw alert records.
