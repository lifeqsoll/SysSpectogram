# How SysSpectogram compares

Honest positioning — not a “we beat everyone” chart. SysSpectogram targets **one or a few Linux VPS hosts you operate**, with plain-language alerts and optional auto-ban, not a full SOC platform.

| | **SysSpectogram** | **fail2ban** | **CrowdSec** | **Wazuh** | **Falco** |
| --- | --- | --- | --- | --- | --- |
| Primary job | Host guard + perimeter rules + optional ML + Telegram/desktop control | Ban IPs from log regexes | Collaborative IP reputation + bouncers | SIEM / FIM / agents on many nodes | Kubernetes/runtime syscall rules |
| Typical operator | Solo dev / small team on 1–N VPS | Same | Same + community blocklists | Security team, central manager | K8s / cloud-native |
| Install friction | Release wheel + menu / AppImage; signed day-0 script | Package + jail configs | Agent + bouncer + LAPI | Manager + agents + indexing | Helm / daemonset |
| Auto-ban | nft **sets** + never-ban + session protect (helper or root) | iptables/nft via action | Bouncer plugins | Mostly detection; response via integrations | N/A (alerting) |
| Host ML | Optional ONNX on VPS; **experimental** — see [EVAL.md](EVAL.md) | No | No | No (rules + ML in manager optional) | No |
| Desktop / friend UX | Control Center, onboarding, protect unit | CLI / configs | CLI + console | Web UI (heavy) | CLI / SaaS |
| Multi-host fleet | SSH pair + Fleet tab (light) | Per host | Central LAPI | Built for fleet | Per cluster |
| Log / auth parsing | Strict sshd line parser + journal | Jails (you write filters) | Parsers + scenarios | Rules + decoders | Kernel events |
| Supply chain story | minisign + SHA256SUMS on releases | Distro packages | Project binaries | Vendor packages | CNCF project |
| Maturity | **Beta** — self-hosted, opinionated defaults | Very mature | Growing | Mature, heavy | Mature in K8s |

### Footnotes

1. **SysSpectogram** is not a replacement for a SIEM or enterprise EDR. It does not centralize logs from hundreds of agents by default.
2. **fail2ban** remains the right tool if you only need SSH jail + mail — lighter than our stack.
3. **CrowdSec** adds crowd-sourced IP intelligence; we do not ship a global blocklist (privacy / control tradeoff).
4. **Wazuh** wins on compliance reporting and large fleets; cost is complexity and resource use.
5. **Falco** wins on container syscall policy; we focus on VPS SSH + host signals + optional eBPF agent paths documented separately.

See also [FAQ.md](FAQ.md), [THREAT_MODEL.md](THREAT_MODEL.md), [README limitations](../README.md#limitations-and-safety).
