# archive/duplicates/

Removed from the active tree to avoid twin .py/.sh confusion.
Use the kept scripts instead:

| Removed | Use instead |
|---------|-------------|
| `attack_deauth.py` / `synFlood_attack.py` / `arpspoof.py` | `host/attacks/*.sh` |
| `netconfig.py` | `host/attacks/netconfig.sh` (sourced by attack scripts) |
| `session_kali.sh` | run `prepare_wifi.sh` + `attack_*.sh` directly |

Do not commit secrets from `archive/` (see parent README).
