# litellm Supply Chain Attack Detector

On March 24, 2026, malicious versions of litellm (1.82.7 and 1.82.8) were published to PyPI, bypassing the normal GitHub release process. The compromised package exfiltrates credentials (SSH keys, AWS/GCP/Azure creds, .env files, k8s configs, shell history, and more) to attacker infrastructure and installs persistent backdoors.

**Full writeup:** [https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/)

## Quick Start

Requires [ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`).

```bash
curl -sL https://raw.githubusercontent.com/jthack/litellm-vuln-detector/main/detect.sh | bash
```

Or clone and run:

```bash
git clone https://github.com/jthack/litellm-vuln-detector.git
cd litellm-vuln-detector
./detect.sh
```

## What It Checks

| Check | Description |
|-------|-------------|
| **Installed version** | Detects litellm 1.82.7/1.82.8 via pip, uv, conda, AND scans ALL virtualenvs/pyenv/site-packages on disk |
| **Malicious .pth file** | Searches for `litellm_init.pth` in site-packages, uv cache, virtualenvs |
| **Persistence backdoor** | Checks for `~/.config/sysmon/sysmon.py` and systemd user service |
| **Exfiltration domain** | Scans shell history and logs for `models.litellm.cloud` |
| **Network connections** | Checks for active connections to attacker infrastructure |
| **Suspicious processes** | Detects running `sysmon.py` or `litellm_init` processes |
| **Kubernetes** | Looks for malicious `node-setup-*` pods in kube-system (if kubectl available) |
| **Credential exposure** | Lists what credentials exist locally that may have been exfiltrated |

## Exit Codes

- `0` — No indicators of compromise found
- `>0` — Number of IOCs detected

## If You're Compromised

1. `pip uninstall litellm`
2. `rm -rf ~/.config/sysmon/ ~/.config/systemd/user/sysmon.service`
3. `pkill -f sysmon.py`
4. **Rotate ALL credentials** — SSH keys, AWS/GCP/Azure tokens, API keys, database passwords
5. Audit Kubernetes clusters for `node-setup-*` pods in `kube-system`
6. Check cloud access logs for unauthorized activity
