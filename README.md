# Brute-force-attack
# 🔒 USB PASSWORD LAB X — ULTIMATE

**Offline USB security auditing & password analysis lab** in pure Python 3.
Red/black hacker-terminal interface, animated UI, zero dependencies.

> ✅ Termux · ✅ Pydroid 3 · ✅ Linux · ✅ macOS · ✅ Windows
> 🚫 No API keys · 🚫 No paid APIs · 🚫 No network required — 100% offline

---

## ⚠️ Ethical Use

This tool is for **authorized security education and training only**.

- It **never** submits password guesses to connected devices or accounts.
- All password "cracking" is performed **offline**, against locally generated
  sample hashes (`sample_hashes.json`) that this tool itself creates.
- USB operations are **read-only enumeration** — the app never writes to,
  unlocks, or modifies any connected device.

Unauthorized use against systems you do not own is illegal.

---

## ✨ Features

| # | Feature |
|---|---------|
| 1 | USB device detection & device info (read-only) |
| 2 | USB connection monitoring with connect/disconnect events |
| 3 | Advanced red-and-black terminal interface |
| 4 | Animated colorful ASCII hacker banner (typewriter effect) |
| 5 | Interactive menu system with spinners & progress bars |
| 6 | Password security testing (offline only) |
| 7 | Automatic wordlist generator — **1,000+ unique candidates** |
| 8 | Configurable wordlist size (min 1000) |
| 9 | Random letters, numbers, upper/lowercase & symbol combinations |
| 10 | Duplicate removal (set-based dedup + auto top-up) |
| 11 | One candidate per line → auto export to `wordlist.txt` |
| 12 | Import existing TXT wordlists + live count display |
| 13 | Export wordlists to any TXT file |
| 14 | Password strength checker (entropy + 7 complexity rules) |
| 15 | SHA-256 offline dictionary demo |
| 16 | SHA-512 offline dictionary demo |
| 17 | Weak-password detection & batch analysis |
| 18 | Audit results saved in TXT (`audit_report.txt`) |
| 19 | Complete error handling (per-menu + top-level safety net) |
| 20 | No fake results — every number is computed live |

---

## 📁 Project Structure
---

## 🚀 Installation

### Android — Termux

```bash
pkg update && pkg install python
git clonehttps://github.com/limbubib710-arch/Brute-force-attack.git
cd Brute-force-attack
ls
# copy or paste usb_password_lab.py here
python USB debugging.py
