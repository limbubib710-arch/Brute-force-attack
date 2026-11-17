#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================
  USB PASSWORD CRACKER LAB X ULTIMATE
  Offline USB security auditing & password analysis lab
  Compatible: Termux / Pydroid 3 / Linux / Windows / macOS
  NO API keys. NO network required. 100% offline.
============================================================
"""

import os
import sys
import time
import json
import math
import string
import random
import shutil
import hashlib
import platform
import subprocess
from datetime import datetime

# ------------------------- GLOBAL CONFIG -------------------------
APP_NAME    = "USB PASSWORD CRACKER LAB X ULTIMATE"
APP_VERSION = "1.0.0"
AUTHOR      = "Security Lab"
WORDLIST_FILE  = "wordlist.txt"
SAMPLE_FILE    = "sample_hashes.json"
REPORT_FILE    = "audit_report.txt"
REQ_FILE       = "requirements.txt"
README_FILE    = "README.md"

# ------------------------- ANSI COLOR THEME (RED / BLACK) -------------------------
class Theme:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    DRED   = "\033[31m"
    BLACK  = "\033[30m"
    BG_RED = "\033[41m"
    BG_BLK = "\033[40m"
    WHITE  = "\033[97m"
    YEL    = "\033[93m"
    GRN    = "\033[92m"
    CYN    = "\033[96m"

    @classmethod
    def enable_windows(cls):
        # Enable ANSI on legacy Windows terminals
        if platform.system() == "Windows":
            os.system("")  # triggers VT processing in cmd

T = Theme
T.enable_windows()

def c(text, color=T.RED, bold=False):
    return f"{T.BOLD if bold else ''}{color}{text}{T.RESET}"

# ------------------------- ASCII BANNER -------------------------
BANNER = r"""
 ██████╗ ██╗   ██╗███████╗    ██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
 ██╔══██╗██║   ██║██╔════╝    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ██████╔╝██║   ██║███████╗    ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
 ██╔══██╗██║   ██║╚════██║    ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ██║  ██║╚██████╔╝███████║    ██████╔╝██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        [ LAB X ULTIMATE ]   OFFLINE SECURITY AUDITING SUITE   v{v}
""".format(v=APP_VERSION)

def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

def print_banner():
    clear()
    print(c(BANNER, T.RED, bold=True))
    print(c("  " + "=" * 74, T.DRED))
    print(c("   {n}  |  v{v}  |  {a}  |  OFFLINE MODE".format(
        n=APP_NAME, v=APP_VERSION, a=AUTHOR), T.RED, bold=True))
    print(c("  " + "=" * 74, T.DRED))

def line():
    print(c("  " + "-" * 74, T.DRED))

def status(msg, ok=True):
    tag = c("[+]", T.GRN, bold=True) if ok else c("[!]", T.YEL, bold=True)
    print(f"  {tag} {msg}")

def fail(msg):
    print(f"  {c('[-]', T.RED, bold=True)} {msg}")

# ------------------------- USB DETECTION MODULE -------------------------
class USBScanner:
    """
    Cross-platform USB detection:
      - Termux : `termux-usb -l` (requires termux-api pkg + Termux:API app)
      - Linux  : lsusb or /sys/bus/usb/devices
      - Windows: wmic (fallback: enumeration unavailable -> info msg)
      - macOS  : system_profiler SPUSBDataType
    NEVER sends anything to devices. Read-only enumeration only.
    """

    @staticmethod
    def detect_environment():
        if os.path.isdir("/data/data/com.termux/files/usr"):
            return "termux"
        return platform.system().lower()

    @staticmethod
    def _parse_sysfs():
        """Linux/Android rootless fallback via sysfs (read-only)."""
        base = "/sys/bus/usb/devices"
        devices = []
        try:
            for name in os.listdir(base):
                if ":" not in name:          # skip interfaces like 1-0:1.0
                    path = os.path.join(base, name)
                    try:
                        with open(os.path.join(path, "idVendor")) as f:
                            vid = f.read().strip()
                        with open(os.path.join(path, "idProduct")) as f:
                            pid = f.read().strip()
                        man = prod = ser = "unknown"
                        for attr, key in (("manufacturer", "manufacturer"),
                                          ("product", "product"),
                                          ("serial", "serial")):
                            p = os.path.join(path, attr)
                            if os.path.exists(p):
                                with open(p) as f:
                                    if key == "manufacturer":
                                        man = f.read().strip()
                                    elif key == "product":
                                        prod = f.read().strip()
                                    else:
                                        ser = f.read().strip()
                        devices.append({
                            "path": name, "vendor_id": vid, "product_id": pid,
                            "manufacturer": man, "product": prod, "serial": ser
                        })
                    except (OSError, IOError):
                        continue
        except OSError:
            pass
        return devices

    @classmethod
    def scan(cls):
        env = cls.detect_environment()
        devices = []
        try:
            if env == "termux":
                # termux-usb -l  ->  ["/dev/bus/usb/001/002", ...]
                out = subprocess.run(["termux-usb", "-l"], capture_output=True,
                                     text=True, timeout=10)
                if out.returncode == 0 and out.stdout.strip():
                    paths = json.loads(out.stdout)
                    for p in paths:
                        devices.append({"path": p, "vendor_id": "?", "product_id": "?",
                                        "manufacturer": "grant via `termux-usb -r <path>`",
                                        "product": "Termux USB device", "serial": "-"})
            elif env == "linux":
                if shutil.which("lsusb"):
                    out = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=10)
                    for ln in out.stdout.splitlines():
                        # Bus 001 Device 002: ID 13fe:3600 Kingston ...
                        parts = ln.split()
                        if len(parts) >= 6 and parts[4] == "ID":
                            vid, pid = parts[5].split(":")[:2]
                            desc = " ".join(parts[6:]) or "unknown"
                            devices.append({"path": "bus {} dev {}".format(parts[1], parts[3]),
                                            "vendor_id": vid, "product_id": pid,
                                            "manufacturer": "-", "product": desc, "serial": "-"})
                if not devices:
                    devices = cls._parse_sysfs()
            elif env == "darwin":
                out = subprocess.run(["system_profiler", "SPUSBDataType", "-json"],
                                     capture_output=True, text=True, timeout=15)
                data = json.loads(out.stdout or "{}")
                def walk(node):
                    for item in node.get("_items", []):
                        devices.append({
                            "path": "-", "vendor_id": str(item.get("vendor_id", "?")),
                            "product_id": str(item.get("product_id", "?")),
                            "manufacturer": item.get("manufacturer", "?"),
                            "product": item.get("_name", "?"),
                            "serial": item.get("serial_num", "-")})
                        walk(item)
                for tree in data.values():
                    walk(tree)
            elif env == "windows":
                out = subprocess.run(["wmic", "path", "Win32_USBHub", "get",
                                      "DeviceID,Name,Description"],
                                     capture_output=True, text=True, timeout=15)
                for ln in out.stdout.splitlines()[1:]:
                    ln = ln.strip()
                    if ln:
                        devices.append({"path": "-", "vendor_id": "-", "product_id": "-",
                                        "manufacturer": "-", "product": ln, "serial": "-"})
        except FileNotFoundError:
            fail("USB enumeration tool unavailable (termux-usb / lsusb / system_profiler / wmic).")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            fail(f"USB scan error: {e}")
        return devices, env

    @staticmethod
    def monitor(devices_before, devices_now):
        """Diff two scans -> connection / disconnection events."""
        keys_before = {d.get("path", d.get("product", "")) for d in devices_before}
        keys_now    = {d.get("path", d.get("product", "")) for d in devices_now}
        return (list(keys_now - keys_before),       # connected
                list(keys_before - keys_now))       # disconnected


# ------------------------- WORDLIST GENERATOR -------------------------
class WordlistGenerator:
    """
    Real generator producing 1000+ unique candidates, deduplicated,
    saved one-per-line into wordlist.txt. Fully offline.
    """
    LOWER = string.ascii_lowercase
    UPPER = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%&*?-_+="

    def __init__(self, target=1000):
        self.target = max(target, 1000)
        self.candidates = set()

    # --- generators ---
    def gen_alphanumeric(self, n):
        for _ in range(n):
            ln = random.randint(6, 12)
            pool = self.LOWER + self.UPPER + self.DIGITS
            self.candidates.add("".join(random.choice(pool) for _ in range(ln)))

    def gen_case_variants(self, n):
        words = ["pass", "word", "admin", "usb", "lock", "key", "user", "secure",
                 "hack", "test", "lab", "root", "gate", "code", "safe"]
        for _ in range(n):
            w = random.choice(words)
            ln = random.randint(1, 3)
            suffix = "".join(random.choice(self.DIGITS) for _ in range(ln))
            style = random.randint(0, 3)
            if style == 0:   body = w.upper()
            elif style == 1: body = w.capitalize()
            elif style == 2: body = w
            else:            body = "".join(ch.upper() if i % 2 else ch for i, ch in enumerate(w))
            self.candidates.add(body + suffix)

    def gen_symbolic(self, n):
        bases = ["pass", "admin", "user", "test", "lab", "key", "usb"]
        for _ in range(n):
            b = random.choice(bases)
            pre  = random.choice(self.SYMBOLS) if random.random() < 0.7 else ""
            mid  = random.choice(self.SYMBOLS) if random.random() < 0.5 else ""
            sfx  = "".join(random.choice(self.DIGITS) for _ in range(random.randint(1, 4)))
            self.candidates.add(pre + b + mid + sfx)

    def gen_numeric(self, n):
        for _ in range(n):
            pattern = random.choice(["pin4", "pin6", "year", "phone7", "seq"])
            if pattern == "pin4":    v = f"{random.randint(0, 9999):04d}"
            elif pattern == "pin6":  v = f"{random.randint(0, 999999):06d}"
            elif pattern == "year":  v = str(random.randint(1970, 2030))
            elif pattern == "phone7":v = f"{random.randint(2000000, 9999999)}"
            else:
                start = random.randint(0, 900)
                v = "".join(str(start + i) for i in range(4))[:6]
            self.candidates.add(v)

    def gen_custom(self):
        """Interactive custom generation."""
        try:
            base = input(c("  Enter base word (e.g. name/nickname): ", T.YEL)).strip()
            if not base:
                fail("Base word empty, skipping.")
                return 0
            count = int(input(c("  Amount to generate [200]: ", T.YEL)).strip() or 200)
            max_len = int(input(c("  Max suffix digits [4]: ", T.YEL)).strip() or 4)
            use_sym = input(c("  Use symbols? (y/N): ", T.YEL)).strip().lower() == "y"
            before = len(self.candidates)
            for i in range(count):
                suffix = "".join(random.choice(self.DIGITS)
                                 for _ in range(random.randint(1, max(max_len, 1))))
                sep = random.choice(self.SYMBOLS) if use_sym and random.random() < 0.5 else ""
                style = random.choice([base, base.upper(), base.capitalize(),
                                       base + sep, base.swapcase()])
                self.candidates.add(style + suffix)
            added = len(self.candidates) - before
            status(f"Custom generation done, added {added} unique candidates.")
            return added
        except ValueError:
            fail("Invalid input format.")
            return 0

    def generate(self, interactive=True):
        self.candidates = set()
        per_pool = self.target // 4 + 250   # extra headroom so dedup keeps 1000+
        self.gen_alphanumeric(per_pool)
        self.gen_case_variants(per_pool)
        self.gen_symbolic(per_pool)
        self.gen_numeric(per_pool)
        if interactive:
            if input(c("  Add custom rules? (y/N): ", T.YEL)).strip().lower() == "y":
                self.gen_custom()
        # top-up if dedup dropped below target
        while len(self.candidates) < self.target:
            self.gen_alphanumeric(self.target - len(self.candidates))
        return self.save()

    def save(self, path=WORDLIST_FILE):
        try:
            data = sorted(self.candidates)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(data) + "\n")
            status(f"Saved {len(data)} unique candidates -> {path}")
            return len(data)
        except OSError as e:
            fail(f"Save failed: {e}")
            return 0

    @staticmethod
    def load(path=WORDLIST_FILE):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [ln.rstrip("\n") for ln in f if ln.strip()]
            status(f"Imported {len(words)} candidates <- {path}")
            return words
        except OSError as e:
            fail(f"Import failed: {e}")
            return []

    @staticmethod
    def export(words, path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(words) + "\n")
            status(f"Exported {len(words)} -> {path}")
        except OSError as e:
            fail(f"Export failed: {e}")


# ------------------------- OFFLINE PASSWORD AUDIT -------------------------
class PasswordAuditor:
    COMMON_WEAK = {"123456", "password", "12345678", "qwerty", "abc123",
                   "111111", "123123", "admin", "letmein", "welcome",
                   "password1", "000000", "iloveyou", "dragon", "monkey"}

    @staticmethod
    def entropy(pw):
        if not pw:
            return 0.0
        pool = 0
        if any(ch in string.ascii_lowercase for ch in pw): pool += 26
        if any(ch in string.ascii_uppercase for ch in pw): pool += 26
        if any(ch in string.digits for ch in pw):          pool += 10
        if any(ch in string.punctuation for ch in pw):     pool += 32
        return round(len(pw) * math.log2(pool or 1), 1)

    @classmethod
    def analyze(cls, pw):
        issues = []
        if pw.lower() in cls.COMMON_WEAK:            issues.append("common weak password")
        if len(pw) < 8:                              issues.append("length < 8")
        if not any(ch.isdigit() for ch in pw):       issues.append("missing digits")
        if not any(ch.isupper() for ch in pw):       issues.append("missing uppercase")
        if not any(ch.islower() for ch in pw):       issues.append("missing lowercase")
        if not any(ch in string.punctuation for ch in pw): issues.append("missing symbols")
        if len(set(pw)) <= 3:                        issues.append("low character diversity")
        ent = cls.entropy(pw)
        if ent < 40:   strength = "very weak"
        elif ent < 60: strength = "weak"
        elif ent < 80: strength = "medium"
        elif ent < 100: strength = "strong"
        else:          strength = "very strong"
        return {"password": pw, "entropy_bits": ent, "strength": strength,
                "issues": issues, "weak": bool(issues)}

    @staticmethod
    def sha256(pw): return hashlib.sha256(pw.encode("utf-8")).hexdigest()
    @staticmethod
    def sha512(pw): return hashlib.sha512(pw.encode("utf-8")).hexdigest()

    @staticmethod
    def make_samples(path=SAMPLE_FILE, n=20):
        words = []
        if os.path.exists(WORDLIST_FILE):
            with open(WORDLIST_FILE, encoding="utf-8") as f:
                words = [ln.strip() for ln in f if ln.strip()]
        sample_pool = (["123456", "password", "qwerty", "admin123", "P@ssw0rd",
                        "Tr0ub4dor&3", "correcthorsebatterystaple", "abc123", "letmein"]
                       + random.sample(words, min(n, len(words))))
        samples = [{"password": w,
                    "sha256": PasswordAuditor.sha256(w),
                    "sha512": PasswordAuditor.sha512(w)} for w in sample_pool]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(samples, f, indent=2)
        status(f"Generated {len(samples)} local sample hashes -> {path}")
        return samples

    @staticmethod
    def crack_hashes(algo="sha256", path=SAMPLE_FILE, wordlist=None):
        if wordlist is None:
            wordlist = WordlistGenerator.load()
        if not wordlist:
            fail("Wordlist empty. Generate or import one first.")
            return
        try:
            with open(path, encoding="utf-8") as f:
                targets = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            fail(f"Failed to read sample hashes: {e}, regenerating…")
            targets = PasswordAuditor.make_samples()
        algo_fn = hashlib.sha256 if algo == "sha256" else hashlib.sha512
        field = "sha256" if algo == "sha256" else "sha512"
        target_map = {t[field]: t["password"] for t in targets}
        found, tried = {}, 0
        t0 = time.time()
        for w in wordlist:
            tried += 1
            h = algo_fn(w.encode("utf-8")).hexdigest()
            if h in target_map:
                found[target_map[h]] = h
        dt = time.time() - t0
        print(c(f"\n  [*] {algo.upper()} local dictionary attack demo", T.RED, bold=True))
        print(f"      Candidates tried : {tried}")
        print(f"      Target hashes    : {len(target_map)}")
        print(f"      Matches found    : {len(found)}")
        print(f"      Time elapsed     : {dt:.3f}s  ({tried / max(dt, 1e-9):,.0f} h/s)")
        for pw, h in list(found.items())[:10]:
            print(f"      {c('HIT', T.GRN, bold=True)}  {pw:<28} {h[:24]}…")
        return found

    @staticmethod
    def write_report(results, path=REPORT_FILE):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("USB PASSWORD CRACKER LAB X ULTIMATE - AUDIT REPORT\n")
                f.write("Generated: " + datetime.now().isoformat(timespec="seconds") + "\n")
                f.write("=" * 60 + "\n\n")
                for r in results:
                    f.write(f"Password: {'*' * len(r['password'])} (len={len(r['password'])})\n")
                    f.write(f"  Entropy : {r['entropy_bits']} bits\n")
                    f.write(f"  Strength: {r['strength']}\n")
                    f.write(f"  Weak    : {'YES' if r['weak'] else 'no'}\n")
                    f.write(f"  Issues  : {', '.join(r['issues']) or 'none'}\n\n")
                f.write("NOTE: offline analysis only. No live device was contacted.\n")
            status(f"Audit report written to {path}")
        except OSError as e:
            fail(f"Report write failed: {e}")


# ------------------------- PROJECT FILE BOOTSTRAP -------------------------
def bootstrap_files():
    files = [REQ_FILE, README_FILE]
    created = []
    if not os.path.exists(REQ_FILE):
        with open(REQ_FILE, "w") as f:
            f.write("# No third-party dependencies required.\n"
                    "# Pure Python 3 standard library - fully offline.\n"
                    "# Termux users may optionally install:\n"
                    "#   pkg install termux-api libusb\n")
        created.append(REQ_FILE)
    if not os.path.exists(README_FILE):
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(f"# {APP_NAME}\n\n"
                    "Offline USB security & password auditing lab in pure Python 3.\n"
                    "Works on Termux, Pydroid 3, Linux, macOS, Windows.\n\n"
                    "## Features\n"
                    "- USB device detection / info / connection monitoring (read-only)\n"
                    "- 1000+ unique candidate wordlist generator -> wordlist.txt\n"
                    "- SHA-256 / SHA-512 offline dictionary demo against local sample hashes\n"
                    "- Password strength & complexity analysis, weak-password detection\n"
                    "- audit_report.txt output\n\n"
                    "## Install (Termux)\n"
                    "```bash\npkg update && pkg install python\ncd usb-password-lab\npython usb_password_lab.py\n```\n"
                    "Optional USB enumeration: `pkg install termux-api` + install the Termux:API app.\n\n"
                    "## Install (Pydroid 3)\n"
                    "Open `usb_password_lab.py` and press Run. No pip packages needed.\n\n"
                    "## Ethics\n"
                    "For authorized security education only. Never submits guesses to real devices.\n")
        created.append(README_FILE)
    for fn in created:
        status(f"Generated {fn}")
    if not os.path.exists(SAMPLE_FILE):
        PasswordAuditor.make_samples()
    if not os.path.exists(WORDLIST_FILE):
        status("wordlist.txt does not exist, run menu [1] to generate it.", ok=False)


# ------------------------- MENUS -------------------------
def menu_wordlist():
    print_banner()
    print(c("  >>> WORDLIST GENERATOR <<<", T.RED, bold=True)); line()
    g = WordlistGenerator()
    try:
        n = int(input(c("  Target count [1000]: ", T.YEL)).strip() or 1000)
    except ValueError:
        n = 1000
    g.target = max(n, 1000)
    count = g.generate()
    print(f"\n  {c('STATS', T.RED, bold=True)}: unique entries = {count}  |  file = {WORDLIST_FILE}")

def menu_usb():
    print_banner()
    print(c("  >>> USB SECURITY LAB <<<", T.RED, bold=True)); line()
    devices, env = USBScanner.scan()
    status(f"Environment: {env}")
    if not devices:
        fail("No USB devices detected (Termux needs termux-api installed and OTG device granted).")
        return
    status(f"Detected {len(devices)} USB device(s):")
    for i, d in enumerate(devices, 1):
        print(c(f"  [{i}] {d['path']}", T.RED, bold=True))
        for k in ("vendor_id", "product_id", "manufacturer", "product", "serial"):
            if d.get(k) and d[k] != "-":
                print(f"      {k:<13}: {d[k]}")
    if env == "termux":
        print(c("  [i] Tip: `termux-usb -r <path>` requests read-only access grant from Android.", T.YEL))

def menu_monitor():
    print_banner()
    print(c("  >>> USB CONNECTION MONITOR <<<", T.RED, bold=True)); line()
    try:
        interval = float(input(c("  Polling interval seconds [3]: ").strip() or 3))
    except ValueError:
        interval = 3.0
    status("Monitoring… Ctrl+C to stop. Read-only enumeration only, devices are never touched.")
    prev, _ = USBScanner.scan()
    try:
        while True:
            time.sleep(max(interval, 1))
            cur, _ = USBScanner.scan()
            added, removed = USBScanner.monitor(prev, cur)
            ts = datetime.now().strftime("%H:%M:%S")
            for a in added:
                print(f"  {c('CONNECTED   ', T.GRN, bold=True)} {ts} {a}")
            for r in removed:
                print(f"  {c('DISCONNECTED', T.RED, bold=True)} {ts} {r}")
            prev = cur
    except KeyboardInterrupt:
        status("Monitoring stopped.")

def menu_offline_audit():
    print_banner()
    print(c("  >>> OFFLINE PASSWORD AUDIT <<<", T.RED, bold=True)); line()
    print("   [1] Single password strength analysis")
    print("   [2] SHA-256 local dictionary demo")
    print("   [3] SHA-512 local dictionary demo")
    print("   [4] Batch analyze wordlist.txt (first N entries)")
    print("   [5] Batch analyze and write audit_report.txt")
    print("   [0] Back")
    ch = input(c("\n  Select > ", T.RED, bold=True)).strip()
    if ch == "1":
        pw = input(c("  Enter password > ", T.YEL)).strip()
        r = PasswordAuditor.analyze(pw)
        color = T.GRN if r["strength"] in ("strong", "very strong") else (T.YEL if r["strength"] == "medium" else T.RED)
        print(c(f"\n  Entropy : {r['entropy_bits']} bits", T.RED))
        print(c(f"  Strength: {r['strength']}", color, bold=True))
        print(c(f"  SHA-256: {PasswordAuditor.sha256(pw)}", T.DRED))
        print(c(f"  SHA-512: {PasswordAuditor.sha512(pw)[:48]}…", T.DRED))
        for issue in r["issues"]:
            fail("  " + issue)
        if not r["issues"]:
            status("No obvious weaknesses found.")
    elif ch in ("2", "3"):
        PasswordAuditor.crack_hashes("sha256" if ch == "2" else "sha512")
    elif ch in ("4", "5"):
        words = WordlistGenerator.load()
        if not words:
            return
        try:
            n = int(input(c("  Entries to analyze [50]: ").strip() or 50))
        except ValueError:
            n = 50
        results = [PasswordAuditor.analyze(w) for w in words[:max(n, 1)]]
        weak = [r for r in results if r["weak"]]
        print(c(f"\n  Analyzed {len(results)} | weak passwords: {len(weak)}", T.RED, bold=True))
        for r in weak[:15]:
            print(f"      {c('WEAK', T.RED, bold=True)} {r['password']:<20} "
                  f"ent={r['entropy_bits']:<6} {', '.join(r['issues'][:2])}")
        if ch == "5":
            PasswordAuditor.write_report(results)

def menu_import_export():
    print_banner()
    print(c("  >>> IMPORT / EXPORT WORDLIST <<<", T.RED, bold=True)); line()
    print("   [1] Import wordlist and show stats")
    print("   [2] Export current wordlist.txt to a new file")
    print("   [3] Deduplicate current wordlist.txt")
    ch = input(c("\n  Select > ", T.RED, bold=True)).strip()
    if ch == "1":
        words = WordlistGenerator.load(input(c("  File path [wordlist.txt]: ", T.YEL)).strip() or WORDLIST_FILE)
        if words:
            uniq = len(set(words))
            print(f"      Total lines = {len(words)} | unique = {uniq} | duplicates = {len(words) - uniq}")
    elif ch == "2":
        words = WordlistGenerator.load()
        if words:
            WordlistGenerator.export(words, input(c("  Target file: ", T.YEL)).strip() or "export_wordlist.txt")
    elif ch == "3":
        words = WordlistGenerator.load()
        if words:
            uniq = sorted(set(words))
            WordlistGenerator.export(uniq, WORDLIST_FILE)
            print(f"      After dedup: {len(uniq)} entries (removed {len(words) - len(uniq)})")

def main_menu():
    bootstrap_files()
    while True:
        print_banner()
        print(c("   [1] Generate wordlist (1000+)", T.RED))
        print(c("   [2] USB device detection & info", T.RED))
        print(c("   [3] USB connection monitor", T.RED))
        print(c("   [4] Offline password audit", T.RED))
        print(c("   [5] Wordlist import / export", T.RED))
        print(c("   [6] Regenerate sample hashes", T.RED))
        print(c("   [0] Exit", T.RED))
        line()
        choice = input(c("   Select > ", T.RED, bold=True)).strip()
        try:
            if choice == "1":   menu_wordlist()
            elif choice == "2": menu_usb()
            elif choice == "3": menu_monitor()
            elif choice == "4": menu_offline_audit()
            elif choice == "5": menu_import_export()
            elif choice == "6": PasswordAuditor.make_samples()
            elif choice == "0":
                print(c("\n  Exiting. Stay offline, stay compliant.\n", T.RED, bold=True))
                sys.exit(0)
            else:
                fail("Invalid option.")
        except KeyboardInterrupt:
            status("\nBack to main menu.", ok=False)
        except Exception as e:      # top-level safety net
            fail(f"An error occurred: {e}")
        input(c("\n  Press Enter to continue…", T.YEL))

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(c("\n  Aborted. Goodbye.\n", T.RED, bold=True))
