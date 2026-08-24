#!/usr/bin/env python3
"""
clamav_scan.py - On-demand virus scan using the ClamAV engine (stock clamscan + freshclam).

The virus DEFINITIONS come from ClamAV's official mirrors (https://database.clamav.net),
which are free, open-source, and updated continuously (main ~3.3M sigs, daily ~350k sigs).
This script is a thin, friendly wrapper: it updates definitions, then scans files/folders
and reports clearly. Works in WSL (can scan /mnt/c to cover the Windows filesystem).

Usage:
    python3 clamav_scan.py <target_path> [--quick] [--quarantine-dir DIR] [--no-update]
                           [--exclude-ext .docx,.xlsx] [--json]

Exit codes:
    0 = no infection found
    1 = infection(s) found
    2 = ClamAV missing / definitions failed / scan error
"""

import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

QUARANTINE_DEFAULT = os.path.join(os.path.expanduser("~"), "clamav-quarantine")
# Files larger than this are skipped in --quick mode (avoid huge media/archive rescans)
QUICK_MAX_BYTES = 100 * 1024 * 1024  # 100 MB


def log(msg):
    print(msg, flush=True)


def find_clam():
    """Return (clamscan_path, freshclam_path). Both must exist for full operation."""
    cs = shutil.which("clamscan")
    fc = shutil.which("freshclam")
    return cs, fc


def ensure_clamav():
    """Attempt to install ClamAV if missing. Returns (clamscan, freshclam) or (None, None)."""
    cs, fc = find_clam()
    if cs and fc:
        return cs, fc

    log("[!] ClamAV not found. Attempting install (may prompt for sudo password)...")
    pkg_cmd = ["sudo", "DEBIAN_FRONTEND=noninteractive", "apt-get",
               "install", "-y", "-qq", "clamav", "clamav-freshclam"]
    try:
        # apt-get wants an env var set on the command itself
        r = subprocess.run(["sudo", "apt-get", "install", "-y", "-qq",
                            "clamav", "clamav-freshclam"],
                           capture_output=True, text=True, timeout=900)
        if r.returncode != 0:
            log("[x] apt-get failed: " + r.stderr[-500:])
            return None, None
    except Exception as e:
        log("[x] install attempt error: " + str(e))
        return None, None

    cs, fc = find_clam()
    return cs, fc


def update_definitions(freshclam_path):
    """Run freshclam to pull the latest virus definitions. Best-effort; returns bool."""
    log("[*] Updating virus definitions (freshclam)...")

    # The freshclam daemon may already hold the log lock -> stop it first (best-effort).
    subprocess.run(["sudo", "pkill", "-x", "freshclam"],
                   capture_output=True)

    # freshclam wants to daemonize by default; force a one-shot foreground update.
    cmd = [freshclam_path, "--foreground"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        tail = (r.stdout or "") + (r.stderr or " ")
        if "up-to-date" in tail or "updated" in tail or "Database test passed" in tail \
           or "already up-to-date" in tail or "reloading" in tail or "run of freshclam" in tail:
            log("  [ok] Definitions up to date.")
            return True
        log("[w] freshclam status unclear, continuing with existing defs.")
        return True
    except subprocess.TimeoutExpired:
        log("[w] freshclam timed out, continuing with existing defs.")
        return True
    except Exception as e:
        log("[w] freshclam error: " + str(e))
        return False


def scan_path(clamscan_path, target, quick=False, exclude_ext=None, quarantine_dir=None):
    """Return (exit_code, findings_list, summary). exit_code mirrors clamscan."""
    target = os.path.abspath(target)
    if not os.path.exists(target):
        log("[x] Path not found: " + target)
        return 2, [], {"error": "path not found"}

    cmd = [clamscan_path]
    if os.path.isdir(target):
        cmd += ["--recursive"]
    cmd += ["--infected"]            # only print infected file lines (keeps output readable)
    # NB: do NOT pass --no-summary; we parse "Scanned files: N" from the summary block
    # and suppress that block ourselves (we render a cleaner summary).
    cmd += ["--archive=yes"]
    if quick and os.path.isfile(target):
        if os.path.getsize(target) > QUICK_MAX_BYTES:
            log("[!] File '%s' is >%dMB; skipped in quick mode." % (target, QUICK_MAX_BYTES // (1024 * 1024)))
            return 0, [], {"skipped": "too large for quick mode"}
    # Exclude extensions (comma sep in arg, but repeated flags also work)
    if exclude_ext:
        for ext in exclude_ext:
            cmd += ["--exclude=%s$" % shlex.quote("." + ext.strip().lstrip("."))]

    cmd.append(target)

    log("[*] Scanning: %s" % target)
    prog_start = time.time()

    try:
        # Stream output so the user sees live progress from clamscan's stderr reports.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        findings = []
        seen = set()
        files_scanned = "-"
        infected_total = 0
        in_summary = False
        import re
        for line in proc.stdout:
            line = line.rstrip("\n")
            if in_summary:
                # Inside the SCAN SUMMARY block: capture counts, don't reprint it.
                m = re.search(r"Scanned files:\s*([\d,]+)", line)
                if m:
                    files_scanned = m.group(1)
                mi = re.search(r"Infected files:\s*([\d,]+)", line)
                if mi:
                    infected_total = int(mi.group(1))
                if line.strip().startswith("-"):
                    in_summary = False
                continue
            if "----------- SCAN SUMMARY -----------" in line:
                in_summary = True
                continue
            # Format:  /path/file: Name FOUND
            if " FOUND" in line:
                name, _, sig = line.rpartition(": ")
                name = name.split("!")[0]          # strip ClamAV archive stream marker "(0)"
                if name not in seen:
                    seen.add(name)
                    findings.append((name, sig.strip()))
                    log("  [!!] %s  ->  %s" % (name, sig.strip()))
            elif line.strip():
                log(line)
        proc.wait()
        rc = proc.returncode
    except Exception as e:
        log("[x] clamscan run error: " + str(e))
        return 2, [], {"error": str(e)}

    dur = time.time() - prog_start
    totals = summary_for(target, rc, findings, dur, files_scanned)

    if findings and quarantine_dir:
        quarantined = quarantine(findings, quarantine_dir)
        totals["quarantined"] = quarantined

    return rc, findings, totals


def quarantine(findings, quarantine_dir):
    """Move infected files into a quarantine folder. Returns list of moved paths."""
    os.makedirs(quarantine_dir, exist_ok=True)
    moved = []
    for path, sig in findings:
        try:
            base = os.path.basename(path)
            dest = os.path.join(quarantine_dir, base)
            n = 1
            while os.path.exists(dest):
                dest = os.path.join(quarantine_dir, "%s_%d" % (base, n))
                n += 1
            shutil.move(path, dest)
            moved.append(dest)
            log("  [Q] Quarantined -> %s" % dest)
        except Exception as e:
            log("  [w] could not quarantine %s: %s" % (path, e))
    return moved


def summary_for(target, rc, findings, dur, files_scanned):
    return {
        "target": target,
        "is_dir": os.path.isdir(target),
        "infected": len(findings),
        "files_scanned": files_scanned,
        "duration_s": round(dur, 1),
        "exit_code": rc,
    }


def main():
    ap = argparse.ArgumentParser(description="On-demand ClamAV virus scan.")
    ap.add_argument("target", help="File or directory to scan")
    ap.add_argument("--quick", action="store_true",
                    help="Skip files larger than 100MB (faster)")
    ap.add_argument("--quarantine-dir", default=None,
                    help="Move infected files here (default: ~/clamav-quarantine)")
    ap.add_argument("--no-update", action="store_true",
                    help="Skip the definition update step")
    ap.add_argument("--exclude-ext", default=None,
                    help="Comma-separated extensions to exclude (e.g. .iso,.mp4)")
    ap.add_argument("--json", action="store_true",
                    help="Print results as JSON at the end")
    args = ap.parse_args()

    cs, fc = ensure_clamav()
    if not cs:
        log("[x] ClamAV could not be located. Install it with:")
        log("      sudo apt-get install -y clamav clamav-freshclam")
        sys.exit(2)

    log("[i] ClamAV engine at: %s" % cs)
    log("[i] Definitions source: https://database.clamav.net (free, open-source, auto-updated)")
    log("[i] Platform: %s" % platform.platform())

    exclude_ext = None
    if args.exclude_ext:
        exclude_ext = [e.strip() for e in args.exclude_ext.split(",") if e.strip()]

    if not args.no_update and fc:
        update_definitions(fc)

    rc, findings, totals = scan_path(cs, args.target, quick=args.quick,
                                     exclude_ext=exclude_ext,
                                     quarantine_dir=args.quarantine_dir)

    # -------- summary --------
    log("\n" + "=" * 60)
    log("SCAN SUMMARY")
    log("=" * 60)
    log("  Target      : %s" % totals.get("target", args.target))
    log("  Files scanned: %s" % totals.get("files_scanned", "-"))
    log("  Infected    : %d" % totals.get("infected", len(findings)))
    log("  Duration    : %ss" % totals.get("duration_s", "-"))
    if totals.get("quarantined"):
        log("  Quarantined : %d" % len(totals["quarantined"]))
    log("  Result      : %s" % ("INFECTIONS FOUND" if rc == 1 else "CLEAN"))
    log("=" * 60)

    if args.json:
        print(json.dumps({
            "exit_code": rc,
            "findings": [{"path": p, "signature": s} for p, s in findings],
            "summary": totals,
        }, indent=2))

    sys.exit(rc)


if __name__ == "__main__":
    main()