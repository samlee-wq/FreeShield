# ClamAV PC Scanner

A free, open-source, on-demand virus scanner for your PC. It uses the **ClamAV** engine
and its **officially maintained virus definitions** (3.6+ million signatures, updated
continuously) to scan any file or folder for malware. Works on Windows (via WSL), Linux,
and macOS. No subscription. No cloud upload. Your files never leave your machine.

> Quick start: install ClamAV, run `clamav_scan.py <path>`, it auto-updates definitions
> and reports CLEAN or INFECTIONS FOUND with a clear exit code.

---

## Why ClamAV?

The hardest part of any antivirus is the **virus definitions** - the ever-growing database
of malware signatures. Commercial vendors keep theirs proprietary. ClamAV publishes its
full database for free under an open license, and it is updated several times a day.

- Definitions live at `https://database.clamav.net` (free, open, continuously updated)
- 3.28M+ signatures in `main`, 355k+ in `daily`, plus `bytecode`
- Detects the same families that commercial engines detect
- Truly free and open source (ClamAV is GPL; signatures are open)

This project is a small, friendly wrapper around the stock `clamscan` engine. It does not
re-invent detection - it makes the official signatures easy to use.

---

## The Virus Definition Source (the core answer)

ClamAV's official signature mirrors:

| Database    | Size     | Signatures | Update cadence |
|-------------|----------|------------|----------------|
| `main.cvd`  | ~85-90MB | 3,287,027  | infrequent, large |
| `daily.cvd` | ~23MB    | 355,622    | several times a day |
| `bytecode.cvd` | ~276KB | 80     | as needed |

`freshclam` pulls these automatically. To test the source is reachable (note: use **GET**,
not HEAD - HEAD returns 403):

```bash
curl -sL -A "ClamAV/1.5.3" -o /tmp/main.cvd \
  -w "HTTP %{http_code} | size %{size_download}\n" \
  https://database.clamav.net/main.cvd
```

Expected: `HTTP 200 | size 89072577`.

---

## Step-by-Step Setup

### 1. Install ClamAV

**Ubuntu / Debian (and WSL):**
```bash
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clamav clamav-freshclam
clamscan --version   # expect ClamAV 1.5.x
```

**macOS (Homebrew):**
```bash
brew install clamav
```

**Windows:** use the WSL route above, or install the native ClamAV Windows build.
When running from WSL, the script can scan the Windows filesystem directly:

```bash
python3 clamav_scan.py /mnt/c/Users/<user>/Downloads
```

### 2. Update definitions

The `freshclam` daemon may hold a lock and block a manual run. Stop it first, then run a
one-shot foreground update:

```bash
sudo pkill -x freshclam 2>/dev/null; sleep 1
sudo freshclam --foreground
```

You should see `up-to-date` or `updated` plus `Database test passed`. Definitions land in
`/var/lib/clamav/*.cvd`.

> Note: a trailing `NotifyClamd: Can't find or parse configuration file /etc/clamav/clamd.conf`
> is harmless - it just means no `clamd` daemon is running, which we don't need.

### 3. Run a scan

```bash
# scan a single file
python3 clamav_scan.py ~/Downloads/suspect.exe

# scan a folder recursively
python3 clamav_scan.py ~/Downloads

# quick mode - skip files >100MB
python3 clamav_scan.py /mnt/c/Users/<user> --quick

# move infected files into a quarantine folder instead of leaving them
python3 clamav_scan.py /mnt/c/Users/<user> --quarantine-dir ~/clamav-quarantine

# skip updating definitions (use existing ones)
python3 clamav_scan.py /mnt/c/Users/<user>/Downloads --no-update

# machine-readable JSON output
python3 clamav_scan.py /mnt/c/Users/<user>/Downloads --json
```

### 4. Verify it works (EICAR test file)

EICAR is the internationally recognized benign malware-detection test string. If your
scanner flags it, detection is working:

```bash
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan --infected /tmp/eicar.com
# expect: /tmp/eicar.com: Eicar-Test-Signature FOUND
```

---

## Command-line options

| Flag | Description |
|------|-------------|
| `target` | File or directory to scan (required) |
| `--quick` | Skip files larger than 100MB (faster on big media) |
| `--quarantine-dir DIR` | Move infected files to a quarantine folder (default `~/clamav-quarantine`) |
| `--no-update` | Skip the definition update step |
| `--exclude-ext .iso,.mp4` | Comma-separated extensions to skip |
| `--json` | Print findings + summary as JSON |

**Exit codes:** `0` = clean, `1` = infection(s) found, `2` = ClamAV missing / scan error.

---

## How it works

The wrapper (`scripts/clamav_scan.py`):

1. Ensures ClamAV is installed (attempts `apt install` if missing)
2. Updates definitions via `freshclam` (unless `--no-update`)
3. Streams `clamscan` live output, flagging each `FOUND` line
4. Dedupes the same file (ClamAV prints `file!(0)` archive-stream markers)
5. Parses `Scanned files: N` from ClamAV's summary block
6. Renders a clean summary and returns the right exit code
7. Optionally quarantines infected files

---

## FAQ

**Q: Is this really a full antivirus?**
It is a real, signature-based on-demand scanner using ClamAV's official engine and
definitions. It is NOT a resident shield that scans every file the moment it is written.
It's a "scan this now" tool - great for cleaning a suspect download, a USB drive, a folder
you were sent, or a machine you don't trust. For always-on protection, pair it with the
built-in OS protection (Windows Security, etc.) and use this for on-demand deep scans.

**Q: Where do the virus definitions come from? Are they free?**
ClamAV's official mirrors at `https://database.clamav.net`. Yes, 100% free and open. They
are updated several times daily.

**Q: Can I scan my Windows drive?**
Yes. Run from WSL and point at `/mnt/c/...`. The script has no opinion about the
filesystem, it just scans whatever path you give it.

**Q: It found a virus. What do I do?**
Run with `--quarantine-dir` to move the file aside safely, then delete or restore it after
inspecting. Do not open the file.

**Q: It's slow scanning /mnt/c. Why?**
The WSL `/mnt/c` mount is a network-ish filesystem - thousands of small files add up. Use
`--quick` and `--exclude-ext` for routine scans, or scan specific folders rather than the
whole drive.

**Q: `freshclam` says it can't lock the log file.**
The `freshclam` daemon is running and holds the lock. Stop it first: `sudo pkill -x freshclam`.

**Q: Does anything upload my files?**
No. Everything runs locally. `freshclam` only downloads signature databases; `clamscan`
scans locally and never sends your files anywhere.

**Q: Do I need an account or license?**
No. ClamAV and its signatures are free and open source. There is nothing to register.

**Q: How current are the definitions?**
`daily.cvd` updates several times a day; `main.cvd` less frequently. The wrapper updates at
the start of every scan (unless you pass `--no-update`).

---

## License

The wrapper script is MIT licensed (see `LICENSE`). ClamAV is GPLv2 and its signature
database is open to all users. See the [ClamAV project](https://www.clamav.net/) for details.

## Credits

- [ClamAV](https://www.clamav.net/) - the antivirus engine and its signature database
- The wrapper streamlines the stock `clamscan`/`freshclam` workflow and handles the common
  operational gotchas (freshclam log lock, GET-vs-HEAD on the mirror, archive-stream dedup).
