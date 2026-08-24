---
name: free-shield
category: devops
tags: [antivirus, clamav, malware, virus-definitions, security, scan, clamscan, freshclam]
description: Free, on-demand virus scan for your PC using the ClamAV engine and its free definitions.
---

# FreeShield - On-Demand Virus Scan (ClamAV)

On-demand malware scanning using the **stock ClamAV engine** (`clamscan` + `freshclam`).
The virus *definitions* are the key question - ClamAV's official mirrors at
`https://database.clamav.net` are free, open-source, and continuously updated
(main ~3.3M sigs, daily ~355k sigs, plus bytecode). GitHub YARA rule repos
(Neo23x0/signature-base) are a secondary/pattern-based source, not needed for a ClamAV scan.

## When to Use

- Scan files/folders for viruses/malware
- Answer where/how to "get virus definitions" (answer: ClamAV mirrors via `freshclam`)
- Build a reusable antivirus scanner script
- Scan the Windows filesystem from WSL via `/mnt/c/...` targets

## The Definition Source (the core answer)

```
https://database.clamav.net/main.cvd     (~85-90 MB, 3.28M sigs)
https://database.clamav.net/daily.cvd    (~23 MB, 355k sigs)
https://database.clamav.net/bytecode.cvd (~276 KB, 80 sigs)
```

`freshclam` pulls these automatically. Test connectivity with GET (HEAD returns 403):

```
curl -sL -A "ClamAV/1.5.3" -o /tmp/main.cvd -w "HTTP %{http_code} | size %{size_download}\n" https://database.clamav.net/main.cvd
```

## Install (WSL / Debian / Ubuntu)

```
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clamav clamav-freshclam
clamscan --version   # expect ClamAV 1.5.x
```

## Update Definitions (freshclam)

The freshclam **daemon** may hold `/var/log/clamav/freshclam.log` and block a manual run.
Stop it first, then run a one-shot foreground update:

```
sudo pkill -x freshclam 2>/dev/null; sleep 1
sudo freshclam --foreground
```

Look for `up-to-date` / `updated` / `Database test passed`. A trailing
`NotifyClamd: Can't find or parse configuration file /etc/clamav/clamd.conf` is harmless
(no clamd daemon running). Definitions land in `/var/lib/clamav/*.cvd`.

## Quick Verify (EICAR test file)

EICAR is the universal benign malware-detection test string. clamscan must flag it:

```
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan --infected /tmp/eicar.com
# expect: /tmp/eicar.com: Eicar-Test-Signature FOUND
```

## The Wrapper Script

`scripts/free_shield_scan.py` is a thin, friendly wrapper around clamscan:

```
python3 free_shield_scan.py <target_file_or_dir> [options]
```

Options:
- `--quick` - skip files >100MB (faster on big media/archives)
- `--quarantine-dir DIR` - move infected files into a quarantine folder (default `~/clamav-quarantine`)
- `--no-update` - skip the freshclam step
- `--exclude-ext .iso,.mp4` - comma-separated extensions to skip
- `--json` - print a JSON blob with findings + summary

Exit codes: `0` = clean, `1` = infection(s) found, `2` = ClamAV missing / scan error.

It auto-runs `ensure_clamav()` (attempts apt install if missing), updates definitions unless
`--no-update`, then streams clamscan live output, dedupes the same file (ClamAV prints
`file!(0)` archive-stream markers), renders a clean summary, and optionally quarantines.

## Windows coverage

Running from WSL, scan the Windows filesystem directly by pointing at `/mnt/c/...`:

```
python3 free_shield_scan.py /mnt/c/Users/<user>/Downloads --no-update
```

ClamAV also ships native Windows builds; the wrapper is engine-agnostic if you swap the
`clamscan` path.

## Pitfalls

1. **freshclam log lock** - the daemon holds `freshclam.log`. `pkill -x freshclam` before a
   manual run (do NOT `pkill -f freshclam`, it matches its own shell and kills the script).
2. **HEAD returns 403** on database.clamav.net - always use GET to test connectivity.
3. **`--no-summary` hides the file count** - the wrapper omits it and parses
   `Scanned files: N` from the summary block instead.
4. **Double-counting** - ClamAV prints `file!(0)` archive markers; strip `!...` and dedupe.
5. **WSL scan of `/mnt/c` is slow** - `--quick` and `--exclude-ext` help for routine scans.
6. **First freshclam run** needs internet; offline it still scans with whatever `.cvd` files exist.
