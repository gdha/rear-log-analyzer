# rear-log-analyzer

**Relax-and-Recover (ReaR) Log Analyzer** — a Python 3 script that parses ReaR log files, detects errors and warnings, extracts the effective runtime configuration, cross-checks it against `/etc/rear/*.conf`, and prints a human-readable report with actionable recommendations.

---

## Features

- **Error & warning detection** — scans the log for `ERROR`, `BUG`, `FATAL`, `ABORT`, missing paths, missing shared libraries, skipped items, and bootloader issues.
- **Known-safe filtering** — automatically suppresses false positives such as `libsystemd-core-*` / `libsystemd-shared-*` rpath warnings (upstream ReaR issues [#3528](https://github.com/rear/rear/issues/3528), [#3250](https://github.com/rear/rear/pull/3250), [#3308](https://github.com/rear/rear/pull/3308)) and `parted`'s "unrecognised disk label" messages on LVM PV / raw disks.
- **Effective configuration extraction** — detects `BACKUP_URL`, `OUTPUT`, `BACKUP`, compression, kernel, UEFI/Secure Boot, ISO path, archive size, and backup-method-specific details (BORG, RSYNC, SFTP, NFS, USB) directly from log activity.
- **Configuration file parsing** — reads `/etc/rear/local.conf`, `/etc/rear/site.conf`, and any additional `*.conf` files under `/etc/rear/`, including bash variable expansion.
- **Config-vs-log consistency check** — highlights mismatches between declared configuration and what actually ran (e.g. `BACKUP_URL` pointing to a different NFS share than the one actually mounted).
- **Stage timings** — shows a simple ASCII bar chart of how long each ReaR stage (`prep`, `layout/save`, `rescue`, `backup`, …) took.
- **Recommendations** — summarises actionable next steps based on everything found.
- **Multiple backup methods** — supports NETFS, BORG, RSYNC, BAREOS, BACULA, TSM, NBU, DP, GALAXY, GALAXY11, SESAM, FDRUPSTREAM, DUPLICITY, RBME, CDM, PPDM, EXTERNAL, REQUESTRESTORE.
- **Alternative config support** — detects when `rear -C <name>` was used and compares the correct config file against the log.

---

## Requirements

- Python 3.6 or newer (no third-party packages needed — standard library only)
- Read access to the ReaR log directory (`/var/log/rear/`) and configuration directory (`/etc/rear/`)

> **Note:** ReaR log files are typically only readable by root. Run the script with `sudo` unless you have changed the file permissions.

---

## Installation

No installation required. Clone or download the script and run it directly:

```bash
git clone https://github.com/gdha/rear-log-analyzer.git
cd rear-log-analyzer
```

---

## Usage

```bash
# Analyze the most recent ReaR log (requires root access to /var/log/rear/)
sudo python3 analyze_rear_log.py

# Analyze a specific log file
sudo python3 analyze_rear_log.py --log /var/log/rear/rear-myhost.log

# Short form
sudo python3 analyze_rear_log.py -l /path/to/rear-custom.log
```

### Options

| Option | Description |
|---|---|
| `--log FILE`, `-l FILE` | Path to a specific ReaR log file. When omitted the newest `rear-*.log` in `/var/log/rear/` is used. |
| `--help`, `-h` | Show built-in help and exit. |

---

## Output sections

```
======================================================================
  ReaR Log Analyzer
======================================================================

  Log file: /var/log/rear/rear-myhost.log
  Size:     3842.7 KB

----------------------------------------------------------------------
  RUN SUMMARY
----------------------------------------------------------------------
  ReaR version:  2.7
  Workflow:       mkbackup
  Start:         2025-01-15 02:00:01
  Duration:      487 seconds
  Completed OK:  Yes

----------------------------------------------------------------------
  STAGE TIMINGS
----------------------------------------------------------------------
  prep                   12s  ############
  layout/save             8s  ########
  rescue                142s  ##################################################
  backup                310s  ##################################################
  ...

----------------------------------------------------------------------
  ERRORS FOUND
----------------------------------------------------------------------
  None — no hard errors detected.

----------------------------------------------------------------------
  WARNINGS / NOTABLE ISSUES
----------------------------------------------------------------------
  L1042  [WARNING] Using ... (deduplicated)

----------------------------------------------------------------------
  SAFELY IGNORABLE
----------------------------------------------------------------------
  L987   [SHARED_LIB_MISSING] libsystemd-shared-252.so => not found

----------------------------------------------------------------------
  EFFECTIVE CONFIGURATION (from log)
----------------------------------------------------------------------
  BACKUP                         = NETFS
  BACKUP_URL                     = nfs://nas.example.com/export/rear
  ISO_IMAGE                      = /var/lib/rear/output/rear-myhost.iso
  ...

----------------------------------------------------------------------
  CONFIGURATION FILES
----------------------------------------------------------------------
  [conf] local.conf (5 variables)
  [conf] site.conf (3 variables)

----------------------------------------------------------------------
  CONFIGURATION vs LOG CONSISTENCY CHECK
----------------------------------------------------------------------
  Consistent settings:
    [OK] BACKUP_URL matches: nfs://nas.example.com/export/rear

----------------------------------------------------------------------
  RECOMMENDATIONS
----------------------------------------------------------------------
  1. No significant issues found. The backup completed successfully.
======================================================================
```

---

## Configuration variables recognized

The analyzer recognizes the following ReaR configuration variables when parsing `*.conf` files and cross-checking against the log:

`OUTPUT`, `OUTPUT_URL`, `BACKUP`, `BACKUP_URL`, `BACKUP_PROG`, `BACKUP_PROG_COMPRESS_OPTIONS`, `BACKUP_PROG_COMPRESS_SUFFIX`, `BACKUP_OPTIONS`, `NETFS_KEEP_OLD_BACKUP_COPY`, `EXCLUDE_MOUNTPOINTS`, `EXCLUDE_BACKUP`, `BACKUP_PROG_EXCLUDE`, `PRE_BACKUP_SCRIPT`, `POST_BACKUP_SCRIPT`, `SSH_ROOT_PASSWORD`, `USE_DHCLIENT`, `MODULES`, `FIRMWARE_FILES`, `KERNEL_FILE`, `UEFI_BOOTLOADER`, `SECURE_BOOT_BOOTLOADER`, `ISO_DIR`, `ISO_PREFIX`, `BACKUP_PROG_CRYPT_ENABLED`, `BACKUP_TYPE`, `USE_STATIC_NETWORKING`, BORG-specific variables (`BORGBACKUP_HOST`, `BORGBACKUP_REPO`, `BORGBACKUP_USERNAME`, `BORGBACKUP_PORT`, `BORGBACKUP_COMPRESSION`, `BORGBACKUP_ENC_TYPE`, `BORGBACKUP_ARCHIVE_PREFIX`, `BORGBACKUP_PRUNE_KEEP_DAILY`, `BORGBACKUP_PRUNE_KEEP_WEEKLY`, `BORGBACKUP_PRUNE_KEEP_MONTHLY`, `BORGBACKUP_PASSPHRASE_FILE`, `BORGBACKUP_EXCLUDE_FILE`), RSYNC-specific (`RSYNC_PREFIX`, `RSYNC_OPTIONS`), BAREOS/BACULA (`BAREOS_CLIENT`, `BAREOS_FILESET`, `BACULA_CLIENT`, `BACULA_FILESET`), and USB (`USB_DEVICE`).

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file included in this repository.
