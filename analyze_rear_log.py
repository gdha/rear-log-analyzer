#!/usr/bin/env python3
"""
ReaR (Relax-and-Recover) Log Analyzer
--------------------------------------
Analyzes /var/log/rear/rear-*.log for errors, warnings, and configuration
consistency with /etc/rear/local.conf and /etc/rear/site.conf.

Usage:
    sudo python3 analyze_rear_log.py [--log /path/to/rear.log]
"""

import os
import re
import sys
import glob
import argparse
from datetime import datetime
from collections import defaultdict


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REAR_LOG_DIR = "/var/log/rear"
REAR_CONF_DIR = "/etc/rear"
LOCAL_CONF = "/etc/rear/local.conf"
SITE_CONF = "/etc/rear/site.conf"

# Patterns considered errors or noteworthy warnings
ERROR_PATTERNS = [
    (re.compile(r"\bERROR\b", re.IGNORECASE), "ERROR"),
    (re.compile(r"\bBUG\b", re.IGNORECASE), "BUG"),
    (re.compile(r"\bFATAL\b", re.IGNORECASE), "FATAL"),
    (re.compile(r"\bABORT", re.IGNORECASE), "ABORT"),
]

WARNING_PATTERNS = [
    (re.compile(r"'ldd' shows 'not found'"), "LIBRARY_NOT_FOUND"),
    (re.compile(r"=> not found"), "SHARED_LIB_MISSING"),
    (re.compile(r"\bWARNING\b(?!s?=)(?!-)", re.IGNORECASE), "WARNING"),
    (re.compile(r"does not exist", re.IGNORECASE), "MISSING_PATH"),
    (re.compile(r"Skipping", re.IGNORECASE), "SKIPPED"),
    (re.compile(r"No known bootloader matches"), "BOOTLOADER_DETECT"),
]

# Known-safe library warnings that can be ignored
# See https://github.com/rear/rear/issues/3528 and PRs #3250, #3308
IGNORABLE_LIB_PATTERNS = [
    re.compile(r"libsystemd-core-\d+"),
    re.compile(r"libsystemd-shared-\d+"),
    # Libraries from applications not used by ReaR rescue system
    re.compile(r"libreoffice"),
    re.compile(r"libuno_"),
    re.compile(r"libreglo\.so"),
    re.compile(r"libunoidllo\.so"),
    re.compile(r"libxmlreaderlo\.so"),
]

# Patterns to extract effective configuration from the log
CONFIG_EXTRACTORS = {
    "BACKUP_URL_NFS": re.compile(
        r"Mounting with 'mount\s+.*?\"([^\"]+)\":\"([^\"]+)\""
    ),
    "BACKUP_PROG_COMPRESS": re.compile(r"--use-compress-program=(\S+)"),
    "BACKUP_TYPE": re.compile(r"Making backup \(using backup method (\w+)\)"),
    "WORKFLOW": re.compile(r"Running rear (\w+) \(PID"),
    "KERNEL": re.compile(r"Using autodetected kernel '([^']+)'"),
    "UEFI": re.compile(r"Using UEFI Boot Loader.*USING_UEFI_BOOTLOADER=(\d)"),
    "SECURE_BOOT": re.compile(r"Secure Boot auto-configuration using '([^']+)'"),
    "ISO_OUTPUT": re.compile(r"Wrote ISO image: (\S+) \(([^)]+)\)"),
    "BACKUP_ARCHIVE": re.compile(r"Using backup archive '([^']+)'"),
    "PRE_BACKUP_SCRIPT": re.compile(r"Running PRE_BACKUP_SCRIPT '([^']+)'"),
    "ARCHIVED_SIZE": re.compile(r"Archived (\d+) MiB in (\d+) seconds"),
    # BORG-specific patterns
    "BORG_REPO": re.compile(r"borg create.*?::(\S+)"),
    "BORG_HOST": re.compile(r"borg.*?(\w+@[\w.-]+:\S+|ssh://\S+)"),
    # RSYNC-specific
    "RSYNC_URL": re.compile(r"rsync://([^\s]+)"),
    # USB output
    "USB_DEVICE": re.compile(r"Using '(/dev/\S+)' as USB device"),
    # OUTPUT_URL
    "OUTPUT_URL_SFTP": re.compile(r"sftp://([^\s]+)"),
    "OUTPUT_URL_NFS": re.compile(r"Copying result files.*to (\S+) at nfs location"),
}

# Known ReaR configuration variables we look for in conf files
KNOWN_VARS = [
    "OUTPUT", "OUTPUT_URL", "BACKUP", "BACKUP_URL", "BACKUP_PROG",
    "BACKUP_PROG_COMPRESS_OPTIONS", "BACKUP_PROG_COMPRESS_SUFFIX",
    "BACKUP_OPTIONS", "NETFS_KEEP_OLD_BACKUP_COPY", "EXCLUDE_MOUNTPOINTS",
    "EXCLUDE_BACKUP", "BACKUP_PROG_EXCLUDE", "PRE_BACKUP_SCRIPT",
    "POST_BACKUP_SCRIPT", "SSH_ROOT_PASSWORD", "USE_DHCLIENT",
    "MODULES", "FIRMWARE_FILES", "KERNEL_FILE", "UEFI_BOOTLOADER",
    "SECURE_BOOT_BOOTLOADER", "ISO_DIR", "ISO_PREFIX",
    "BACKUP_PROG_CRYPT_ENABLED", "BACKUP_TYPE",
    # BORG-specific
    "BORGBACKUP_HOST", "BORGBACKUP_REPO", "BORGBACKUP_USERNAME",
    "BORGBACKUP_PORT", "BORGBACKUP_COMPRESSION", "BORGBACKUP_ENC_TYPE",
    "BORGBACKUP_ARCHIVE_PREFIX", "BORGBACKUP_PRUNE_KEEP_DAILY",
    "BORGBACKUP_PRUNE_KEEP_WEEKLY", "BORGBACKUP_PRUNE_KEEP_MONTHLY",
    "BORGBACKUP_PASSPHRASE_FILE", "BORGBACKUP_EXCLUDE_FILE",
    # RSYNC-specific
    "RSYNC_PREFIX", "RSYNC_OPTIONS",
    # BAREOS/BACULA
    "BAREOS_CLIENT", "BAREOS_FILESET", "BACULA_CLIENT", "BACULA_FILESET",
    # USB
    "USB_DEVICE",
    # Network
    "USE_STATIC_NETWORKING",
]

# Recognized backup methods
BACKUP_METHODS = [
    "NETFS", "BORG", "RSYNC", "BAREOS", "BACULA", "TSM", "NBU",
    "DP", "GALAXY", "GALAXY11", "SESAM", "FDRUPSTREAM", "DUPLICITY",
    "RBME", "CDM", "PPDM", "EXTERNAL", "REQUESTRESTORE",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_latest_rear_log(log_dir):
    """Find the most recent rear log file."""
    patterns = [
        os.path.join(log_dir, "rear-*.log"),
    ]
    logs = []
    for pat in patterns:
        logs.extend(glob.glob(pat))
    # Filter out .old files unless nothing else
    primary = [l for l in logs if not l.endswith(".old")]
    if primary:
        return max(primary, key=os.path.getmtime)
    if logs:
        return max(logs, key=os.path.getmtime)
    return None


def discover_rear_configs(conf_dir):
    """Discover all configuration files under /etc/rear/."""
    configs = {}
    if not os.path.isdir(conf_dir):
        return configs
    try:
        for entry in sorted(os.listdir(conf_dir)):
            full_path = os.path.join(conf_dir, entry)
            if os.path.isfile(full_path) and entry.endswith(".conf"):
                configs[entry] = full_path
            elif os.path.isdir(full_path):
                # Note subdirectories (like cert/, mappings/, etc.)
                try:
                    sub_files = os.listdir(full_path)
                    configs[f"{entry}/ ({len(sub_files)} files)"] = full_path
                except PermissionError:
                    configs[f"{entry}/ (permission denied)"] = full_path
    except PermissionError:
        pass
    return configs


def parse_rear_conf(filepath):
    """Parse a ReaR configuration file and return variable assignments."""
    config = {}
    if not os.path.isfile(filepath):
        return None
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Match VAR=value or VAR="value" or VAR='value' or VAR=(array)
                m = re.match(r'^([A-Z_][A-Z0-9_]*)=(.*)$', line)
                if m:
                    var = m.group(1)
                    val = m.group(2).strip().strip("'\"")
                    config[var] = val
    except PermissionError:
        print(f"  [!] Permission denied reading {filepath}")
        return None
    return config


def parse_log_timestamp(line):
    """Extract timestamp from a rear log line."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+", line)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    return None


def extract_log_metadata(lines):
    """Extract high-level metadata from the log."""
    meta = {}
    for line in lines[:20]:
        m = re.search(r"Relax-and-Recover ([\d.]+\S*)", line)
        if m:
            meta["rear_version"] = m.group(1)
        m = re.search(r"Running rear (\w+) \(PID (\d+) date ([^)]+)\)", line)
        if m:
            meta["workflow"] = m.group(1)
            meta["pid"] = m.group(2)
            meta["start_date"] = m.group(3)
    # Get end status
    for line in reversed(lines[-10:]):
        m = re.search(r"Finished rear (\w+) in (\d+) seconds", line)
        if m:
            meta["finish_workflow"] = m.group(1)
            meta["duration_seconds"] = int(m.group(2))
            break
    # Check if ended with error
    for line in reversed(lines[-20:]):
        if re.search(r"\bERROR\b|\bFATAL\b|Aborting", line, re.IGNORECASE):
            meta["ended_with_error"] = True
            break
    else:
        meta["ended_with_error"] = False

    return meta


def find_issues(lines):
    """Find errors and warnings in log lines."""
    errors = []
    warnings = []
    ignorable = []

    for i, line in enumerate(lines, 1):
        for pat, category in ERROR_PATTERNS:
            if pat.search(line):
                # Filter false positives: library names containing "error"
                if category == "ERROR" and re.search(
                    r"lib.*error|gpg-error|libgpg", line, re.IGNORECASE
                ):
                    continue
                errors.append((i, category, line.strip()[:200]))
                break
        else:
            for pat, category in WARNING_PATTERNS:
                if pat.search(line):
                    # Check if this is a known-safe library warning
                    if category in ("LIBRARY_NOT_FOUND", "SHARED_LIB_MISSING"):
                        if any(ip.search(line) for ip in IGNORABLE_LIB_PATTERNS):
                            ignorable.append((i, category, line.strip()[:200]))
                            break
                    warnings.append((i, category, line.strip()[:200]))
                    break

    return errors, warnings, ignorable


def extract_effective_config(lines):
    """Extract the effective configuration used during the run from log lines."""
    effective = {}

    for line in lines:
        for key, pat in CONFIG_EXTRACTORS.items():
            m = pat.search(line)
            if m:
                if key == "BACKUP_URL_NFS":
                    effective["BACKUP_URL"] = f"nfs://{m.group(1)}{m.group(2)}"
                elif key == "WORKFLOW":
                    effective["WORKFLOW"] = m.group(1)
                elif key == "BACKUP_PROG_COMPRESS":
                    effective["BACKUP_PROG_COMPRESS"] = m.group(1)
                elif key == "BACKUP_TYPE":
                    effective["BACKUP"] = m.group(1)
                elif key == "KERNEL":
                    effective["KERNEL_FILE"] = m.group(1)
                elif key == "UEFI":
                    effective["USING_UEFI_BOOTLOADER"] = m.group(1)
                elif key == "SECURE_BOOT":
                    effective["SECURE_BOOT_BOOTLOADER"] = m.group(1)
                elif key == "ISO_OUTPUT":
                    effective["ISO_IMAGE"] = m.group(1)
                    effective["ISO_SIZE"] = m.group(2)
                elif key == "BACKUP_ARCHIVE":
                    effective["BACKUP_ARCHIVE"] = m.group(1)
                elif key == "PRE_BACKUP_SCRIPT":
                    effective["PRE_BACKUP_SCRIPT"] = m.group(1)
                elif key == "ARCHIVED_SIZE":
                    effective["ARCHIVED_SIZE_MiB"] = m.group(1)
                    effective["ARCHIVE_DURATION_SEC"] = m.group(2)
                elif key == "BORG_REPO":
                    effective["BORG_REPO"] = m.group(1)
                elif key == "BORG_HOST":
                    effective["BORG_HOST"] = m.group(1)
                elif key == "RSYNC_URL":
                    effective["RSYNC_URL"] = m.group(1)
                elif key == "USB_DEVICE":
                    effective["USB_DEVICE"] = m.group(1)
                elif key == "OUTPUT_URL_SFTP":
                    effective.setdefault("OUTPUT_URL", f"sftp://{m.group(1)}")
                elif key == "OUTPUT_URL_NFS":
                    effective.setdefault("OUTPUT_DEST", m.group(1))

    # Detect OUTPUT method from archive path or ISO creation
    if "ISO_IMAGE" in effective:
        effective.setdefault("OUTPUT", "ISO")
    if "BACKUP_ARCHIVE" in effective:
        archive = effective["BACKUP_ARCHIVE"]
        if ".tar." in archive:
            effective.setdefault("BACKUP_PROG", "tar")

    # Detect BORG from log content
    for line in lines:
        if re.search(r"Including .*/BORG/", line):
            effective.setdefault("BACKUP", "BORG")
            break
        elif re.search(r"Including .*/BAREOS/", line):
            effective.setdefault("BACKUP", "BAREOS")
            break
        elif re.search(r"Including .*/BACULA/", line):
            effective.setdefault("BACKUP", "BACULA")
            break
        elif re.search(r"Including .*/TSM/", line):
            effective.setdefault("BACKUP", "TSM")
            break
        elif re.search(r"Including .*/RSYNC/", line):
            effective.setdefault("BACKUP", "RSYNC")
            break
        elif re.search(r"Including .*/DUPLICITY/", line):
            effective.setdefault("BACKUP", "DUPLICITY")
            break

    return effective


def extract_stage_timings(lines):
    """Extract stage timings from the log."""
    timings = []
    for line in lines:
        m = re.search(
            r"Finished running '([^']+)' stage in (\d+) seconds", line
        )
        if m:
            timings.append((m.group(1), int(m.group(2))))
    return timings


def compare_config(conf_vars, effective, conf_name):
    """Compare declared configuration against effective runtime behavior."""
    mismatches = []
    notes = []

    if conf_vars is None:
        return mismatches, notes

    def expand_vars(value, variables):
        """Expand bash-style ${VAR} and $VAR references using known variables."""
        import socket
        # Add common environment variables that ReaR uses
        env_vars = {
            "HOSTNAME": socket.gethostname(),
        }
        lookup = {**env_vars, **variables}

        def replacer(m):
            var_name = m.group(1) or m.group(2)
            return lookup.get(var_name, m.group(0))
        # Expand ${VAR} and $VAR (only uppercase var names to avoid false matches)
        # Iterate to resolve nested references (e.g. $VAR referencing another $VAR)
        prev = None
        expanded = value
        for _ in range(5):  # max 5 expansion passes
            if expanded == prev:
                break
            prev = expanded
            expanded = re.sub(
                r'\$\{([A-Z_][A-Z0-9_]*)\}|\$([A-Z_][A-Z0-9_]*)',
                replacer, expanded
            )
        return expanded

    # Check BACKUP_URL consistency
    if "BACKUP_URL" in conf_vars and "BACKUP_URL" in effective:
        declared = expand_vars(conf_vars["BACKUP_URL"], conf_vars).rstrip("/")
        actual = effective["BACKUP_URL"].rstrip("/")
        if declared != actual:
            mismatches.append(
                f"BACKUP_URL: declared='{declared}' vs actual='{actual}'"
            )
        else:
            notes.append(f"BACKUP_URL matches: {declared}")

    # Check OUTPUT method
    if "OUTPUT" in conf_vars and "OUTPUT" in effective:
        if conf_vars["OUTPUT"] != effective["OUTPUT"]:
            mismatches.append(
                f"OUTPUT: declared='{conf_vars['OUTPUT']}' vs actual='{effective['OUTPUT']}'"
            )
        else:
            notes.append(f"OUTPUT method matches: {conf_vars['OUTPUT']}")

    # Check BACKUP method
    if "BACKUP" in conf_vars and "BACKUP" in effective:
        if conf_vars["BACKUP"] != effective["BACKUP"]:
            mismatches.append(
                f"BACKUP: declared='{conf_vars['BACKUP']}' vs actual='{effective['BACKUP']}'"
            )
        else:
            notes.append(f"BACKUP method matches: {conf_vars['BACKUP']}")

    # Check PRE_BACKUP_SCRIPT (handle bash array syntax)
    if "PRE_BACKUP_SCRIPT" in conf_vars and "PRE_BACKUP_SCRIPT" in effective:
        declared = conf_vars["PRE_BACKUP_SCRIPT"]
        actual = effective["PRE_BACKUP_SCRIPT"]
        # Strip bash array wrapper: ( 'cmd' ) -> cmd
        declared_clean = re.sub(r"^\(\s*['\"]?|['\"]?\s*\)$", "", declared).strip("'\" ")
        if declared_clean != actual:
            mismatches.append(
                f"PRE_BACKUP_SCRIPT: declared='{declared_clean}' "
                f"vs actual='{actual}'"
            )
        else:
            notes.append(f"PRE_BACKUP_SCRIPT matches: {actual}")

    # Check BORG-specific settings
    if conf_vars.get("BACKUP") == "BORG":
        if "BORGBACKUP_HOST" in conf_vars:
            notes.append(f"BORG host: {conf_vars['BORGBACKUP_HOST']}")
        if "BORGBACKUP_REPO" in conf_vars:
            notes.append(f"BORG repo: {conf_vars['BORGBACKUP_REPO']}")
        if "BORGBACKUP_COMPRESSION" in conf_vars:
            notes.append(f"BORG compression: {conf_vars['BORGBACKUP_COMPRESSION']}")
        if "BORGBACKUP_ENC_TYPE" in conf_vars:
            notes.append(f"BORG encryption: {conf_vars['BORGBACKUP_ENC_TYPE']}")

    # Check OUTPUT_URL (expand variables before comparing)
    if "OUTPUT_URL" in conf_vars and "OUTPUT_URL" in effective:
        declared = expand_vars(conf_vars["OUTPUT_URL"], conf_vars).rstrip("/")
        actual = effective["OUTPUT_URL"].rstrip("/")
        if declared != actual:
            mismatches.append(
                f"OUTPUT_URL: declared='{declared}' vs actual='{actual}'"
            )
        else:
            notes.append(f"OUTPUT_URL matches: {declared}")

    return mismatches, notes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze ReaR log files for errors and config consistency."
    )
    parser.add_argument(
        "--log", "-l",
        help="Path to a specific rear log file (default: latest in /var/log/rear)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  ReaR Log Analyzer")
    print("=" * 70)
    print()

    # --- Locate log file ---
    if args.log:
        log_path = args.log
    else:
        log_path = find_latest_rear_log(REAR_LOG_DIR)

    if not log_path or not os.path.isfile(log_path):
        print(f"[ERROR] No ReaR log file found in {REAR_LOG_DIR}")
        print("        Run with --log /path/to/rear.log to specify manually.")
        sys.exit(1)

    print(f"  Log file: {log_path}")
    print(f"  Size:     {os.path.getsize(log_path) / 1024:.1f} KB")
    print()

    # --- Read log ---
    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        sys.exit(1)

    # --- Metadata ---
    meta = extract_log_metadata(lines)
    print("-" * 70)
    print("  RUN SUMMARY")
    print("-" * 70)
    print(f"  ReaR version:  {meta.get('rear_version', 'unknown')}")
    print(f"  Workflow:       {meta.get('workflow', 'unknown')}")
    print(f"  Start:         {meta.get('start_date', 'unknown')}")
    print(f"  Duration:      {meta.get('duration_seconds', '?')} seconds")
    print(f"  Completed OK:  {'No' if meta.get('ended_with_error') else 'Yes'}")
    print()

    # --- Stage timings ---
    timings = extract_stage_timings(lines)
    if timings:
        print("-" * 70)
        print("  STAGE TIMINGS")
        print("-" * 70)
        for stage, secs in timings:
            bar = "#" * min(secs, 50)
            print(f"  {stage:<20s} {secs:>4d}s  {bar}")
        print()

    # --- Errors & Warnings ---
    errors, warnings, ignorable = find_issues(lines)

    print("-" * 70)
    print("  ERRORS FOUND")
    print("-" * 70)
    if errors:
        for lineno, category, text in errors:
            print(f"  L{lineno:<5d} [{category}] {text}")
    else:
        print("  None — no hard errors detected.")
    print()

    print("-" * 70)
    print("  WARNINGS / NOTABLE ISSUES")
    print("-" * 70)
    if warnings:
        # Deduplicate similar warnings
        seen = set()
        for lineno, category, text in warnings:
            short = f"[{category}] {text[:120]}"
            if short not in seen:
                seen.add(short)
                print(f"  L{lineno:<5d} {short}")
        if len(warnings) > len(seen):
            print(f"  ... ({len(warnings) - len(seen)} additional duplicate warnings suppressed)")
    else:
        print("  None.")
    print()

    if ignorable:
        print("-" * 70)
        print("  SAFELY IGNORABLE (systemd rpath libs per rear#3528; non-ReaR apps)")
        print("-" * 70)
        seen = set()
        for lineno, category, text in ignorable:
            short = f"[{category}] {text[:120]}"
            if short not in seen:
                seen.add(short)
                print(f"  L{lineno:<5d} {short}")
        print()

    # --- Effective Configuration from log ---
    effective = extract_effective_config(lines)
    print("-" * 70)
    print("  EFFECTIVE CONFIGURATION (from log)")
    print("-" * 70)
    for k, v in sorted(effective.items()):
        print(f"  {k:<30s} = {v}")
    print()

    # --- Configuration files ---
    print("-" * 70)
    print("  CONFIGURATION FILES")
    print("-" * 70)

    # Discover all files under /etc/rear/
    all_configs = discover_rear_configs(REAR_CONF_DIR)
    if all_configs:
        print(f"\n  Files found under {REAR_CONF_DIR}/:")
        for name, path in sorted(all_configs.items()):
            if os.path.isdir(path):
                print(f"    [dir]  {name}")
            else:
                size = os.path.getsize(path) if os.access(path, os.R_OK) else 0
                print(f"    [conf] {name} ({size} bytes)")
    else:
        print(f"\n  {REAR_CONF_DIR}/ not found or not accessible.")

    # Parse individual config files
    local_conf = parse_rear_conf(LOCAL_CONF)
    site_conf = parse_rear_conf(SITE_CONF)

    # Parse any additional .conf files discovered
    extra_confs = {}
    for name, path in all_configs.items():
        if name.endswith(".conf") and path not in (LOCAL_CONF, SITE_CONF):
            parsed = parse_rear_conf(path)
            if parsed is not None:
                extra_confs[name] = parsed

    if local_conf is not None:
        print(f"\n  {LOCAL_CONF} ({len(local_conf)} variables):")
        for k, v in sorted(local_conf.items()):
            print(f"    {k} = {v}")
    else:
        print(f"\n  {LOCAL_CONF}: NOT PRESENT or unreadable")

    if site_conf is not None:
        print(f"\n  {SITE_CONF} ({len(site_conf)} variables):")
        for k, v in sorted(site_conf.items()):
            print(f"    {k} = {v}")
    else:
        print(f"\n  {SITE_CONF}: NOT PRESENT or unreadable")

    for name, conf_vars in sorted(extra_confs.items()):
        path = all_configs[name]
        backup_method = conf_vars.get("BACKUP", "unknown")
        print(f"\n  {path} ({len(conf_vars)} variables, BACKUP={backup_method}):")
        for k, v in sorted(conf_vars.items()):
            print(f"    {k} = {v}")
    print()

    # --- Cross-check config vs log ---
    print("-" * 70)
    print("  CONFIGURATION vs LOG CONSISTENCY CHECK")
    print("-" * 70)

    all_mismatches = []
    all_notes = []

    # Determine which config file was actually used in this run by checking
    # what the log included. ReaR always includes local.conf, but may also
    # include an alternative config via rear -C <name>.
    included_conf = None
    for line in lines:
        m = re.search(r"Including /etc/rear/(\S+\.conf)", line)
        if m:
            included_conf = m.group(1)

    # Identify the "active" config: if an alternative config was included and
    # it matches one of the extra_confs, use that for primary comparison
    active_conf_name = None
    active_conf_vars = None
    if included_conf and included_conf != "local.conf" and included_conf != "site.conf":
        if included_conf in extra_confs:
            active_conf_name = included_conf
            active_conf_vars = extra_confs[included_conf]

    # Always compare local.conf against the log if no alternative was loaded
    if active_conf_vars:
        m, n = compare_config(active_conf_vars, effective, active_conf_name)
        all_mismatches.extend(m)
        all_notes.extend(n)
        # local.conf is still loaded as base, but the alternative overrides BACKUP
        # so skip the BACKUP mismatch from local.conf
        if local_conf:
            m2, n2 = compare_config(local_conf, effective, "local.conf")
            # Filter out BACKUP mismatch if it's overridden by the alternative
            m2 = [x for x in m2 if not x.startswith("BACKUP:")]
            all_mismatches.extend(m2)
            all_notes.extend(n2)
    else:
        if local_conf:
            m, n = compare_config(local_conf, effective, "local.conf")
            all_mismatches.extend(m)
            all_notes.extend(n)

    if site_conf:
        m, n = compare_config(site_conf, effective, "site.conf")
        all_mismatches.extend(m)
        all_notes.extend(n)

    if not local_conf and not site_conf and not extra_confs:
        print("  [!] No configuration files found to compare against.")
        print("      The log shows the backup used defaults or settings from")
        print("      an included /etc/rear/local.conf that may have been")
        print("      removed or is unreadable without root privileges.")
        print()
        print("  Inferred settings from log activity:")
        print(f"    - Backup method: {effective.get('BACKUP', 'unknown')}")
        if "BACKUP_URL" in effective:
            print(f"    - Backup URL:    {effective['BACKUP_URL']}")
        if "OUTPUT" in effective:
            print(f"    - Output method: {effective['OUTPUT']}")
        if "BACKUP_PROG_COMPRESS" in effective:
            print(f"    - Compression:   {effective['BACKUP_PROG_COMPRESS']}")
        if "PRE_BACKUP_SCRIPT" in effective:
            print(f"    - Pre-backup:    {effective['PRE_BACKUP_SCRIPT']}")
    else:
        if all_notes:
            print("\n  Consistent settings:")
            for note in all_notes:
                print(f"    [OK] {note}")
        if all_mismatches:
            print("\n  Mismatches detected:")
            for mm in all_mismatches:
                print(f"    [!!] {mm}")
        if not all_mismatches and all_notes:
            print("\n  All checked settings are consistent between config and log.")

    # Flag if log used a different backup method than what extra configs define
    if extra_confs:
        log_backup = effective.get("BACKUP", "")
        for name, conf_vars in extra_confs.items():
            if name == active_conf_name:
                continue  # Skip the one that was actually used
            conf_backup = conf_vars.get("BACKUP", "")
            if conf_backup and log_backup and conf_backup != log_backup:
                print(f"\n  [INFO] {name} defines BACKUP={conf_backup}, but this")
                print(f"         log run used BACKUP={log_backup}.")
                print(f"         This is an alternative configuration (not used in this run).")
    print()

    # --- Recommendations ---
    print("-" * 70)
    print("  RECOMMENDATIONS")
    print("-" * 70)
    recs = []

    # Hard errors in the log
    if errors:
        recs.append(
            f"{len(errors)} error(s) detected in the log. The backup run did NOT\n"
            "      complete successfully. Review the ERROR lines above for details."
        )

    # Library warnings (only non-ignorable ones)
    lib_warns = [w for w in warnings if w[1] in ("LIBRARY_NOT_FOUND", "SHARED_LIB_MISSING")]
    if lib_warns:
        recs.append(
            "Library 'not found' warnings detected during rescue image verification.\n"
            "      These are NOT the known-safe systemd ones (those are listed separately).\n"
            "      Verify the rescue ISO boots correctly in a test VM."
        )

    # No conf files
    if not local_conf and not site_conf:
        recs.append(
            "No /etc/rear/local.conf or site.conf readable. Ensure configuration\n"
            "      exists and is readable. ReaR relies on these for non-default settings."
        )

    # Large backup time
    if meta.get("duration_seconds", 0) > 600:
        recs.append(
            f"Backup took {meta['duration_seconds']}s ({meta['duration_seconds']//60}min).\n"
            "      Consider incremental/differential backups (BACKUP_TYPE=incremental)\n"
            "      or reviewing EXCLUDE lists if duration is a concern."
        )

    # Missing path warnings
    path_warns = [w for w in warnings if w[1] == "MISSING_PATH"]
    if path_warns:
        recs.append(
            "Some expected FHS directories don't exist (e.g. /usr/X11R6).\n"
            "      This is normal on modern systems and can safely be ignored."
        )

    # Bootloader detection issue
    boot_warns = [w for w in warnings if w[1] == "BOOTLOADER_DETECT"]
    if boot_warns:
        recs.append(
            "No bootloader signature found in MBR of the boot disk. This is expected\n"
            "      on UEFI-only systems (no legacy BIOS boot). GRUB2 was detected via\n"
            "      grub-probe, so recovery should work correctly."
        )

    # Skipped interfaces
    skip_warns = [w for w in warnings if w[1] == "SKIPPED" and "network interface" in w[2].lower()]
    if skip_warns:
        recs.append(
            "Some network interfaces were skipped (docker0, lo). This is expected\n"
            "      behavior — only physical NICs are included in the rescue system."
        )

    if not recs:
        recs.append("No significant issues found. The backup completed successfully.")

    # Alternative backup configs note
    if extra_confs:
        # Only mention configs that were NOT loaded in this run
        unused_extras = {
            n: c for n, c in extra_confs.items()
            if n != active_conf_name and c.get("BACKUP")
        }
        if unused_extras:
            recs.append(
                f"Alternative backup configuration(s) available but not used in this run: "
                + ", ".join(f"{n} (BACKUP={unused_extras[n].get('BACKUP', '?')})"
                            for n in sorted(unused_extras.keys()))
                + ".\n      To use them, run: rear -C <config_name_without_.conf> mkbackup"
            )

    for i, rec in enumerate(recs, 1):
        print(f"  {i}. {rec}")
    print()

    print("=" * 70)
    print("  Analysis complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
