#!/usr/bin/env python3
"""
OrangeBox Wazuh Active Response: quarantine a file confirmed by rule 99901.

Safety guarantees:
- Only handles rule 99901.
- Requires syscheck.path and syscheck.sha256.
- Refuses symlinks.
- Re-hashes the original before touching it.
- Copies to /var/ossec/quarantine/<sha256>/.
- Verifies the quarantine copy has the expected SHA-256.
- Stores metadata with mode 0400.
- Sets the quarantined file to mode 0400.
- Removes the original only after successful verification.
- Fails closed: on any verification/copy error, the original is preserved.
"""

import datetime
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile

QUARANTINE_ROOT = "/var/ossec/quarantine"
LOG_FILE = "/var/ossec/logs/active-responses.log"


def log(message):
    try:
        with open(LOG_FILE, "a") as log_file:
            log_file.write(
                "{} orangebox-quarantine: {}\n".format(
                    datetime.datetime.utcnow().strftime("%Y/%m/%d %H:%M:%S"),
                    message,
                )
            )
    except Exception:
        pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def main():
    raw = sys.stdin.readline()
    if not raw:
        log("ERROR: empty active-response input")
        return 1

    try:
        message = json.loads(raw)
    except Exception as exc:
        log("ERROR: invalid JSON: {}".format(exc))
        return 1

    if message.get("command") != "add":
        log("Ignoring command={!r}".format(message.get("command")))
        return 0

    alert = message.get("parameters", {}).get("alert", {}) or {}
    syscheck = alert.get("syscheck", {}) or {}
    path = syscheck.get("path")
    expected = (syscheck.get("sha256") or syscheck.get("sha256_after") or "").lower()
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", ""))
    agent = alert.get("agent", {}) or {}

    if rule_id != "99901":
        log("Ignoring unexpected rule {}".format(rule_id))
        return 0

    if not path or not expected or len(expected) != 64:
        log("ERROR: missing syscheck.path or valid syscheck.sha256")
        return 1

    if not os.path.isfile(path) or os.path.islink(path):
        log("ERROR: target is missing or is a symlink: {}".format(path))
        return 1

    try:
        actual = sha256_file(path)
    except Exception as exc:
        log("ERROR: cannot hash {}: {}".format(path, exc))
        return 1

    if actual.lower() != expected:
        log(
            "ABORT: source hash changed/mismatch for {} expected={} actual={}".format(
                path, expected, actual
            )
        )
        return 1

    try:
        os.makedirs(QUARANTINE_ROOT, mode=0o700, exist_ok=True)
        os.chmod(QUARANTINE_ROOT, 0o700)
    except Exception as exc:
        log("ERROR: cannot create quarantine root {}: {}".format(QUARANTINE_ROOT, exc))
        return 1

    qdir = os.path.join(QUARANTINE_ROOT, expected)
    try:
        os.makedirs(qdir, mode=0o700, exist_ok=True)
        os.chmod(qdir, 0o700)
    except Exception as exc:
        log("ERROR: cannot create quarantine directory {}: {}".format(qdir, exc))
        return 1

    base = os.path.basename(path) or "quarantined-file"
    destination = os.path.join(qdir, base)
    if os.path.exists(destination):
        stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        destination = os.path.join(qdir, "{}-{}".format(stamp, base))

    temp_fd, temp_path = tempfile.mkstemp(prefix=".quarantine-", dir=qdir)
    os.close(temp_fd)

    try:
        shutil.copy2(path, temp_path, follow_symlinks=False)
        copied_hash = sha256_file(temp_path)

        if copied_hash.lower() != expected:
            log(
                "ABORT: quarantine copy hash mismatch for {} expected={} actual={}".format(
                    path, expected, copied_hash
                )
            )
            os.unlink(temp_path)
            return 1

        os.chmod(temp_path, 0o400)
        os.rename(temp_path, destination)
        os.chmod(destination, 0o400)
    except Exception as exc:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        log("ERROR: failed to quarantine {}: {}".format(path, exc))
        return 1

    try:
        source_stat = os.stat(path, follow_symlinks=False)
        metadata = {
            "quarantine_time_utc": datetime.datetime.utcnow().strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "rule_id": rule_id,
            "sha256": expected,
            "original_path": path,
            "quarantine_path": destination,
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "uid": source_stat.st_uid,
            "gid": source_stat.st_gid,
            "mode": "{:04o}".format(stat.S_IMODE(source_stat.st_mode)),
            "size": source_stat.st_size,
            "mtime_epoch": source_stat.st_mtime,
        }

        metadata_path = os.path.join(qdir, "metadata.json")
        temp_metadata = metadata_path + ".tmp"

        with open(temp_metadata, "w") as metadata_file:
            json.dump(metadata, metadata_file, indent=2, sort_keys=True)
            metadata_file.write("\n")

        os.chmod(temp_metadata, 0o400)
        os.rename(temp_metadata, metadata_path)
        os.chmod(metadata_path, 0o400)
    except Exception as exc:
        log(
            "WARNING: quarantined {} but metadata creation failed: {}".format(
                path, exc
            )
        )

    try:
        os.unlink(path)
    except Exception as exc:
        log(
            "ERROR: file preserved in quarantine but original could not be removed: "
            "{}: {}".format(path, exc)
        )
        return 1

    log(
        "QUARANTINED: {} -> {} sha256={} rule={} agent={}".format(
            path, destination, expected, rule_id, agent.get("name", "unknown")
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
