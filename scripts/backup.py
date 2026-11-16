"""Create an online, integrity-checked SQLite backup (no service interruption)."""
import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def backup(database, directory):
    source = Path(database).resolve(strict=True)
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / ("vulnwatch-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".db")
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as src:
        with sqlite3.connect(target) as dst:
            src.backup(dst)
            result = dst.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise RuntimeError("Backup integrity check failed: " + result)
    os.chmod(target, 0o600)
    print(str(target))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="/var/lib/vulnwatch/vulnwatch.db")
    parser.add_argument("--directory", default="/var/backups/vulnwatch")
    args = parser.parse_args()
    backup(args.database, args.directory)
