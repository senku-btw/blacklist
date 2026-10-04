#!/usr/bin/env python3
"""
Pi-hole Gravity Database Manager & Blacklist Migrator
Production-Grade Release (High Autonomy, Security-Hardened)
"""

import fcntl
import logging
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path
from typing import FrozenSet, List, Optional

import requests  # pylint: disable=import-error
from requests.adapters import HTTPAdapter  # pylint: disable=import-error
from urllib3.util.retry import Retry  # pylint: disable=import-error

# --- HARDENED CONFIGURATION & PATHS ---
SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_DB_PATH = (
    "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"
)
DB_PATH = Path(os.getenv("PIHOLE_DB_PATH", DEFAULT_DB_PATH))

BLACKLIST_FILE = SCRIPT_DIR / "blacklist.txt"
MINOR_LISTS_FILE = SCRIPT_DIR / "minor_lists.txt"
EXTRA_BLACKLIST_FILE = SCRIPT_DIR / "blacklist-extra.txt"
LOCK_FILE = SCRIPT_DIR / ".blacklist_manager.lock"

# Strict binary path resolution to prevent PATH hijacking
DOCKER_BIN = shutil.which("docker") or "/usr/bin/docker"
GIT_BIN = shutil.which("git") or "/usr/bin/git"

CMD_TIMEOUT = 30
FILE_PERMISSIONS = 0o644

# Stricter domain regex avoiding catastrophic backtracking
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# --- LOGGING SETUP ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - [%(funcName)s] %(message)s"
)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)


# --- LOCK MANAGER ---
class ProcessLockManager:
    """Manages process exclusion lock file using POSIX fcntl."""

    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self.lock_fd: Optional[int] = None

    def acquire(self) -> None:
        """Acquires an exclusive lock or exits if another process holds it."""
        try:
            self.lock_fd = os.open(
                self.lock_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600
            )
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.critical(
                "Another instance is running. Exiting to prevent DB corruption."
            )
            if self.lock_fd is not None:
                os.close(self.lock_fd)
            sys.exit(1)
        except OSError as e:
            logger.critical("Failed to acquire system lock: %s", e)
            sys.exit(1)

    def release(self) -> None:
        """Releases the lock and removes the lockfile."""
        if self.lock_fd is not None:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                os.close(self.lock_fd)
                if self.lock_path.exists():
                    self.lock_path.unlink(missing_ok=True)
                self.lock_fd = None
            except OSError as e:
                logger.error("Error releasing lock: %s", e)


lock_manager = ProcessLockManager(LOCK_FILE)


def signal_handler(signum: int, _frame: object) -> None:
    """Graceful degradation on system termination signals."""
    logger.warning(
        "Received termination signal (%d). Initiating graceful shutdown...",
        signum,
    )
    lock_manager.release()
    sys.exit(128 + signum)


# Register signal handlers for robust lifecycle management
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def get_db_connection() -> sqlite3.Connection:
    """Establish a secure, integrity-enforced SQLite3 connection."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def get_http_session() -> requests.Session:
    """Creates an HTTP session with strict timeouts and exponential backoff."""
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def sanitize_and_extract_domains(raw_data: List[str]) -> FrozenSet[str]:
    """Applies multi-step sanitization and strictly validates domains."""
    valid_domains = set()
    for line in raw_data:
        line = line.strip()
        if not line or line.startswith(("#", "!", "/", "<")):
            continue

        parts = line.split()
        candidate = parts[-1] if parts else ""
        candidate = candidate.lower().strip(".").split("#")[0].split("^")[0]

        if DOMAIN_REGEX.match(candidate):
            valid_domains.add(candidate)

    return frozenset(valid_domains)


def load_local_file(filepath: Path) -> FrozenSet[str]:
    """Loads domain lines from a local file and sanitizes them."""
    if not filepath.exists():
        return frozenset()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return sanitize_and_extract_domains(f.readlines())
    except OSError as e:
        logger.error("Failed to read %s: %s", filepath.name, e)
        return frozenset()


def write_frozenset_to_file(domains: FrozenSet[str], filepath: Path) -> None:
    """True POSIX atomic write operation using the system temp folder."""
    sorted_domains = sorted(domains)

    fd, temp_path = tempfile.mkstemp(dir=filepath.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")

        os.chmod(temp_path, FILE_PERMISSIONS)
        os.replace(temp_path, filepath)
        logger.info(
            "Successfully saved %d entries to %s",
            len(sorted_domains),
            filepath.name,
        )
    except OSError as e:
        logger.error("Failed to atomic-write %s: %s", filepath.name, e)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


# --- CORE LOGIC STEPS ---


def step1_migrate_exact_blacklists(conn: sqlite3.Connection) -> None:
    """Migrates exact blacklist items from the DB to a local text file."""
    logger.info("Starting Step 1: Exact Blacklist Migration")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT d.id, d.domain
        FROM domainlist d
        LEFT JOIN domainlist_by_group dbg ON d.id = dbg.domainlist_id
        WHERE d.type = 1
        AND (
            (dbg.group_id IS NULL AND (d.comment IS NULL OR d.comment = ''))
            OR dbg.group_id = 0
            OR (dbg.group_id IS NOT NULL AND (d.comment IS NULL OR d.comment = ''))
        )
        """
    )
    rows = cursor.fetchall()

    db_frozenset_items = set()
    db_ids_to_delete = []

    for row in rows:
        domain = row["domain"]
        row_id = row["id"]
        sanitized = sanitize_and_extract_domains([domain])
        if sanitized:
            db_frozenset_items.update(sanitized)
            db_ids_to_delete.append(row_id)

    if not db_frozenset_items:
        logger.info("No matching blacklist entries found in database.")

    local_frozenset = load_local_file(BLACKLIST_FILE)
    merged_frozenset = frozenset(db_frozenset_items | local_frozenset)
    write_frozenset_to_file(merged_frozenset, BLACKLIST_FILE)

    if db_ids_to_delete:
        try:
            placeholders = ",".join("?" * len(db_ids_to_delete))
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({placeholders})",
                db_ids_to_delete,
            )
            cursor.execute(
                f"DELETE FROM domainlist WHERE id IN ({placeholders})",
                db_ids_to_delete,
            )
            cursor.execute("COMMIT;")
            logger.info(
                "Deleted %d migrated entries from database.",
                len(db_ids_to_delete),
            )
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK;")
            logger.error("Failed to delete entries from DB: %s", e)


def fetch_and_validate_adlist(url: str, session: requests.Session) -> bool:
    """Fetches an adlist URL and checks if it contains zero valid domains."""
    try:
        response = session.get(url, timeout=15)
        response.raise_for_status()
        domains = sanitize_and_extract_domains(response.text.splitlines())
        return len(domains) == 0
    except requests.RequestException as e:
        logger.warning("Failed to fetch adlist %s: %s. Skipping deletion.", url, e)
        return False


def step2_prune_empty_adlists(
    conn: sqlite3.Connection, session: requests.Session
) -> None:
    """Identifies and purges verified empty adlists from the database."""
    logger.info("Starting Step 2: Empty Adlist Pruning")
    cursor = conn.cursor()
    cursor.execute("SELECT id, address FROM adlist WHERE number = 0")
    suspect_lists = cursor.fetchall()

    if not suspect_lists:
        logger.info("No adlists with 0 entries found in database.")
        return

    ids_to_delete = []
    for row in suspect_lists:
        adlist_id, url = row["id"], row["address"]
        if fetch_and_validate_adlist(url, session):
            ids_to_delete.append(adlist_id)

    if ids_to_delete:
        try:
            placeholders = ",".join("?" * len(ids_to_delete))
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                f"DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders})",
                ids_to_delete,
            )
            cursor.execute(
                f"DELETE FROM adlist WHERE id IN ({placeholders})",
                ids_to_delete,
            )
            cursor.execute("COMMIT;")
            logger.info(
                "Safely purged %d verified empty adlists from database.",
                len(ids_to_delete),
            )
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK;")
            logger.error("Database deletion failed for adlists: %s", e)


def _append_minor_urls(urls: List[str]) -> None:
    """Appends new minor list URLs to the tracking file."""
    existing_urls = set()
    if MINOR_LISTS_FILE.exists():
        with open(MINOR_LISTS_FILE, "r", encoding="utf-8") as f:
            existing_urls = set(f.read().splitlines())

    try:
        with open(MINOR_LISTS_FILE, "a", encoding="utf-8") as f:
            for url in urls:
                if url not in existing_urls:
                    f.write(f"{url}\n")
        os.chmod(MINOR_LISTS_FILE, FILE_PERMISSIONS)
        logger.info("Stored/Updated minor list URLs in %s", MINOR_LISTS_FILE.name)
    except OSError as e:
        logger.error("Failed to append to %s: %s", MINOR_LISTS_FILE.name, e)


def step3_extract_minor_lists(
    conn: sqlite3.Connection, session: requests.Session
) -> None:
    """Extracts minor adlists (1-100 entries) and moves them to local extra blacklist."""
    logger.info("Starting Step 3: Minor List Extraction & Migration")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT a.id, a.address
        FROM adlist a
        JOIN adlist_by_group abg ON a.id = abg.adlist_id
        WHERE abg.group_id = 0 AND a.number BETWEEN 1 AND 100
        """
    )
    minor_lists = cursor.fetchall()

    if not minor_lists:
        logger.info("No minor lists (1-100 entries) found in default group.")
        return

    adlist_ids_to_delete = [row["id"] for row in minor_lists]
    urls = [row["address"] for row in minor_lists]

    _append_minor_urls(urls)

    all_extracted_domains = set()
    for url in urls:
        try:
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            extracted = sanitize_and_extract_domains(resp.text.splitlines())
            all_extracted_domains.update(extracted)
        except requests.RequestException as e:
            logger.warning("Could not fetch domains from minor list %s: %s", url, e)

    try:
        write_frozenset_to_file(
            frozenset(all_extracted_domains | load_local_file(EXTRA_BLACKLIST_FILE)),
            EXTRA_BLACKLIST_FILE,
        )
    except OSError as e:
        logger.error("Failed to write blacklist-extra.txt. Aborting DB purge: %s", e)
        return

    if adlist_ids_to_delete:
        try:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(
                f"DELETE FROM adlist_by_group WHERE adlist_id IN "
                f"({','.join('?' * len(adlist_ids_to_delete))})",
                adlist_ids_to_delete,
            )
            cursor.execute(
                f"DELETE FROM adlist WHERE id IN "
                f"({','.join('?' * len(adlist_ids_to_delete))})",
                adlist_ids_to_delete,
            )
            cursor.execute("COMMIT;")
            logger.info(
                "Successfully purged %d minor lists from gravity database.",
                len(adlist_ids_to_delete),
            )
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK;")
            logger.error("Database deletion failed for minor lists: %s", e)


# --- SYSTEM INTEGRATIONS ---


def reload_ftl_engine(container_name: str = "pihole") -> None:
    """Forces the Pi-hole dashboard to update by restarting FTL."""
    logger.info("Forcing FTL cold-restart to rebuild shared memory counters...")
    if not os.path.exists(DOCKER_BIN):
        logger.error("Docker binary not found. Cannot reload FTL engine.")
        return

    nuke_shm_cmd = [
        DOCKER_BIN,
        "exec",
        container_name,
        "sh",
        "-c",
        "rm -f /dev/shm/FTL-*",
    ]
    kill_ftl_cmd = [DOCKER_BIN, "exec", container_name, "pkill", "-TERM", "pihole-FTL"]
    force_kill_cmd = [DOCKER_BIN, "exec", container_name, "pkill", "-9", "pihole-FTL"]

    try:
        logger.debug("Executing: %s", " ".join(nuke_shm_cmd))
        subprocess.run(
            nuke_shm_cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=CMD_TIMEOUT,
        )

        logger.debug("Executing: %s", " ".join(kill_ftl_cmd))
        subprocess.run(
            kill_ftl_cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=CMD_TIMEOUT,
        )

        logger.info(
            "FTL memory wiped and process restarted. Dashboard will now reflect gravity.db."
        )

    except subprocess.CalledProcessError as e:
        if "pkill" in e.cmd and e.returncode == 1:
            logger.info(
                "Graceful kill returned 1 (already stopped). "
                "Attempting SIGKILL fallback..."
            )
            subprocess.run(
                force_kill_cmd, capture_output=True, text=True, check=False, timeout=10
            )
        else:
            stderr_msg = e.stderr.strip() if e.stderr else "Unknown error"
            logger.warning("FTL cold-restart encountered an issue: %s", stderr_msg)

    except subprocess.TimeoutExpired as e:
        logger.warning("Command timed out: %s", " ".join(e.cmd))


def push_to_github() -> None:
    """Pushes local list updates to GitHub repository."""
    logger.info("Starting GitHub Repository Backup...")
    if not os.path.exists(GIT_BIN):
        logger.error("Git binary not found. Cannot push to repository.")
        return

    expected_files = ["blacklist.txt", "minor_lists.txt", "blacklist-extra.txt"]
    files_to_add = [f for f in expected_files if (SCRIPT_DIR / f).exists()]

    if not files_to_add:
        logger.info("No target text files currently exist to commit.")
        return

    try:
        status = subprocess.run(
            [GIT_BIN, "status", "--porcelain"] + files_to_add,
            cwd=SCRIPT_DIR,
            capture_output=True,
            text=True,
            check=True,
            timeout=CMD_TIMEOUT,
        )

        if not status.stdout.strip():
            logger.info(
                "No changes detected in target list files. Skipping GitHub push."
            )
            return

        commit_msg = secrets.token_hex(4)

        subprocess.run(
            [GIT_BIN, "add"] + files_to_add,
            cwd=SCRIPT_DIR,
            check=True,
            capture_output=True,
            timeout=CMD_TIMEOUT,
        )
        subprocess.run(
            [GIT_BIN, "commit", "-m", commit_msg],
            cwd=SCRIPT_DIR,
            check=True,
            capture_output=True,
            timeout=CMD_TIMEOUT,
        )
        subprocess.run(
            [GIT_BIN, "push"],
            cwd=SCRIPT_DIR,
            check=True,
            capture_output=True,
            timeout=CMD_TIMEOUT,
        )

        logger.info("Successfully pushed updates to GitHub with commit: %s", commit_msg)

    except subprocess.TimeoutExpired:
        logger.error("Git operation timed out.")
    except subprocess.CalledProcessError as e:
        stdout_msg = (
            e.stdout.decode("utf-8", errors="ignore").strip()
            if isinstance(e.stdout, bytes)
            else str(e.stdout or "")
        )
        stderr_msg = (
            e.stderr.decode("utf-8", errors="ignore").strip()
            if isinstance(e.stderr, bytes)
            else str(e.stderr or "")
        )
        logger.error(
            "GitHub push failed. Git error -> stderr: '%s' | stdout: '%s'",
            stderr_msg,
            stdout_msg,
        )


# --- ORCHESTRATION ---


def main() -> None:
    """Main orchestration pipeline for Pi-hole Gravity Database Manager."""
    logger.info("Initiating Pi-hole Gravity Database Manager...")
    lock_manager.acquire()

    try:
        with closing(get_db_connection()) as conn, closing(
            get_http_session()
        ) as http_session:
            step1_migrate_exact_blacklists(conn)
            step2_prune_empty_adlists(conn, http_session)
            step3_extract_minor_lists(conn, http_session)

        reload_ftl_engine()
        push_to_github()

    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Execution pipeline failed: %s", e, exc_info=True)
    finally:
        lock_manager.release()
        logger.info("All tasks completed.")


if __name__ == "__main__":
    main()
