#!/usr/bin/env python3
"""
Pi-hole gravity.db Maintenance and Blacklist Extraction Suite.

Enterprise-grade in-place database processor and maintenance pipeline.
Extracts, sanitizes, and purges database entries directly using set-based
SQL queries, retry decorators, concurrent HTTP list fetching, and Git synchronization.
"""

import logging
import os
import re
import secrets
import shutil
import signal
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, List, Optional, Set

# ------------------------------------------------------------------------------
# Enterprise Configuration & Environment Overrides
# ------------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

DB_PATH = Path(
    os.getenv(
        "GRAVITY_DB_PATH",
        "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db",
    )
).resolve()

CONTAINER_NAME = os.getenv("PIHOLE_CONTAINER_NAME", "pihole")
if not re.match(r"^[a-zA-Z0-9_.-]+$", CONTAINER_NAME):
    raise ValueError(f"Invalid CONTAINER_NAME provided: {CONTAINER_NAME}")

BLACKLISTS_DIR = BASE_DIR / "blacklists"
REGEX_DIR = BASE_DIR / "regex"

BLACKLIST_FILE = BLACKLISTS_DIR / "blacklist.txt"
EXTRA_FILE = BLACKLISTS_DIR / "blacklist-extra.txt"
REGEX_FILE = REGEX_DIR / "regex_deny.txt"
MINOR_LISTS_FILE = BASE_DIR / "minor-lists.txt"
EMPTY_LISTS_FILE = BASE_DIR / "empty-lists.txt"

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Safeguards & Performance Parameters
MIN_FREE_DISK_BYTES = int(os.getenv("MIN_FREE_DISK_BYTES", str(50 * 1024 * 1024)))
HTTP_TIMEOUT_SECONDS = int(os.getenv("HTTP_TIMEOUT_SECONDS", "10"))
MAX_HTTP_WORKERS = int(os.getenv("MAX_HTTP_WORKERS", "12"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", str(20 * 1024 * 1024)))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("GravityPipeline")


# ------------------------------------------------------------------------------
# System & Robustness Helpers
# ------------------------------------------------------------------------------
def handle_shutdown_signals(signum: int, _frame: Any) -> None:
    """Safely handle incoming shutdown signals like SIGINT and SIGTERM."""
    logger.warning("Received shutdown signal (%s). Exiting safely...", signum)
    sys.exit(128 + signum)


signal.signal(signal.SIGINT, handle_shutdown_signals)
signal.signal(signal.SIGTERM, handle_shutdown_signals)


def retry_on_db_lock(max_retries: int = 5, initial_delay: float = 1.0):
    """Decorator to retry database operations if the SQLite database is locked."""

    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            delay = initial_delay
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as err:
                    if "locked" in str(err).lower() or "busy" in str(err).lower():
                        if attempt == max_retries:
                            logger.error(
                                "Database remained locked after %s attempts. Aborting.",
                                max_retries,
                            )
                            raise
                        logger.warning(
                            "Database busy (attempt %s/%s). Retrying in %.1fs...",
                            attempt,
                            max_retries,
                            delay,
                        )
                        time.sleep(delay)
                        delay *= 2
                    else:
                        raise
            return None

        return wrapper

    return decorator


def check_preflight_conditions(db_path: Path) -> None:
    """Verify prerequisites like database existence and adequate disk space."""
    if not db_path.exists():
        raise FileNotFoundError(f"Database file missing at path: {db_path}")

    stat = shutil.disk_usage(db_path.parent)
    if stat.free < MIN_FREE_DISK_BYTES:
        free_mb = stat.free / 1024 / 1024
        req_mb = MIN_FREE_DISK_BYTES / 1024 / 1024
        raise OSError(
            f"Insufficient disk space. Free: {free_mb:.2f} MB, Required: {req_mb:.2f} MB"
        )

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
        conn.execute("SELECT 1 FROM info LIMIT 1;")
        conn.close()
        logger.info("Pre-flight database read check passed.")
    except sqlite3.Error as err:
        raise sqlite3.DatabaseError(f"Failed database health check: {err}") from err


def ensure_database_indexes(conn: sqlite3.Connection) -> None:
    """Ensure database possesses performance indexes before running operations."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_gravity_adlist_id';"
    )
    if not cursor.fetchone():
        logger.info("Index idx_gravity_adlist_id missing. Building index...")
        cursor.execute("CREATE INDEX idx_gravity_adlist_id ON gravity (adlist_id);")


# ------------------------------------------------------------------------------
# Database Connection & File Context Managers
# ------------------------------------------------------------------------------
@contextmanager
def get_db_connection(db_path: Path):
    """Context manager for yielding a configured SQLite connection."""
    check_preflight_conditions(db_path)

    conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=60.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 60000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -10000;")

        ensure_database_indexes(conn)
        yield conn
    except sqlite3.Error as err:
        conn.rollback()
        logger.error("Database transaction error encountered, rolling back: %s", err)
        raise
    finally:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except sqlite3.Error as err:
            logger.warning("WAL truncate checkpoint warning: %s", err)
        conn.close()


# ------------------------------------------------------------------------------
# Sanitization & Data Parsers
# ------------------------------------------------------------------------------
def sanitize_domain(raw_domain: str) -> Optional[str]:
    """Clean and validate domain strings against standard patterns."""
    if not raw_domain or not isinstance(raw_domain, str):
        return None
    cleaned = (
        re.sub(r"[\x00-\x1F\x7F-\x9F\u200b-\u200d\ufeff]", "", raw_domain)
        .strip()
        .lower()
    )
    return cleaned if cleaned and DOMAIN_REGEX.match(cleaned) else None


def sanitize_regex(raw_regex: str) -> Optional[str]:
    """Validate and clean raw regular expression strings."""
    if not raw_regex or not isinstance(raw_regex, str):
        return None
    cleaned = raw_regex.strip()
    if not cleaned:
        return None
    try:
        re.compile(cleaned)
        return cleaned
    except re.error:
        logger.warning("Invalid regular expression skipped: '%s'", cleaned)
        return None


def read_text_file_lines(file_path: Path) -> Set[str]:
    """Read lines from a file path into a set, ignoring errors cleanly."""
    if not file_path.is_file():
        return set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return {line.strip() for line in file if line.strip()}
    except IOError as err:
        logger.error("Failed to read file %s: %s", file_path, err)
        raise


def atomic_write_file(file_path: Path, lines: List[str]) -> None:
    """Write list entries atomically using a temporary file with rollback."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    new_content = "".join(f"{line}\n" for line in lines)

    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                if file.read() == new_content:
                    logger.info(
                        "Content unchanged. Skipped disk write for %s", file_path.name
                    )
                    return
        except IOError as err:
            logger.warning(
                "Failed reading file for content comparison, writing: %s", err
            )

    temp_path = file_path.with_suffix(".tmp")
    backup_path = file_path.with_suffix(".bak")

    if file_path.exists():
        shutil.copy2(file_path, backup_path)

    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            file.write(new_content)
            file.flush()
            os.fsync(file.fileno())

        temp_path.replace(file_path)

        if backup_path.exists():
            backup_path.unlink()

        logger.info("Successfully wrote %s entries to %s", len(lines), file_path)
    except IOError as err:
        if temp_path.exists():
            temp_path.unlink()
        if backup_path.exists() and not file_path.exists():
            shutil.move(backup_path, file_path)
        logger.error("Failed atomic write to %s: %s", file_path, err)
        raise


def fetch_single_list(url: str) -> Set[str]:
    """Worker function to download and parse remote blocklists concurrently."""
    extracted: Set[str] = set()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; PiholeGravityPipeline/2.1)"},
    )

    ssl_context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(
            req, timeout=HTTP_TIMEOUT_SECONDS, context=ssl_context
        ) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                logger.warning(
                    "Skipping %s: Payload exceeds allowed size (%s bytes)",
                    url,
                    content_length,
                )
                return extracted

            raw_bytes = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw_bytes) > MAX_RESPONSE_BYTES:
                logger.warning(
                    "Skipping %s: Response body exceeded limit of %s bytes",
                    url,
                    MAX_RESPONSE_BYTES,
                )
                return extracted

            text = raw_bytes.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                clean_line = line.split("#")[0].strip()
                if not clean_line:
                    continue
                parts = clean_line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    target = parts[1]
                else:
                    target = parts[0]
                if sanitized := sanitize_domain(target):
                    extracted.add(sanitized)
    except (urllib.error.URLError, ssl.SSLError, IOError) as err:
        logger.warning("Failed to fetch minor list URL %s: %s", url, err)
    return extracted


def get_default_group_id(cursor: sqlite3.Cursor) -> int:
    """Retrieve the primary ID for the 'Default' grouping in the domain database."""
    cursor.execute("SELECT id FROM 'group' WHERE name = 'Default';")
    row = cursor.fetchone()
    return int(row["id"]) if row else 0


# ------------------------------------------------------------------------------
# Core Pipeline Execution Steps
# ------------------------------------------------------------------------------
@retry_on_db_lock()
def step_1_process_exact_blocked_domains(conn: sqlite3.Connection) -> None:
    # pylint: disable=too-many-locals
    """Extract manually configured blacklisted domains and purge from the DB."""
    logger.info("Starting Step 1: Exact blocked domains processing...")
    cursor = conn.cursor()
    default_group_id = get_default_group_id(cursor)

    query = """
        SELECT d.id, d.domain
        FROM domainlist d
        JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
        WHERE d.type = 1
          AND dg.group_id = ?
          AND (d.comment IS NULL OR TRIM(d.comment) = '')
    """
    cursor.execute(query, (default_group_id,))
    rows = cursor.fetchall()

    extracted_domains: Set[str] = set()
    domain_ids_to_delete: List[int] = []

    for row in rows:
        domain_id = int(row["id"])
        if sanitized := sanitize_domain(row["domain"]):
            extracted_domains.add(sanitized)
            domain_ids_to_delete.append(domain_id)

    logger.info("Step 1 DB query yielded %s matching domains.", len(extracted_domains))

    existing_domains = read_text_file_lines(BLACKLIST_FILE)
    sanitized_existing = {
        s for line in existing_domains if (s := sanitize_domain(line))
    }
    combined_set = extracted_domains.union(sanitized_existing)

    if extracted_domains or not BLACKLIST_FILE.exists():
        atomic_write_file(BLACKLIST_FILE, sorted(combined_set))

    if domain_ids_to_delete:
        logger.info(
            "Deleting %s transferred entries from gravity.db...",
            len(domain_ids_to_delete),
        )
        with conn:
            for i in range(0, len(domain_ids_to_delete), 500):
                chunk = domain_ids_to_delete[i : i + 500]
                placeholders = ",".join(["?"] * len(chunk))
                cursor.execute(
                    f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({placeholders});",
                    tuple(chunk),
                )
                cursor.execute(
                    f"DELETE FROM domainlist WHERE id IN ({placeholders});",
                    tuple(chunk),
                )
        logger.info("Step 1 database purge completed successfully.")


@retry_on_db_lock()
def step_2_process_regex_deny(conn: sqlite3.Connection) -> None:
    """
    Extract deny regular expressions, excluding healthchecks,
    and assign healthcheck regexes to Default group.
    """
    logger.info("Starting Step 2: Regex deny rules processing...")
    cursor = conn.cursor()

    default_group_id = get_default_group_id(cursor)

    cursor.execute("SELECT id FROM 'group' WHERE LOWER(name) = 'healthcheck';")
    healthcheck_row = cursor.fetchone()
    healthcheck_id = int(healthcheck_row["id"]) if healthcheck_row else None

    # 1. Identify regex deny entries assigned to healthcheck group or with comment "healthcheck"
    healthcheck_regex_query = """
        SELECT DISTINCT d.id, d.domain
        FROM domainlist d
        LEFT JOIN domainlist_by_group dg ON d.id = dg.domainlist_id AND dg.group_id = ?
        WHERE d.type = 3
          AND (dg.domainlist_id IS NOT NULL OR LOWER(TRIM(d.comment)) = 'healthcheck')
    """
    hc_param = healthcheck_id if healthcheck_id is not None else -1
    cursor.execute(healthcheck_regex_query, (hc_param,))
    healthcheck_rows = cursor.fetchall()

    # 2. Ensure these healthcheck/comment-matching regex entries are assigned to the Default group also
    if default_group_id and healthcheck_rows:
        with conn:
            assigned_count = 0
            for row in healthcheck_rows:
                domainlist_id = int(row["id"])
                cursor.execute(
                    "SELECT 1 FROM domainlist_by_group WHERE domainlist_id = ? AND group_id = ?",
                    (domainlist_id, default_group_id)
                )
                if not cursor.fetchone():
                    cursor.execute(
                        "INSERT INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)",
                        (domainlist_id, default_group_id)
                    )
                    assigned_count += 1
            if assigned_count > 0:
                logger.info(
                    "Assigned %s healthcheck/comment regex entries to the Default group.",
                    assigned_count,
                )

    # 3. Extract remaining regex deny entries for regex_deny.txt
    # (excluding healthcheck group or comment "healthcheck")
    export_query = """
        SELECT DISTINCT d.domain
        FROM domainlist d
        LEFT JOIN domainlist_by_group dg ON d.id = dg.domainlist_id AND dg.group_id = ?
        WHERE d.type = 3
          AND dg.domainlist_id IS NULL
          AND (d.comment IS NULL OR LOWER(TRIM(d.comment)) != 'healthcheck')
    """
    cursor.execute(export_query, (hc_param,))
    rows = cursor.fetchall()
    processed_regexes = {
        sanitized for row in rows if (sanitized := sanitize_regex(row["domain"]))
    }

    atomic_write_file(REGEX_FILE, sorted(processed_regexes))
    logger.info("Step 2 completed. %s regex entries saved.", len(processed_regexes))


@retry_on_db_lock()
def step_3_purge_empty_blocklists(conn: sqlite3.Connection) -> None:
    """Remove empty adlists from the gravity database and record their links."""
    logger.info("Starting Step 3: Empty blocklists purge verification...")
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(adlist);")
    columns = [col["name"] for col in cursor.fetchall()]
    type_filter = " AND a.type = 0" if "type" in columns else ""

    empty_candidates_query = f"""
        SELECT a.id, a.address
        FROM adlist a
        WHERE a.id NOT IN (
            SELECT DISTINCT adlist_id
            FROM gravity
            WHERE adlist_id IS NOT NULL
        ) {type_filter};
    """
    cursor.execute(empty_candidates_query)
    rows = cursor.fetchall()

    empty_ids: List[int] = [int(row["id"]) for row in rows]
    empty_urls: Set[str] = {
        row["address"].strip() for row in rows if row["address"] and row["address"].strip()
    }

    if empty_urls:
        existing_empty_lists = read_text_file_lines(EMPTY_LISTS_FILE)
        combined_empty_lists = existing_empty_lists.union(empty_urls)
        atomic_write_file(EMPTY_LISTS_FILE, sorted(combined_empty_lists))
        logger.info(
            "Recorded %s empty blocklist links to %s",
            len(empty_urls),
            EMPTY_LISTS_FILE.name,
        )

    if not empty_ids:
        logger.info("Step 3: No empty blocklists found.")
        return

    logger.info("Purging %s empty blocklists from database...", len(empty_ids))
    with conn:
        for i in range(0, len(empty_ids), 500):
            chunk = empty_ids[i : i + 500]
            placeholders = ",".join(["?"] * len(chunk))
            cursor.execute(
                f"DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders});",
                tuple(chunk),
            )
            cursor.execute(
                f"DELETE FROM adlist WHERE id IN ({placeholders});", tuple(chunk)
            )
    logger.info("Step 3 completed. Purged %s empty adlists.", len(empty_ids))


@retry_on_db_lock()
def step_4_process_minor_blocklists(conn: sqlite3.Connection) -> None:
    # pylint: disable=too-many-locals
    """Fetch concurrent payloads of minor adlists (<= 100 entries)."""
    logger.info("Starting Step 4: Minor blocklists extraction and fresh HTTP fetch...")
    cursor = conn.cursor()
    default_group_id = get_default_group_id(cursor)

    query_exclusive_default = """
        SELECT adlist_id
        FROM adlist_by_group
        GROUP BY adlist_id
        HAVING COUNT(DISTINCT group_id) = 1 AND MAX(group_id) = ?
    """
    cursor.execute(query_exclusive_default, (default_group_id,))
    exclusive_adlist_ids: List[int] = [
        int(row["adlist_id"]) for row in cursor.fetchall()
    ]

    new_minor_urls: Set[str] = set()

    if exclusive_adlist_ids:
        minor_candidates: Set[int] = set()
        for i in range(0, len(exclusive_adlist_ids), 500):
            chunk = exclusive_adlist_ids[i : i + 500]
            placeholders = ",".join(["?"] * len(chunk))
            batch_query = f"""
                SELECT adlist_id
                FROM gravity
                WHERE adlist_id IN ({placeholders})
                GROUP BY adlist_id
                HAVING COUNT(*) BETWEEN 1 AND 100;
            """
            cursor.execute(batch_query, tuple(chunk))
            minor_candidates.update(int(row["adlist_id"]) for row in cursor.fetchall())

        if minor_candidates:
            logger.info("Identified %s new minor lists in DB.", len(minor_candidates))
            minor_candidates_list = list(minor_candidates)
            for i in range(0, len(minor_candidates_list), 500):
                chunk = minor_candidates_list[i : i + 500]
                placeholders = ",".join(["?"] * len(chunk))
                cursor.execute(
                    f"SELECT address FROM adlist WHERE id IN ({placeholders});",
                    tuple(chunk),
                )
                new_minor_urls.update(
                    row["address"].strip()
                    for row in cursor.fetchall()
                    if row["address"]
                )

    if not new_minor_urls:
        logger.info(
            "Step 4: No new minor lists with 1 to 100 domains identified in DB."
        )

    existing_minor_urls = read_text_file_lines(MINOR_LISTS_FILE)
    all_minor_urls = existing_minor_urls.union(new_minor_urls)

    if not all_minor_urls:
        logger.info("No minor lists available to process. Skipping HTTP fetch.")
        return

    if new_minor_urls:
        atomic_write_file(MINOR_LISTS_FILE, sorted(all_minor_urls))

    logger.info(
        "Fetching fresh contents concurrently over HTTP for %s minor lists...",
        len(all_minor_urls),
    )
    extracted_domains: Set[str] = set()

    with ThreadPoolExecutor(max_workers=MAX_HTTP_WORKERS) as executor:
        future_to_url = {
            executor.submit(fetch_single_list, url): url for url in all_minor_urls
        }
        for future in as_completed(future_to_url):
            extracted_domains.update(future.result())

    if extracted_domains:
        existing_extra_domains = read_text_file_lines(EXTRA_FILE)
        san_extra = {
            s for line in existing_extra_domains if (s := sanitize_domain(line))
        }
        combined_extra_domains = san_extra.union(extracted_domains)

        atomic_write_file(EXTRA_FILE, sorted(combined_extra_domains))
        logger.info(
            "Step 4 completed. Extracted %s active domains from minor URLs.",
            len(extracted_domains),
        )
    else:
        logger.info("Step 4 completed. No valid domains extracted from minor URLs.")


@retry_on_db_lock()
def step_5_purge_minor_blocklists_from_db(conn: sqlite3.Connection) -> None:
    """Purge identified minor lists from the local Pi-hole configuration in DB."""
    logger.info("Starting Step 5: Purging minor blocklists from database in-place...")
    minor_urls = list(read_text_file_lines(MINOR_LISTS_FILE))

    if not minor_urls:
        logger.info("No minor list URLs found to purge.")
        return

    cursor = conn.cursor()
    target_ids: List[int] = []

    for i in range(0, len(minor_urls), 500):
        url_chunk = minor_urls[i : i + 500]
        placeholders = ",".join(["?"] * len(url_chunk))
        cursor.execute(
            f"SELECT id FROM adlist WHERE TRIM(address) IN ({placeholders});",
            tuple(url_chunk),
        )
        fetched_rows = cursor.fetchall()
        target_ids.extend([int(row["id"]) for row in fetched_rows])

    if not target_ids:
        logger.info("Step 5: No matching adlist IDs found in database for deletion.")
        return

    logger.info("Executing purge for %s minor adlists...", len(target_ids))
    with conn:
        for i in range(0, len(target_ids), 500):
            id_chunk = target_ids[i : i + 500]
            placeholders = ",".join(["?"] * len(id_chunk))
            cursor.execute(
                f"DELETE FROM gravity WHERE adlist_id IN ({placeholders});",
                tuple(id_chunk),
            )
            cursor.execute(
                f"DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders});",
                tuple(id_chunk),
            )
            cursor.execute(
                f"DELETE FROM adlist WHERE id IN ({placeholders});", tuple(id_chunk)
            )

    logger.info("Step 5 completed. Purged %s matching minor adlists.", len(target_ids))


def stop_pihole_container() -> None:
    """Temporarily stop the Pi-hole container to release database locks."""
    logger.info("Checking Pi-hole Docker container status...")

    if not shutil.which("docker"):
        logger.warning("Docker executable not found in PATH. Skipping container stop.")
        return

    try:
        check_running = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
            text=True,
            timeout=10,
            stderr=subprocess.STDOUT,
        ).strip()

        if check_running != "true":
            logger.warning(
                "Pi-hole container '%s' is not running. Skipping stop.",
                CONTAINER_NAME,
            )
            return

        logger.info(
            "Stopping Pi-hole container '%s' temporarily...", CONTAINER_NAME
        )
        subprocess.run(
            ["docker", "stop", CONTAINER_NAME],
            check=True,
            timeout=30,
            capture_output=True,
            text=True,
        )
        logger.info("Pi-hole container stopped successfully.")
    except subprocess.TimeoutExpired:
        logger.error("Docker execution timed out while stopping container.")
    except subprocess.CalledProcessError as err:
        logger.error("Failed to stop Pi-hole container via docker stop: %s", err.output)
    except OSError as err:
        logger.warning("Unexpected error stopping Pi-hole container: %s", err)


def start_pihole_container() -> None:
    """Start the Pi-hole container back up after database maintenance."""
    if not shutil.which("docker"):
        logger.warning("Docker executable not found in PATH. Skipping container start.")
        return

    try:
        logger.info("Starting Pi-hole container '%s'...", CONTAINER_NAME)
        subprocess.run(
            ["docker", "start", CONTAINER_NAME],
            check=True,
            timeout=30,
            capture_output=True,
            text=True,
        )
        logger.info("Pi-hole container started successfully.")
    except subprocess.TimeoutExpired:
        logger.error("Docker execution timed out while starting container.")
    except subprocess.CalledProcessError as err:
        logger.error("Failed to start Pi-hole container via docker start: %s", err.output)
    except OSError as err:
        logger.warning("Unexpected error starting Pi-hole container: %s", err)


def step_6_git_commit_and_push() -> None:
    """Commit configuration changes and push them dynamically to the remote Git repo."""
    logger.info("Starting Step 6: Git version control push...")

    if not shutil.which("git"):
        logger.warning("Git executable not found in PATH. Skipping git operations.")
        return

    if not (BASE_DIR / ".git").exists():
        logger.warning("Directory is not a Git repository. Skipping git operations.")
        return

    hex_commit_msg = secrets.token_hex(4)[:7]

    try:
        pull_run = subprocess.run(
            ["git", "pull", "--rebase", "--autostash"],
            cwd=str(BASE_DIR),
            check=False,
            timeout=20,
            capture_output=True,
            text=True,
        )

        if pull_run.returncode != 0:
            logger.error(
                "Git pull failed. Aborting commit to protect repository state. Details: %s",
                pull_run.stderr,
            )
            return

        status_output = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(BASE_DIR),
            text=True,
            timeout=15,
        )

        if not status_output.strip():
            logger.info("No changes detected in Git repository. Skipping commit/push.")
            return

        subprocess.run(
            ["git", "add", "-A"],
            cwd=str(BASE_DIR),
            check=True,
            timeout=15,
            capture_output=True,
        )

        staged_status = subprocess.check_output(
            ["git", "diff", "--staged", "--name-only"],
            cwd=str(BASE_DIR),
            text=True,
            timeout=15,
        )

        if not staged_status.strip():
            logger.info("No staged changes to commit. Skipping commit.")
            return

        subprocess.run(
            ["git", "commit", "-m", hex_commit_msg],
            cwd=str(BASE_DIR),
            check=True,
            timeout=15,
            capture_output=True,
        )

        subprocess.run(
            ["git", "push"],
            cwd=str(BASE_DIR),
            check=True,
            timeout=30,
            capture_output=True,
        )
        logger.info("Git push executed successfully.")

    except subprocess.TimeoutExpired as err:
        logger.error("Git execution timed out: %s", err)
    except subprocess.CalledProcessError as err:
        logger.error("Git execution failed: %s", err.stderr or err.output)


# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------
def main() -> None:
    """Bootstrap script environment and orchestrate execution process safely."""
    logger.info("Initializing Gravity Database Extraction and Maintenance Pipeline.")

    BLACKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    REGEX_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # Stop Pi-hole container completely to eliminate any database lock risks
        stop_pihole_container()

        try:
            with get_db_connection(DB_PATH) as conn:
                step_1_process_exact_blocked_domains(conn)
                step_2_process_regex_deny(conn)
                step_3_purge_empty_blocklists(conn)
                step_4_process_minor_blocklists(conn)
                step_5_purge_minor_blocklists_from_db(conn)
        finally:
            # Ensure container restarts even if database operations encounter an exception
            start_pihole_container()

        step_6_git_commit_and_push()

        logger.info("Pipeline execution finished cleanly and successfully.")
        sys.exit(0)

    except Exception as fatal_err:  # pylint: disable=broad-exception-caught
        logger.critical(
            "Fatal error encountered during pipeline execution: %s",
            fatal_err,
            exc_info=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
