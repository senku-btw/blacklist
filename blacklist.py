#!/usr/bin/env python3
"""
Pi-hole gravity.db Maintenance and Blacklist Extraction Suite.

Direct in-place database processor for Pi-hole gravity.db.
Extracts, sanitizes, and cleans database entries directly using set-based
SQL queries, retry decorators for lock resilience, and pre-flight health checks.
"""

import os
import sys
import re
import time
import signal
import sqlite3
import logging
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Set, List, Optional, Callable, Any
from contextlib import contextmanager

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
DB_PATH = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
BASE_DIR = Path(__file__).resolve().parent

BLACKLISTS_DIR = BASE_DIR / "blacklists"
REGEX_DIR = BASE_DIR / "regex"

BLACKLIST_FILE = BLACKLISTS_DIR / "blacklist.txt"
EXTRA_FILE = BLACKLISTS_DIR / "blacklist-extra.txt"
REGEX_FILE = REGEX_DIR / "regex_deny.txt"
MINOR_LISTS_FILE = BASE_DIR / "minor-lists.txt"

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

MIN_FREE_DISK_BYTES = 50 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Robustness Helpers
# ------------------------------------------------------------------------------
def handle_shutdown_signals(signum: int, frame: Any) -> None:
    logger.warning(f"Received signal {signum}. Terminating process safely...")
    sys.exit(128 + signum)

signal.signal(signal.SIGINT, handle_shutdown_signals)
signal.signal(signal.SIGTERM, handle_shutdown_signals)

def retry_on_db_lock(max_retries: int = 5, initial_delay: float = 1.0):
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            delay = initial_delay
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except sqlite3.OperationalError as err:
                    if "locked" in str(err).lower() or "busy" in str(err).lower():
                        if attempt == max_retries:
                            logger.error(f"Database locked after {max_retries} attempts. Aborting.")
                            raise
                        logger.warning(f"Database busy (attempt {attempt}/{max_retries}). Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                        delay *= 2
                    else:
                        raise
        return wrapper
    return decorator

def check_preflight_conditions(db_path: Path) -> None:
    if not db_path.exists():
        raise FileNotFoundError(f"Database file missing at path: {db_path}")

    stat = shutil.disk_usage(db_path.parent)
    if stat.free < MIN_FREE_DISK_BYTES:
        raise OSError(f"Insufficient disk space. Free: {stat.free / 1024 / 1024:.2f} MB required: 50 MB")

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
        conn.execute("SELECT 1 FROM info LIMIT 1;")
        conn.close()
        logger.info("Pre-flight database read check passed.")
    except Exception as err:
        raise sqlite3.DatabaseError(f"Failed database health check: {err}")

# ------------------------------------------------------------------------------
# Database Connection & File Operations
# ------------------------------------------------------------------------------
@contextmanager
def get_db_connection(db_path: Path):
    check_preflight_conditions(db_path)
    conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=60.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 60000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_gravity_adlist_id ON gravity (adlist_id);")
        yield conn
    except Exception as err:
        conn.rollback()
        logger.error(f"Database transaction error, rolling back: {err}")
        raise
    finally:
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
        except Exception as e:
            logger.warning(f"WAL passive checkpoint warning: {e}")
        conn.close()

def sanitize_domain(raw_domain: str) -> Optional[str]:
    if not raw_domain or not isinstance(raw_domain, str):
        return None
    cleaned = re.sub(r"[\x00-\x1F\x7F-\x9F\u200b-\u200d\ufeff]", "", raw_domain).strip().lower()
    return cleaned if cleaned and DOMAIN_REGEX.match(cleaned) else None

def sanitize_regex(raw_regex: str) -> Optional[str]:
    if not raw_regex or not isinstance(raw_regex, str):
        return None
    cleaned = raw_regex.strip()
    if not cleaned:
        return None
    try:
        re.compile(cleaned)
        return cleaned
    except re.error:
        logger.warning(f"Invalid regular expression skipped: '{cleaned}'")
        return None

def read_text_file_lines(file_path: Path) -> Set[str]:
    if not file_path.is_file():
        return set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as err:
        logger.error(f"Failed to read file {file_path}: {err}")
        raise

def atomic_write_file(file_path: Path, lines: List[str]) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = file_path.with_suffix(".tmp")
    backup_path = file_path.with_suffix(".bak")

    if file_path.exists():
        shutil.copy2(file_path, backup_path)

    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.writelines(f"{line}\n" for line in lines)
            f.flush()
            os.fsync(f.fileno())

        temp_path.replace(file_path)

        if backup_path.exists():
            backup_path.unlink()

        logger.info(f"Successfully wrote {len(lines)} entries to {file_path}")
    except Exception as err:
        if temp_path.exists():
            temp_path.unlink()
        if backup_path.exists() and not file_path.exists():
            shutil.move(backup_path, file_path)
        logger.error(f"Failed atomic write to {file_path}: {err}")
        raise

def get_default_group_id(cursor: sqlite3.Cursor) -> int:
    cursor.execute("SELECT id FROM 'group' WHERE name = 'Default';")
    row = cursor.fetchone()
    return int(row["id"]) if row else 0

# ------------------------------------------------------------------------------
# Core Processing Steps
# ------------------------------------------------------------------------------
@retry_on_db_lock()
def step_1_process_exact_blocked_domains(conn: sqlite3.Connection) -> None:
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
        domain_id = row["id"]
        if sanitized := sanitize_domain(row["domain"]):
            extracted_domains.add(sanitized)
            domain_ids_to_delete.append(domain_id)

    logger.info(f"Step 1 DB query yielded {len(extracted_domains)} matching domains.")

    existing_domains = read_text_file_lines(BLACKLIST_FILE)
    sanitized_existing = {s for line in existing_domains if (s := sanitize_domain(line))}
    combined_set = extracted_domains.union(sanitized_existing)
    
    if extracted_domains or not BLACKLIST_FILE.exists():
        atomic_write_file(BLACKLIST_FILE, sorted(combined_set))

    if domain_ids_to_delete:
        logger.info(f"Deleting {len(domain_ids_to_delete)} transferred entries from gravity.db...")
        chunk_size = 500
        with conn:
            for i in range(0, len(domain_ids_to_delete), chunk_size):
                chunk = domain_ids_to_delete[i:i + chunk_size]
                placeholders = ",".join(["?"] * len(chunk))
                cursor.execute(f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({placeholders});", tuple(chunk))
                cursor.execute(f"DELETE FROM domainlist WHERE id IN ({placeholders});", tuple(chunk))
        logger.info("Step 1 database purge completed successfully.")

@retry_on_db_lock()
def step_2_process_regex_deny(conn: sqlite3.Connection) -> None:
    logger.info("Starting Step 2: Regex deny rules processing...")
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM 'group' WHERE LOWER(name) = 'healthcheck';")
    healthcheck_row = cursor.fetchone()
    healthcheck_id = healthcheck_row["id"] if healthcheck_row else None

    if healthcheck_id is not None:
        query = """
            SELECT DISTINCT d.domain
            FROM domainlist d
            WHERE d.type = 3
              AND d.id NOT IN (
                  SELECT domainlist_id FROM domainlist_by_group WHERE group_id = ?
              )
        """
        cursor.execute(query, (healthcheck_id,))
    else:
        cursor.execute("SELECT DISTINCT domain FROM domainlist WHERE type = 3;")

    rows = cursor.fetchall()
    processed_regexes = {sanitized for row in rows if (sanitized := sanitize_regex(row["domain"]))}

    atomic_write_file(REGEX_FILE, sorted(processed_regexes))
    logger.info(f"Step 2 completed. {len(processed_regexes)} regex entries saved.")

@retry_on_db_lock()
def step_3_purge_empty_blocklists(conn: sqlite3.Connection) -> None:
    logger.info("Starting Step 3: Empty blocklists purge verification...")
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(adlist);")
    columns = [col["name"] for col in cursor.fetchall()]
    type_filter = " AND a.type = 0" if "type" in columns else ""

    empty_candidates_query = f"""
        SELECT a.id 
        FROM adlist a 
        WHERE a.id NOT IN (
            SELECT DISTINCT adlist_id 
            FROM gravity 
            WHERE adlist_id IS NOT NULL
        ) {type_filter};
    """
    cursor.execute(empty_candidates_query)
    empty_ids = [row["id"] for row in cursor.fetchall()]

    if not empty_ids:
        logger.info("Step 3: No empty blocklists found.")
        return

    logger.info(f"Purging {len(empty_ids)} empty blocklists from database...")
    chunk_size = 500
    with conn:
        for i in range(0, len(empty_ids), chunk_size):
            chunk = empty_ids[i:i + chunk_size]
            placeholders = ",".join(["?"] * len(chunk))
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders});", tuple(chunk))
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({placeholders});", tuple(chunk))
    logger.info(f"Step 3 completed. Purged {len(empty_ids)} empty adlists.")

@retry_on_db_lock()
def step_4_process_minor_blocklists(conn: sqlite3.Connection) -> None:
    logger.info("Starting Step 4: Minor blocklists extraction...")
    cursor = conn.cursor()
    default_group_id = get_default_group_id(cursor)

    query_exclusive_default = """
        SELECT adlist_id 
        FROM adlist_by_group 
        GROUP BY adlist_id 
        HAVING COUNT(DISTINCT group_id) = 1 AND MAX(group_id) = ?
    """
    cursor.execute(query_exclusive_default, (default_group_id,))
    exclusive_adlist_ids = [row["adlist_id"] for row in cursor.fetchall()]

    if not exclusive_adlist_ids:
        logger.info("Step 4: No exclusive default group lists found.")
        return

    minor_candidates: Set[int] = set()
    chunk_size = 500
    for i in range(0, len(exclusive_adlist_ids), chunk_size):
        chunk = exclusive_adlist_ids[i:i + chunk_size]
        placeholders = ",".join(["?"] * len(chunk))
        batch_count_query = f"""
            SELECT adlist_id
            FROM gravity 
            WHERE adlist_id IN ({placeholders}) 
            GROUP BY adlist_id 
            HAVING COUNT(*) BETWEEN 1 AND 100;
        """
        cursor.execute(batch_count_query, tuple(chunk))
        minor_candidates.update(row["adlist_id"] for row in cursor.fetchall())

    if not minor_candidates:
        logger.info("Step 4: No minor lists with 1 to 100 domains identified.")
        return

    logger.info(f"Identified {len(minor_candidates)} minor lists. Extracting domains...")
    minor_candidates_list = list(minor_candidates)
    minor_adlist_urls: Set[str] = set()
    extracted_domains: Set[str] = set()

    for i in range(0, len(minor_candidates_list), chunk_size):
        chunk = minor_candidates_list[i:i + chunk_size]
        placeholders = ",".join(["?"] * len(chunk))

        cursor.execute(f"SELECT address FROM adlist WHERE id IN ({placeholders});", tuple(chunk))
        minor_adlist_urls.update(row["address"].strip() for row in cursor.fetchall() if row["address"])

        cursor.execute(f"SELECT domain FROM gravity WHERE adlist_id IN ({placeholders});", tuple(chunk))
        for row in cursor.fetchall():
            if sanitized := sanitize_domain(row["domain"]):
                extracted_domains.add(sanitized)

    if extracted_domains:
        logger.info(f"Extracted {len(extracted_domains)} domains from {len(minor_adlist_urls)} minor lists.")

        existing_minor_urls = read_text_file_lines(MINOR_LISTS_FILE)
        combined_minor_urls = existing_minor_urls.union(minor_adlist_urls)
        atomic_write_file(MINOR_LISTS_FILE, sorted(combined_minor_urls))

        existing_extra_domains = read_text_file_lines(EXTRA_FILE)
        sanitized_existing_extra = {s for line in existing_extra_domains if (s := sanitize_domain(line))}
        combined_extra_domains = sanitized_existing_extra.union(extracted_domains)
        
        atomic_write_file(EXTRA_FILE, sorted(combined_extra_domains))
        logger.info("Step 4 minor blocklist extraction completed.")

@retry_on_db_lock()
def step_5_purge_minor_blocklists_from_db(conn: sqlite3.Connection) -> None:
    logger.info("Starting Step 5: Purging minor blocklists from database in-place...")
    minor_urls = list(read_text_file_lines(MINOR_LISTS_FILE))

    if not minor_urls:
        logger.info("No minor list URLs found to purge.")
        return

    cursor = conn.cursor()
    chunk_size = 500
    all_target_ids: List[int] = []

    for i in range(0, len(minor_urls), chunk_size):
        chunk = minor_urls[i:i + chunk_size]
        placeholders = ",".join(["?"] * len(chunk))
        cursor.execute(f"SELECT id FROM adlist WHERE TRIM(address) IN ({placeholders});", tuple(chunk))
        all_target_ids.extend([row["id"] for row in cursor.fetchall()])

    if not all_target_ids:
        logger.info("Step 5: No matching adlist IDs found in database for deletion.")
        return

    logger.info(f"Executing purge for {len(all_target_ids)} minor adlists...")

    with conn:
        for i in range(0, len(all_target_ids), chunk_size):
            chunk = all_target_ids[i:i + chunk_size]
            placeholders = ",".join(["?"] * len(chunk))
            cursor.execute(f"DELETE FROM gravity WHERE adlist_id IN ({placeholders});", tuple(chunk))
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders});", tuple(chunk))
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({placeholders});", tuple(chunk))

    logger.info(f"Step 5 completed. Purged {len(all_target_ids)} matching minor adlists.")

def step_6_git_commit_and_push() -> None:
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
            ["git", "pull", "--rebase"],
            cwd=str(BASE_DIR),
            check=False,
            timeout=15,
            capture_output=True,
            text=True
        )
        
        if pull_run.returncode != 0:
            logger.error(f"Git pull failed or conflicted. Aborting commit to protect repository state. Details: {pull_run.stderr}")
            return

        status_output = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(BASE_DIR),
            text=True,
            timeout=15
        )

        if not status_output.strip():
            logger.info("No changes detected in Git repository. Skipping commit/push.")
            return

        subprocess.run(
            ["git", "add", "blacklists/", "regex/", "minor-lists.txt"],
            cwd=str(BASE_DIR),
            check=True,
            timeout=15,
            capture_output=True
        )

        staged_status = subprocess.check_output(
            ["git", "diff", "--staged", "--name-only"],
            cwd=str(BASE_DIR),
            text=True,
            timeout=15
        )

        if not staged_status.strip():
            logger.info("No staged changes to commit. Skipping commit.")
            return

        subprocess.run(
            ["git", "commit", "-m", hex_commit_msg],
            cwd=str(BASE_DIR),
            check=True,
            timeout=15,
            capture_output=True
        )

        subprocess.run(
            ["git", "push"],
            cwd=str(BASE_DIR),
            check=True,
            timeout=30,
            capture_output=True,
            text=True
        )
        logger.info("Git push executed successfully.")

    except subprocess.TimeoutExpired as err:
        logger.error(f"Git execution timed out: {err}")
    except subprocess.CalledProcessError as err:
        logger.error(f"Git execution failed: {err.stderr or err.output}")

def restart_pihole_services() -> None:
    logger.info("Checking Pi-hole Docker container status...")
    
    if not shutil.which("docker"):
        logger.warning("Docker executable not found in PATH. Skipping DNS restart.")
        return
        
    try:
        check_running = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Running}}", "pihole"],
            text=True,
            timeout=10,
            stderr=subprocess.STDOUT
        ).strip()

        if check_running != "true":
            logger.warning("Pi-hole Docker container is not running. Skipping DNS restart.")
            return

        logger.info("Restarting Pi-hole DNS engine via Docker...")
        subprocess.run(
            ["docker", "exec", "pihole", "pihole", "restartdns"], 
            check=True,
            timeout=30,
            capture_output=True,
            text=True
        )
        logger.info("Pi-hole DNS engine restarted successfully.")
    except subprocess.TimeoutExpired:
        logger.error("Docker command timed out.")
    except subprocess.CalledProcessError as err:
        logger.error(f"Failed to restart Pi-hole via docker exec: {err.output}")
    except Exception as err:
        logger.warning(f"Unexpected error restarting Pi-hole: {err}")

# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------
def main() -> None:
    logger.info("Initializing Gravity Database Extraction and Maintenance Pipeline.")

    BLACKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    REGEX_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with get_db_connection(DB_PATH) as conn:
            step_1_process_exact_blocked_domains(conn)
            step_2_process_regex_deny(conn)
            step_3_purge_empty_blocklists(conn)
            step_4_process_minor_blocklists(conn)
            step_5_purge_minor_blocklists_from_db(conn)

        restart_pihole_services()
        step_6_git_commit_and_push()

        logger.info("Pipeline execution finished cleanly and successfully.")
        sys.exit(0)

    except Exception as fatal_err:
        logger.critical(f"Fatal error encountered during pipeline execution: {fatal_err}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
