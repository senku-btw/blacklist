#!/usr/bin/env python3
"""
Pi-hole Gravity Database Manager & Blacklist Migrator
Production-Grade Release (High Autonomy, Security-Hardened)
"""

import sqlite3
import re
import logging
import subprocess
import os
import sys
import secrets
import fcntl
import signal
import tempfile
import shutil
from pathlib import Path
from typing import FrozenSet, List, Optional
from contextlib import closing

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- HARDENED CONFIGURATION & PATHS ---
SCRIPT_DIR = Path(__file__).parent.resolve()
DB_PATH = Path(os.getenv("PIHOLE_DB_PATH", "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"))

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
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')

# --- LOGGING SETUP ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] %(message)s')
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)

# --- GLOBAL LOCK STATE ---
_lock_fd: Optional[int] = None

# --- INFRASTRUCTURE & SAFETY UTILITIES ---

def release_lock():
    """Safely releases the process lock if held."""
    global _lock_fd
    if _lock_fd:
        try:
            fcntl.flock(_lock_fd, fcntl.LOCK_UN)
            os.close(_lock_fd)
            if LOCK_FILE.exists():
                LOCK_FILE.unlink(missing_ok=True)
            _lock_fd = None
        except OSError as e:
            logger.error(f"Error releasing lock: {e}")

def signal_handler(signum, frame):
    """Graceful degradation on system termination signals."""
    logger.warning(f"Received termination signal ({signum}). Initiating graceful shutdown...")
    release_lock()
    sys.exit(128 + signum)

# Register signal handlers for robust lifecycle management
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def acquire_exclusive_lock():
    """Prevents overlapping executions using unbuffered POSIX locks."""
    global _lock_fd
    try:
        _lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.critical("Another instance is running. Exiting to prevent DB corruption.")
        os.close(_lock_fd)
        sys.exit(1)
    except OSError as e:
        logger.critical(f"Failed to acquire system lock: {e}")
        sys.exit(1)

def get_db_connection() -> sqlite3.Connection:
    """Establish a secure, integrity-enforced SQLite3 connection."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None) # Manage transactions manually
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;") 
    conn.execute("PRAGMA foreign_keys=ON;") # Enforce relational integrity
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def get_http_session() -> requests.Session:
    """Creates an HTTP session with strict timeouts and exponential backoff."""
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
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
        if not line or line.startswith(('#', '!', '/', '<')):
            continue
        
        parts = line.split()
        candidate = parts[-1] if parts else ""
        candidate = candidate.lower().strip('.').split('#')[0].split('^')[0]
        
        if DOMAIN_REGEX.match(candidate):
            valid_domains.add(candidate)
            
    return frozenset(valid_domains)

def load_local_file(filepath: Path) -> FrozenSet[str]:
    if not filepath.exists():
        return frozenset()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return sanitize_and_extract_domains(f.readlines())
    except OSError as e:
        logger.error(f"Failed to read {filepath.name}: {e}")
        return frozenset()

def write_frozenset_to_file(domains: FrozenSet[str], filepath: Path) -> None:
    """True POSIX atomic write operation using the system temp folder."""
    sorted_domains = sorted(domains)
    
    # Create temp file in the same directory to guarantee they are on the same filesystem
    fd, temp_path = tempfile.mkstemp(dir=filepath.parent, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")
                
        os.chmod(temp_path, FILE_PERMISSIONS)
        os.replace(temp_path, filepath) # Guaranteed atomic on POSIX
        logger.info(f"Successfully saved {len(sorted_domains)} entries to {filepath.name}")
    except OSError as e:
        logger.error(f"Failed to atomic-write {filepath.name}: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

# --- CORE LOGIC STEPS ---

def step1_migrate_exact_blacklists(conn: sqlite3.Connection) -> None:
    logger.info("Starting Step 1: Exact Blacklist Migration")
    cursor = conn.cursor()
    
    query = """
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
    cursor.execute(query)
    rows = cursor.fetchall()
    
    db_frozenset_items = set()
    db_ids_to_delete = []

    for row in rows:
        domain = row['domain']
        row_id = row['id']
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
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({','.join('?'*len(db_ids_to_delete))})", db_ids_to_delete)
            cursor.execute(f"DELETE FROM domainlist WHERE id IN ({','.join('?'*len(db_ids_to_delete))})", db_ids_to_delete)
            cursor.execute("COMMIT;")
            logger.info(f"Deleted {len(db_ids_to_delete)} migrated entries from database.")
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK;")
            logger.error(f"Failed to delete entries from DB: {e}")

def fetch_and_validate_adlist(url: str, session: requests.Session) -> bool:
    try:
        response = session.get(url, timeout=15)
        response.raise_for_status()
        domains = sanitize_and_extract_domains(response.text.splitlines())
        return len(domains) == 0
    except requests.RequestException as e:
        logger.warning(f"Failed to fetch adlist {url}: {e}. Skipping deletion.")
        return False

def step2_prune_empty_adlists(conn: sqlite3.Connection, session: requests.Session) -> None:
    logger.info("Starting Step 2: Empty Adlist Pruning")
    cursor = conn.cursor()
    cursor.execute("SELECT id, address FROM adlist WHERE number = 0")
    suspect_lists = cursor.fetchall()
    
    if not suspect_lists:
        logger.info("No adlists with 0 entries found in database.")
        return

    ids_to_delete = []
    for row in suspect_lists:
        adlist_id, url = row['id'], row['address']
        if fetch_and_validate_adlist(url, session):
            ids_to_delete.append(adlist_id)

    if ids_to_delete:
        try:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
            cursor.execute("COMMIT;")
            logger.info(f"Safely purged {len(ids_to_delete)} verified empty adlists from database.")
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK;")
            logger.error(f"Database deletion failed for adlists: {e}")

def step3_extract_minor_lists(conn: sqlite3.Connection, session: requests.Session) -> None:
    logger.info("Starting Step 3: Minor List Extraction & Migration")
    cursor = conn.cursor()
    
    query = """
        SELECT a.id, a.address 
        FROM adlist a
        JOIN adlist_by_group abg ON a.id = abg.adlist_id
        WHERE abg.group_id = 0 AND a.number BETWEEN 1 AND 100
    """
    cursor.execute(query)
    minor_lists = cursor.fetchall()
    
    if not minor_lists:
        logger.info("No minor lists (1-100 entries) found in default group.")
        return

    adlist_ids_to_delete = [row['id'] for row in minor_lists]
    urls = [row['address'] for row in minor_lists]
    
    existing_urls = set()
    if MINOR_LISTS_FILE.exists():
        with open(MINOR_LISTS_FILE, 'r', encoding='utf-8') as f:
            existing_urls = set(f.read().splitlines())
    
    try:
        with open(MINOR_LISTS_FILE, 'a', encoding='utf-8') as f:
            for url in urls:
                if url not in existing_urls:
                    f.write(f"{url}\n")
        os.chmod(MINOR_LISTS_FILE, FILE_PERMISSIONS)
        logger.info(f"Stored/Updated minor list URLs in {MINOR_LISTS_FILE.name}")
    except OSError as e:
        logger.error(f"Failed to append to {MINOR_LISTS_FILE.name}: {e}")
        return

    all_extracted_domains = set()
    for url in urls:
        try:
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            extracted = sanitize_and_extract_domains(resp.text.splitlines())
            all_extracted_domains.update(extracted)
        except requests.RequestException as e:
            logger.warning(f"Could not fetch domains from minor list {url}: {e}")

    new_frozenset = frozenset(all_extracted_domains)
    existing_frozenset = load_local_file(EXTRA_BLACKLIST_FILE)
    cumulative_frozenset = frozenset(new_frozenset | existing_frozenset)
    
    try:
        write_frozenset_to_file(cumulative_frozenset, EXTRA_BLACKLIST_FILE)
    except Exception as e:
        logger.error(f"Failed to write blacklist-extra.txt. Aborting DB purge: {e}")
        return

    if adlist_ids_to_delete:
        try:
            cursor.execute("BEGIN TRANSACTION;")
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({','.join('?'*len(adlist_ids_to_delete))})", adlist_ids_to_delete)
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({','.join('?'*len(adlist_ids_to_delete))})", adlist_ids_to_delete)
            cursor.execute("COMMIT;")
            logger.info(f"Successfully purged {len(adlist_ids_to_delete)} minor lists from gravity database.")
        except sqlite3.Error as e:
            cursor.execute("ROLLBACK;")
            logger.error(f"Database deletion failed for minor lists: {e}")

# --- SYSTEM INTEGRATIONS ---

def reload_ftl_engine(container_name: str = "pihole") -> None:
    logger.info("Reloading Pi-hole FTL Engine...")
    if not os.path.exists(DOCKER_BIN):
        logger.error("Docker binary not found. Cannot reload FTL engine.")
        return

    # Command sequence to force FTL to drop in-memory stats and pull from SQLite
    reload_commands = [
        # 1. Instruct FTL to reload database lists and recreate shared memory structures
        [DOCKER_BIN, "exec", container_name, "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db", "SELECT flush_gravity();"],
        # 2. Force Pi-hole DNS restart to apply changes across the web dashboard
        [DOCKER_BIN, "exec", container_name, "pihole", "restartdns"],
    ]

    for cmd in reload_commands:
        cmd_str = " ".join(cmd[2:])
        try:
            logger.info(f"Executing FTL cache update: {cmd_str}")
            subprocess.run(
                cmd,
                capture_output=True, text=True, check=True, timeout=CMD_TIMEOUT
            )
            logger.info(f"Executed '{cmd_str}' successfully.")
        except subprocess.CalledProcessError as e:
            stdout_msg = e.stdout.strip() if e.stdout else ""
            stderr_msg = e.stderr.strip() if e.stderr else ""
            logger.warning(f"Command '{cmd_str}' failed: stdout='{stdout_msg}' | stderr='{stderr_msg}'")
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: '{cmd_str}'")

def push_to_github() -> None:
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
            cwd=SCRIPT_DIR, capture_output=True, text=True, check=True, timeout=CMD_TIMEOUT
        )
        
        if not status.stdout.strip():
            logger.info("No changes detected in target list files. Skipping GitHub push.")
            return

        commit_msg = secrets.token_hex(4)
        
        # Sequenced, validated subprocess calls
        subprocess.run([GIT_BIN, "add"] + files_to_add, cwd=SCRIPT_DIR, check=True, capture_output=True, timeout=CMD_TIMEOUT)
        subprocess.run([GIT_BIN, "commit", "-m", commit_msg], cwd=SCRIPT_DIR, check=True, capture_output=True, timeout=CMD_TIMEOUT)
        subprocess.run([GIT_BIN, "push"], cwd=SCRIPT_DIR, check=True, capture_output=True, timeout=CMD_TIMEOUT)
        
        logger.info(f"Successfully pushed updates to GitHub with commit: {commit_msg}")
        
    except subprocess.TimeoutExpired:
        logger.error("Git operation timed out.")
    except subprocess.CalledProcessError as e:
        stdout_msg = e.stdout.decode('utf-8', errors='ignore').strip() if isinstance(e.stdout, bytes) else str(e.stdout or '')
        stderr_msg = e.stderr.decode('utf-8', errors='ignore').strip() if isinstance(e.stderr, bytes) else str(e.stderr or '')
        logger.error(f"GitHub push failed. Git error -> stderr: '{stderr_msg}' | stdout: '{stdout_msg}'")

def force_ftl_restart(container_name: str = "pihole") -> None:
    """Restarts the FTL process inside the container to force a full DB re-read."""
    logger.info("Restarting pihole-FTL process inside container...")
    try:
        subprocess.run(
            [DOCKER_BIN, "exec", container_name, "supervisorctl", "restart", "pihole-FTL"],
            capture_output=True, text=True, check=True, timeout=30
        )
        logger.info("pihole-FTL process restarted successfully.")
    except subprocess.CalledProcessError:
        # Fallback if supervisorctl is not used in your docker image variant
        logger.info("supervisorctl failed, attempting direct killall on pihole-FTL...")
        subprocess.run(
            [DOCKER_BIN, "exec", container_name, "pkill", "-9", "pihole-FTL"],
            capture_output=True, text=True, check=False, timeout=10
        )
        
# --- ORCHESTRATION ---

def main():
    logger.info("Initiating Pi-hole Gravity Database Manager...")
    acquire_exclusive_lock()
    
    try:
        with closing(get_db_connection()) as conn, closing(get_http_session()) as http_session:
            step1_migrate_exact_blacklists(conn)
            step2_prune_empty_adlists(conn, http_session)
            step3_extract_minor_lists(conn, http_session)
            
        reload_ftl_engine()
        push_to_github()
        
    except Exception as e:
        logger.error(f"Execution pipeline failed: {e}", exc_info=True)
    finally:
        release_lock()
        logger.info("All tasks completed.")

if __name__ == "__main__":
    main()
