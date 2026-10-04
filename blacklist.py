#!/usr/bin/env python3
"""
Pi-hole Gravity Database Manager & Blacklist Migrator
Enterprise-Grade Release
"""

import sqlite3
import re
import logging
import subprocess
import os
import secrets
import fcntl
from pathlib import Path
from typing import FrozenSet, List
from contextlib import closing

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- CONFIGURATION & PATHS ---
SCRIPT_DIR = Path(__file__).parent.resolve()
DB_PATH = Path(os.getenv("PIHOLE_DB_PATH", "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"))

BLACKLIST_FILE = SCRIPT_DIR / "blacklist.txt"
MINOR_LISTS_FILE = SCRIPT_DIR / "minor_lists.txt"
EXTRA_BLACKLIST_FILE = SCRIPT_DIR / "blacklist-extra.txt"

LOCK_FILE = SCRIPT_DIR / ".blacklist_manager.lock"

CMD_TIMEOUT = 30
FILE_PERMISSIONS = 0o644

DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,63}$'
)

# --- LOGGING SETUP ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] %(message)s')

# Console Handler
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

# --- INFRASTRUCTURE & SAFETY UTILITIES ---

def acquire_exclusive_lock():
    """Prevents overlapping executions which could corrupt the SQLite DB."""
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_fd
    except BlockingIOError:
        logger.critical("Another instance of the script is currently running. Exiting to prevent corruption.")
        exit(1)

def get_db_connection() -> sqlite3.Connection:
    """Establish a secure SQLite3 connection with lock-wait timeouts."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;") 
    return conn

def get_http_session() -> requests.Session:
    """Creates an HTTP session with exponential backoff."""
    session = requests.Session()
    retries = Retry(
        total=4,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retries)
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
    except IOError as e:
        logger.error(f"Failed to read {filepath.name}: {e}")
        return frozenset()

def write_frozenset_to_file(domains: FrozenSet[str], filepath: Path) -> None:
    """Atomic write operation with strict permission enforcements."""
    sorted_domains = sorted(domains)
    temp_filepath = filepath.with_suffix('.tmp')
    
    try:
        with open(temp_filepath, 'w', encoding='utf-8') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")
        
        # Enforce secure file permissions before replacing
        os.chmod(temp_filepath, FILE_PERMISSIONS)
        temp_filepath.replace(filepath)
        logger.info(f"Successfully saved {len(sorted_domains)} entries to {filepath.name}")
    except IOError as e:
        logger.error(f"Failed to write to {filepath.name}: {e}")
        if temp_filepath.exists():
            temp_filepath.unlink(missing_ok=True)
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
        else:
            logger.warning(f"Domain '{domain}' (ID: {row_id}) failed validation. Kept in DB.")

    if not db_frozenset_items:
        logger.info("No matching blacklist entries found in database.")

    local_frozenset = load_local_file(BLACKLIST_FILE)
    merged_frozenset = frozenset(db_frozenset_items | local_frozenset)
    write_frozenset_to_file(merged_frozenset, BLACKLIST_FILE)
    
    if db_ids_to_delete:
        try:
            cursor.execute(f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({','.join('?'*len(db_ids_to_delete))})", db_ids_to_delete)
            cursor.execute(f"DELETE FROM domainlist WHERE id IN ({','.join('?'*len(db_ids_to_delete))})", db_ids_to_delete)
            conn.commit()
            logger.info(f"Deleted {len(db_ids_to_delete)} migrated entries from database.")
        except sqlite3.Error as e:
            conn.rollback()
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
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
            conn.commit()
            logger.info(f"Safely purged {len(ids_to_delete)} verified empty adlists from database.")
        except sqlite3.Error as e:
            conn.rollback()
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
    except IOError as e:
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
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({','.join('?'*len(adlist_ids_to_delete))})", adlist_ids_to_delete)
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({','.join('?'*len(adlist_ids_to_delete))})", adlist_ids_to_delete)
            conn.commit()
            logger.info(f"Successfully purged {len(adlist_ids_to_delete)} minor lists from gravity database.")
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Database deletion failed for minor lists: {e}")

# --- SYSTEM INTEGRATIONS ---

def reload_ftl_engine() -> None:
    logger.info("Reloading Pi-hole FTL Engine...")
    try:
        subprocess.run(
            ["docker", "exec", "pihole", "pihole", "restartdns", "reload-lists"],
            capture_output=True, text=True, check=True, timeout=CMD_TIMEOUT
        )
        logger.info("FTL Engine reloaded successfully.")
    except Exception as e:
        logger.error(f"Failed to reload FTL engine: {e}")

def push_to_github() -> None:
    logger.info("Starting GitHub Repository Backup...")
    
    expected_files = ["blacklist.txt", "minor_lists.txt", "blacklist-extra.txt"]
    files_to_add = [f for f in expected_files if (SCRIPT_DIR / f).exists()]
    
    if not files_to_add:
        logger.info("No target text files currently exist to commit.")
        return

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"] + files_to_add, 
            cwd=SCRIPT_DIR, capture_output=True, text=True, check=True, timeout=CMD_TIMEOUT
        )
        
        if not status.stdout.strip():
            logger.info("No changes detected in target list files. Skipping GitHub push.")
            return

        commit_msg = secrets.token_hex(4)
        subprocess.run(["git", "add"] + files_to_add, cwd=SCRIPT_DIR, check=True, capture_output=True, timeout=CMD_TIMEOUT)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=SCRIPT_DIR, check=True, capture_output=True, timeout=CMD_TIMEOUT)
        subprocess.run(["git", "push"], cwd=SCRIPT_DIR, check=True, capture_output=True, timeout=CMD_TIMEOUT)
        
        logger.info(f"Successfully pushed updates to GitHub with commit: {commit_msg}")
        
    except subprocess.CalledProcessError as e:
        stdout_msg = e.stdout.decode('utf-8', errors='ignore').strip() if isinstance(e.stdout, bytes) else str(e.stdout or '')
        stderr_msg = e.stderr.decode('utf-8', errors='ignore').strip() if isinstance(e.stderr, bytes) else str(e.stderr or '')
        logger.error(f"GitHub push failed. Git error -> stderr: '{stderr_msg}' | stdout: '{stdout_msg}'")
    except Exception as e:
        logger.error(f"Unexpected error during GitHub push: {e}")

# --- ORCHESTRATION ---

def main():
    logger.info("Initiating Pi-hole Gravity Database Manager...")
    lock_fd = acquire_exclusive_lock()
    
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
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
        logger.info("All tasks completed. Lock released.")

if __name__ == "__main__":
    main()
