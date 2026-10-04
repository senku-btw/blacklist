#!/usr/bin/env python3
"""
Pi-hole Gravity Database Manager & Blacklist Migrator
Designed for Python 3.8+
"""

import sqlite3
import re
import logging
import subprocess
import requests
import secrets
from pathlib import Path
from typing import FrozenSet, Tuple, List, Optional

# --- CONFIGURATION ---
DB_PATH = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
SCRIPT_DIR = Path(__file__).parent.resolve()

BLACKLIST_FILE = SCRIPT_DIR / "blacklist.txt"
MINOR_LISTS_FILE = SCRIPT_DIR / "minor_lists.txt"
EXTRA_BLACKLIST_FILE = SCRIPT_DIR / "blacklist-extra.txt"

# Domain validation Regex (RFC 1035/1123 compliant)
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'                # First character
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' # Sub domain + hostname
    r'[a-zA-Z]{2,63}$'                # TLD
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(funcName)s] %(message)s'
)
logger = logging.getLogger(__name__)

# --- UTILITY FUNCTIONS ---

def get_db_connection() -> sqlite3.Connection:
    """Establish and return a secure SQLite3 connection."""
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Gravity database not found at {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def sanitize_and_extract_domains(raw_data: List[str]) -> FrozenSet[str]:
    """
    Applies multi-step sanitization to a list of raw string entries.
    Strips hosts file prefixes (0.0.0.0, 127.0.0.1), ignores comments,
    and returns a frozenset of strictly valid domains.
    """
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

def load_local_file_to_frozenset(filepath: Path) -> FrozenSet[str]:
    """Reads a local file and returns sanitized entries as a frozenset."""
    if not filepath.exists():
        return frozenset()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return sanitize_and_extract_domains(f.readlines())
    except Exception as e:
        logger.error(f"Failed to read {filepath}: {e}")
        return frozenset()

def write_frozenset_to_file(domains: FrozenSet[str], filepath: Path) -> None:
    """Alphabetically sorts a frozenset and writes to a file."""
    try:
        sorted_domains = sorted(domains)
        with open(filepath, 'w', encoding='utf-8') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")
        logger.info(f"Successfully saved {len(sorted_domains)} entries to {filepath.name}")
    except Exception as e:
        logger.error(f"Failed to write to {filepath}: {e}")
        raise

# --- STEP 1: BLACKLIST MIGRATION ---

def step1_migrate_exact_blacklists(conn: sqlite3.Connection) -> None:
    """
    Extracts specific exact blacklist entries from gravity.db, validates them,
    merges them with local blacklist.txt, and removes migrated entries from DB.
    Always processes, sanitizes, and deduplicates blacklist.txt on every execution.
    """
    logger.info("Starting Step 1: Exact Blacklist Migration & Maintenance")
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

    if rows:
        for row in rows:
            domain = row['domain']
            row_id = row['id']
            
            sanitized = sanitize_and_extract_domains([domain])
            
            if sanitized:
                db_frozenset_items.update(sanitized)
                db_ids_to_delete.append(row_id)
            else:
                logger.warning(f"Domain '{domain}' (ID: {row_id}) failed regex validation. Keeping in DB.")
    else:
        logger.info("No matching blacklist entries found in database.")

    db_frozenset = frozenset(db_frozenset_items)
    local_frozenset = load_local_file_to_frozenset(BLACKLIST_FILE)
    
    merged_frozenset = frozenset(db_frozenset | local_frozenset)
    write_frozenset_to_file(merged_frozenset, BLACKLIST_FILE)
    
    if db_ids_to_delete:
        try:
            cursor.execute(f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({','.join('?'*len(db_ids_to_delete))})", db_ids_to_delete)
            cursor.execute(f"DELETE FROM domainlist WHERE id IN ({','.join('?'*len(db_ids_to_delete))})", db_ids_to_delete)
            conn.commit()
            logger.info(f"Deleted {len(db_ids_to_delete)} migrated entries from database.")
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to delete entries from DB: {e}")

# --- STEP 2: EMPTY ADLIST PRUNING ---

def fetch_and_validate_adlist(url: str) -> bool:
    """Downloads an adlist and strictly verifies if it contains 0 valid domains."""
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        domains = sanitize_and_extract_domains(response.text.splitlines())
        return len(domains) == 0
    except requests.RequestException as e:
        logger.warning(f"Failed to fetch adlist {url}: {e}. Skipping deletion to be safe.")
        return False

def step2_prune_empty_adlists(conn: sqlite3.Connection) -> None:
    """Finds adlists with 0 entries, verifies they are empty online, and deletes them."""
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
        logger.info(f"Verifying potentially empty adlist: {url}")
        
        if fetch_and_validate_adlist(url):
            logger.info(f"Verified {url} is completely empty.")
            ids_to_delete.append(adlist_id)

    if ids_to_delete:
        try:
            cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
            cursor.execute(f"DELETE FROM adlist WHERE id IN ({','.join('?'*len(ids_to_delete))})", ids_to_delete)
            conn.commit()
            logger.info(f"Safely purged {len(ids_to_delete)} verified empty adlists from database.")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database deletion failed for adlists: {e}")

# --- STEP 3: MINOR LIST EXTRACTION ---

def step3_extract_minor_lists(conn: sqlite3.Connection) -> None:
    """Finds default-group adlists with 1-100 entries, saves them to a unified list, and extracts domains."""
    logger.info("Starting Step 3: Minor List Extraction")
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

    urls = [row['address'] for row in minor_lists]
    
    existing_urls = set()
    if MINOR_LISTS_FILE.exists():
        with open(MINOR_LISTS_FILE, 'r') as f:
            existing_urls = set(f.read().splitlines())
    
    with open(MINOR_LISTS_FILE, 'a') as f:
        for url in urls:
            if url not in existing_urls:
                f.write(f"{url}\n")
    logger.info(f"Stored/Updated minor list URLs in {MINOR_LISTS_FILE.name}")

    all_extracted_domains = set()
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            extracted = sanitize_and_extract_domains(resp.text.splitlines())
            all_extracted_domains.update(extracted)
        except requests.RequestException:
            logger.warning(f"Could not fetch domains from minor list: {url}")

    new_frozenset = frozenset(all_extracted_domains)
    existing_frozenset = load_local_file_to_frozenset(EXTRA_BLACKLIST_FILE)
    
    cumulative_frozenset = frozenset(new_frozenset | existing_frozenset)
    write_frozenset_to_file(cumulative_frozenset, EXTRA_BLACKLIST_FILE)

# --- FINAL STEP: DOCKER RELOAD ---

def reload_ftl_engine() -> None:
    """Triggers the Pi-hole FTL reload via the Docker daemon."""
    logger.info("Reloading Pi-hole FTL Engine...")
    try:
        result = subprocess.run(
            ["docker", "exec", "pihole", "pihole", "restartdns", "reload-lists"],
            capture_output=True, text=True, check=True
        )
        logger.info("FTL Engine reloaded successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to reload FTL engine. Error: {e.stderr.strip()}")
    except FileNotFoundError:
        logger.error("Docker command not found.")

# --- GIT AUTOMATION ---

def push_to_github() -> None:
    """Automates committing and pushing generated lists to GitHub securely."""
    logger.info("Starting GitHub Repository Backup...")
    
    # Generate 8 random hex digits (4 bytes)
    commit_msg = secrets.token_hex(4)
    logger.info(f"Generated secure commit message: {commit_msg}")
    
    try:
        # Check if there are any changes to tracked files
        status = subprocess.run(
            ["git", "status", "--porcelain"], 
            cwd=SCRIPT_DIR, capture_output=True, text=True, check=True
        )
        
        if not status.stdout.strip():
            logger.info("No changes detected in repository. Skipping GitHub push.")
            return

        # 1. Stage the text files explicitly to avoid committing gravity.db accidentally
        files_to_add = ["blacklist.txt", "minor_lists.txt", "blacklist-extra.txt"]
        subprocess.run(["git", "add"] + files_to_add, cwd=SCRIPT_DIR, check=True, capture_output=True)
        
        # 2. Commit the changes
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=SCRIPT_DIR, check=True, capture_output=True)
        
        # 3. Push to remote (requires SSH keys or credentials to be pre-configured)
        subprocess.run(["git", "push"], cwd=SCRIPT_DIR, check=True, capture_output=True)
        
        logger.info(f"Successfully pushed updates to GitHub with commit: {commit_msg}")
        
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else getattr(e, 'output', 'Unknown Git Error')
        logger.error(f"GitHub push failed. Git error: {error_output}")
    except FileNotFoundError:
        logger.error("Git command not found. Ensure git is installed and in the PATH.")

# --- ORCHESTRATION ---

def main():
    logger.info("Initiating Pi-hole Gravity Database Manager...")
    try:
        conn = get_db_connection()
    except Exception as e:
        logger.critical(f"Database connection failed: {e}")
        return

    try:
        step1_migrate_exact_blacklists(conn)
        step2_prune_empty_adlists(conn)
        step3_extract_minor_lists(conn)
    finally:
        conn.close()
        logger.info("Database connection closed securely.")

    reload_ftl_engine()
    push_to_github()
    logger.info("All tasks completed.")

if __name__ == "__main__":
    main()
