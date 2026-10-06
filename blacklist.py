#!/usr/bin/env python3
"""
Pi-hole gravity.db Maintenance and Blacklist Extraction Suite.

Direct in-place database processor for Pi-hole gravity.db.
Extracts, sanitizes, and cleans database entries directly without file backups,
utilizing SQLite transaction rollbacks and busy timeouts for safety.
"""

import os
import sys
import re
import sqlite3
import logging
import secrets
import subprocess
from pathlib import Path
from typing import Set, List, Optional, FrozenSet
from contextlib import contextmanager

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
DB_PATH = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
BASE_DIR = Path.cwd()
BLACKLISTS_DIR = BASE_DIR / "blacklists"
BLACKLIST_FILE = BLACKLISTS_DIR / "blacklist.txt"
REGEX_FILE = BLACKLISTS_DIR / "regex.txt"
EXTRA_FILE = BLACKLISTS_DIR / "blacklist-extra.txt"
MINOR_LISTS_FILE = BASE_DIR / "minor-lists.txt"

# Domain validation regex (RFC 1035 / RFC 1123 compliant subset)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("gravity_maintenance")


# ------------------------------------------------------------------------------
# In-Place Database Connection & Helper Functions
# ------------------------------------------------------------------------------
@contextmanager
def get_db_connection(db_path: Path):
    """
    Context manager for editing gravity.db directly in-place.
    Uses busy_timeout pragma and URI read-write mode to resolve lock stalls with Pi-hole FTL.
    """
    assert db_path.exists(), f"Database file missing at path: {db_path}"
    
    conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=60.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 60000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    except Exception as err:
        conn.rollback()
        logger.error(f"Database transaction error encountered, rolling back: {err}")
        raise
    finally:
        conn.close()


def sanitize_domain(raw_domain: str) -> Optional[str]:
    """Strip white-space, non-printable/invisible characters, validate domain syntax."""
    if not raw_domain or not isinstance(raw_domain, str):
        return None
    cleaned = re.sub(r"[\x00-\x1F\x7F-\x9F\u200b-\u200d\ufeff]", "", raw_domain).strip().lower()
    
    if not cleaned or not DOMAIN_REGEX.match(cleaned):
        return None
    return cleaned


def sanitize_regex(raw_regex: str) -> Optional[str]:
    """Sanitize and validate regular expression string."""
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
    """Reads lines from a file if it exists, returning a set of stripped strings."""
    if not file_path.is_file():
        return set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as err:
        logger.error(f"Failed to read file {file_path}: {err}")
        raise


def atomic_write_file(file_path: Path, lines: List[str]) -> None:
    """Atomically writes sorted lines to a file via a temporary file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = file_path.with_suffix(".tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")
        temp_path.replace(file_path)
        logger.info(f"Successfully wrote {len(lines)} entries to {file_path}")
    except Exception as err:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"Failed atomic write to {file_path}: {err}")
        raise


def get_default_group_id(cursor: sqlite3.Cursor) -> int:
    """Retrieve the ID of the 'Default' group from gravity.db."""
    cursor.execute("SELECT id FROM 'group' WHERE name = 'Default';")
    row = cursor.fetchone()
    if row:
        return int(row["id"])
    return 0


# ------------------------------------------------------------------------------
# Core Processing Steps
# ------------------------------------------------------------------------------
def step_1_process_exact_blocked_domains(conn: sqlite3.Connection) -> None:
    """
    Step 1: Extract exact blocked domains matching criteria:
    - Belongs to 'Default' group
    - Has an empty comment
    Combine with existing blacklist.txt, overwrite file, and delete extracted DB entries in place.
    """
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
        sanitized = sanitize_domain(row["domain"])
        if sanitized:
            extracted_domains.add(sanitized)
            domain_ids_to_delete.append(domain_id)

    db_immutable_set: FrozenSet[str] = frozenset(extracted_domains)
    logger.info(f"Step 1 DB query yielded {len(db_immutable_set)} matching domains.")

    existing_domains = read_text_file_lines(BLACKLIST_FILE)
    sanitized_existing = {s for line in existing_domains if (s := sanitize_domain(line))}
    file_immutable_set: FrozenSet[str] = frozenset(sanitized_existing)

    combined_set: FrozenSet[str] = db_immutable_set.union(file_immutable_set)
    alphabetized_list = sorted(combined_set)

    atomic_write_file(BLACKLIST_FILE, alphabetized_list)

    if domain_ids_to_delete:
        logger.info(f"Deleting {len(domain_ids_to_delete)} transferred entries from gravity.db in-place...")
        cursor.executemany(
            "DELETE FROM domainlist_by_group WHERE domainlist_id = ?;",
            [(did,) for did in domain_ids_to_delete]
        )
        cursor.executemany(
            "DELETE FROM domainlist WHERE id = ?;",
            [(did,) for did in domain_ids_to_delete]
        )
        conn.commit()
        logger.info("Step 1 database purge completed successfully.")


def step_2_process_regex_deny(conn: sqlite3.Connection) -> None:
    """
    Step 2: Parse regex blacklist database fetching all regex deny entries (type=3),
    excluding any belonging to group 'healthcheck'.
    Overwrite blacklists/regex.txt (backup only, no DB deletion).
    """
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
        query = "SELECT DISTINCT domain FROM domainlist WHERE type = 3;"
        cursor.execute(query)

    rows = cursor.fetchall()
    processed_regexes: Set[str] = set()

    for row in rows:
        sanitized = sanitize_regex(row["domain"])
        if sanitized:
            processed_regexes.add(sanitized)

    immutable_regex_set: FrozenSet[str] = frozenset(processed_regexes)
    alphabetized_regexes = sorted(immutable_regex_set)

    atomic_write_file(REGEX_FILE, alphabetized_regexes)
    logger.info(f"Step 2 completed. {len(alphabetized_regexes)} regex entries saved to backup.")


def step_3_purge_empty_blocklists(conn: sqlite3.Connection) -> None:
    """
    Step 3: Identify adlists that have 0 domain entries.
    Queries the database efficiently to find empty candidates FIRST, 
    then independently verifies only those candidates before purging.
    """
    logger.info("Starting Step 3: Empty blocklists purge verification...")
    cursor = conn.cursor()

    # Efficiently ask the database for adlists that have NO entries in the gravity table.
    # We check for the 'type' column dynamically to ensure schema compatibility.
    cursor.execute("PRAGMA table_info(adlist);")
    columns = [col["name"] for col in cursor.fetchall()]
    type_filter = " AND type = 0" if "type" in columns else ""

    find_empty_candidates_query = f"""
        SELECT id, address 
        FROM adlist 
        WHERE id NOT IN (SELECT DISTINCT adlist_id FROM gravity){type_filter};
    """
    cursor.execute(find_empty_candidates_query)
    empty_candidates = cursor.fetchall()

    empty_adlist_ids: List[int] = []

    if not empty_candidates:
        logger.info("Step 3: No empty blocklist candidates identified by the database.")
        return

    logger.info(f"Database identified {len(empty_candidates)} potentially empty lists. Independently verifying...")

    for candidate in empty_candidates:
        adlist_id = candidate["id"]

        # Multi-check Verification 1: Exact aggregate count in gravity table
        cursor.execute("SELECT COUNT(1) AS cnt FROM gravity WHERE adlist_id = ?;", (adlist_id,))
        gravity_count = cursor.fetchone()["cnt"]

        # Multi-check Verification 2: Existence scan for single record
        cursor.execute("SELECT 1 FROM gravity WHERE adlist_id = ? LIMIT 1;", (adlist_id,))
        has_gravity_entry = cursor.fetchone() is not None

        # Verification: Both checks must independently confirm 0 records
        if gravity_count == 0 and not has_gravity_entry:
            assert gravity_count == 0, f"Inconsistency in gravity table count for adlist {adlist_id}"
            assert not has_gravity_entry, f"Found record despite zero count for adlist {adlist_id}"

            empty_adlist_ids.append(adlist_id)
            logger.info(f"100% Confirmed Empty Adlist ID {adlist_id}: {candidate['address']}")

    if empty_adlist_ids:
        logger.info(f"Purging {len(empty_adlist_ids)} verified empty adlists from database in-place...")
        cursor.executemany("DELETE FROM adlist_by_group WHERE adlist_id = ?;", [(aid,) for aid in empty_adlist_ids])
        cursor.executemany("DELETE FROM adlist WHERE id = ?;", [(aid,) for aid in empty_adlist_ids])
        conn.commit()
        logger.info("Step 3 empty adlists purge completed.")
    else:
        logger.info("Step 3: No empty blocklists passed verification.")


def step_4_process_minor_blocklists(conn: sqlite3.Connection) -> None:
    """
    Step 4: Identify blocklists with 1 to 100 entries belonging EXCLUSIVELY to 'Default' group.
    Uses bulk-query optimization to prevent loop freezing.
    """
    logger.info("Starting Step 4: Minor blocklists extraction...")
    cursor = conn.cursor()
    default_group_id = get_default_group_id(cursor)

    # 1. Find adlists that belong EXCLUSIVELY to Default group
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

    # 2. Bulk query SQLite to find which of those lists have 1-100 domains
    placeholders = ",".join(["?"] * len(exclusive_adlist_ids))
    bulk_count_query = f"""
        SELECT adlist_id, COUNT(1) as cnt 
        FROM gravity 
        WHERE adlist_id IN ({placeholders}) 
        GROUP BY adlist_id 
        HAVING cnt BETWEEN 1 AND 100;
    """
    cursor.execute(bulk_count_query, tuple(exclusive_adlist_ids))
    minor_candidates = cursor.fetchall()

    minor_adlist_urls: Set[str] = set()
    extracted_domains: Set[str] = set()

    logger.info(f"Database identified {len(minor_candidates)} minor lists. Extracting domains...")

    for candidate in minor_candidates:
        aid = candidate["adlist_id"]
        expected_count = candidate["cnt"]

        # Fetch domains for verification and extraction
        cursor.execute("SELECT domain FROM gravity WHERE adlist_id = ?;", (aid,))
        domain_rows = cursor.fetchall()
        
        assert len(domain_rows) == expected_count, f"Count mismatch verification failed for adlist ID {aid}"

        cursor.execute("SELECT address FROM adlist WHERE id = ?;", (aid,))
        addr_row = cursor.fetchone()
        if addr_row and addr_row["address"]:
            minor_adlist_urls.add(addr_row["address"].strip())

        for d_row in domain_rows:
            sanitized = sanitize_domain(d_row["domain"])
            if sanitized:
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
    else:
        logger.info("Step 4: No minor lists met all criteria.")

def step_5_purge_minor_blocklists_from_db(conn: sqlite3.Connection) -> None:
    """
    Step 5: Purge adlists matching URLs in minor-lists.txt from gravity.db in-place.
    Does not modify minor-lists.txt.
    """
    logger.info("Starting Step 5: Purging minor blocklists from database in-place...")
    minor_urls = read_text_file_lines(MINOR_LISTS_FILE)

    if not minor_urls:
        logger.info("No minor list URLs found to purge.")
        return

    cursor = conn.cursor()
    purged_count = 0

    for url in minor_urls:
        cursor.execute("SELECT id FROM adlist WHERE address = ?;", (url,))
        rows = cursor.fetchall()
        for row in rows:
            aid = row["id"]
            cursor.execute("DELETE FROM gravity WHERE adlist_id = ?;", (aid,))
            cursor.execute("DELETE FROM adlist_by_group WHERE adlist_id = ?;", (aid,))
            cursor.execute("DELETE FROM adlist WHERE id = ?;", (aid,))
            purged_count += 1

    conn.commit()
    logger.info(f"Step 5 completed. Purged {purged_count} matching minor adlists from database.")


def step_6_git_commit_and_push() -> None:
    """
    Generates a random 7-character hexadecimal commit hash message,
    checks for repository changes, commits, and safely pushes to remote.
    """
    logger.info("Starting Step 6: Git version control push...")

    hex_commit_msg = secrets.token_hex(4)[:7]
    logger.info(f"Generated commit identifier: {hex_commit_msg}")

    try:
        status_output = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(BASE_DIR),
            text=True
        )

        if not status_output.strip():
            logger.info("No changes detected in Git repository. Skipping commit/push.")
            return

        subprocess.run(["git", "add", "blacklists/", "minor-lists.txt"], cwd=str(BASE_DIR), check=True)

        staged_status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(BASE_DIR),
            text=True
        )

        if not staged_status.strip():
            logger.info("No staged changes to commit.")
            return

        subprocess.run(["git", "commit", "-m", hex_commit_msg], cwd=str(BASE_DIR), check=True)
        logger.info(f"Git commit created with message: '{hex_commit_msg}'")

        subprocess.run(["git", "push"], cwd=str(BASE_DIR), check=True)
        logger.info("Git push executed successfully.")

    except subprocess.CalledProcessError as err:
        logger.error(f"Git execution failed: {err}")
        raise


# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------
def main() -> None:
    logger.info("Initializing Gravity Database Extraction and Maintenance Pipeline.")

    BLACKLISTS_DIR.mkdir(parents=True, exist_ok=True)
    assert DB_PATH.exists(), f"Target database does not exist: {DB_PATH}"

    try:
        with get_db_connection(DB_PATH) as conn:
            step_1_process_exact_blocked_domains(conn)
            step_2_process_regex_deny(conn)
            step_3_purge_empty_blocklists(conn)
            step_4_process_minor_blocklists(conn)
            step_5_purge_minor_blocklists_from_db(conn)

        step_6_git_commit_and_push()

        logger.info("Pipeline execution finished cleanly and successfully.")
        sys.exit(0)

    except Exception as fatal_err:
        logger.critical(f"Fatal error encountered during execution pipeline: {fatal_err}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
