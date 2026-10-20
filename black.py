import os
import re
import sys
import sqlite3
import logging
import argparse
import tempfile
from typing import Set, FrozenSet, Tuple, Iterable, Optional

# Configure production-grade structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("PiholeSync")

# Hardcoded Pi-hole gravity.db path
DB_PATH = "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"

# RFC 1123 compliant domain validation regex
DOMAIN_REGEX = re.compile(
    r"^(?=^.{1,253}$)(([a-zA-Z0-9][-a-zA-Z0-9]{0,62}[a-zA-Z0-9])|[a-zA-Z0-9])"
    r"(\.([a-zA-Z0-9][-a-zA-Z0-9]{0,62}[a-zA-Z0-9])|[a-zA-Z0-9])+$"
)

class BlacklistSyncError(Exception):
    """Base exception for pipeline errors."""
    pass

def sanitize_domain(domain: str) -> str:
    """
    Multi-step sanitization to ensure domain compatibility with Pi-hole.
    Strips protocols, trailing slashes, whitespace, and validates syntax.
    """
    if not domain or not isinstance(domain, str):
        return ""
    
    cleaned = domain.strip().lower()
    
    for prefix in ("http://", "https://", "ftp://", "file://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
            
    cleaned = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    
    if DOMAIN_REGEX.match(cleaned):
        return cleaned
    return ""

def sanitize_domain_batch(domains: Iterable[str]) -> FrozenSet[str]:
    """
    Processes a batch of domains into an immutable, unique-by-type frozenset object.
    """
    valid_domains: Set[str] = set()
    for d in domains:
        sanitized = sanitize_domain(d)
        if sanitized:
            valid_domains.add(sanitized)
    return frozenset(valid_domains)

def fetch_pihole_default_domains(db_path: str) -> Set[str]:
    """
    Queries Pi-hole's gravity.db securely using parameterized checks and explicit transaction safety.
    """
    if not os.path.exists(db_path):
        logger.warning(f"Pi-hole database not found at '{db_path}'. Skipping database extraction.")
        return set()

    extracted_domains: Set[str] = set()
    try:
        with sqlite3.connect(db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            query = """
                SELECT DISTINCT d.domain 
                FROM domainlist d
                JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
                JOIN "group" g ON dg.group_id = g.id
                WHERE g.name = 'Default' 
                  AND (d.comment IS NULL OR TRIM(d.comment) = '')
                  AND d.type IN (0, 1, 2, 3)
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                if row and row[0]:
                    extracted_domains.add(row[0])
                    
    except sqlite3.Error as e:
        logger.error(f"SQLite error while fetching from Pi-hole database: {e}")
        raise BlacklistSyncError(f"Database read failed: {e}") from e

    return extracted_domains

def purge_pihole_domains(domains: FrozenSet[str], db_path: str) -> None:
    """
    Atomically purges extracted domains from Pi-hole's gravity.db within a transaction boundary.
    """
    if not domains or not os.path.exists(db_path):
        return

    domain_list = list(domains)
    try:
        with sqlite3.connect(db_path, timeout=15.0) as conn:
            cursor = conn.cursor()
            conn.execute("BEGIN TRANSACTION;")
            
            batch_size = 500
            total_purged = 0
            
            for i in range(0, len(domain_list), batch_size):
                chunk = domain_list[i:i + batch_size]
                placeholders = ",".join(["?"] * len(chunk))
                
                cursor.execute(f"SELECT id FROM domainlist WHERE domain IN ({placeholders})", tuple(chunk))
                domain_ids = [row[0] for row in cursor.fetchall()]

                if domain_ids:
                    id_placeholders = ",".join(["?"] * len(domain_ids))
                    cursor.execute(f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({id_placeholders})", tuple(domain_ids))
                    cursor.execute(f"DELETE FROM domainlist WHERE id IN ({id_placeholders})", tuple(domain_ids))
                    total_purged += len(domain_ids)

            conn.commit()
            logger.info(f"Successfully purged {total_purged} domains from Pi-hole gravity database.")
            
    except sqlite3.Error as e:
        logger.error(f"Transaction failed during database purge, rolling back: {e}")
        raise BlacklistSyncError(f"Database purge failed: {e}") from e

def parse_local_blacklist(file_path: str) -> Set[str]:
    """
    Safely parses local blacklist file line by line, handling missing directories gracefully.
    """
    if not os.path.exists(file_path):
        logger.info(f"Local blacklist file not found at '{file_path}'. Initializing empty file.")
        dir_name = os.path.dirname(file_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        open(file_path, 'w', encoding='utf-8').close()
        return set()

    local_domains: Set[str] = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    local_domains.add(domain)
    except OSError as e:
        logger.error(f"Filesystem error reading local blacklist: {e}")
        raise BlacklistSyncError(f"Failed to read blacklist file: {e}") from e

    return local_domains

def atomic_write_blacklist(file_path: str, domains_tuple: Tuple[str, ...]) -> None:
    """
    Performs an atomic write operation via temporary file replacement to prevent data corruption.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
        
    fd, temp_path = tempfile.mkstemp(dir=dir_name, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for domain in domains_tuple:
                f.write(f"{domain}\n")
        os.replace(temp_path, file_path)
        logger.info(f"Successfully updated '{file_path}' atomically with {len(domains_tuple)} domains.")
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Failed to write blacklist file atomically: {e}")
        raise BlacklistSyncError(f"Atomic file write failed: {e}") from e

def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for optional custom blacklist path overrides."""
    parser = argparse.ArgumentParser(description="Production-grade Pi-hole blacklist synchronizer.")
    parser.add_argument(
        "--blacklist-path",
        type=str,
        default=None,
        help="Custom absolute path to blacklist.txt file."
    )
    return parser.parse_args()

def main() -> None:
    args = parse_arguments()
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    blacklist_file_path = args.blacklist_path or os.path.join(current_dir, "blacklists", "blacklist.txt")
    
    logger.info("Initializing Pi-hole blacklist synchronization pipeline...")

    try:
        pihole_raw = fetch_pihole_default_domains(DB_PATH)
        pihole_frozen: FrozenSet[str] = sanitize_domain_batch(pihole_raw)
        logger.info(f"Sanitized {len(pihole_frozen)} valid unique domains from gravity.db.")

        local_raw = parse_local_blacklist(blacklist_file_path)
        local_frozen: FrozenSet[str] = sanitize_domain_batch(local_raw)
        logger.info(f"Sanitized {len(local_frozen)} valid unique domains from local file.")

        combined_tuple: Tuple[str, ...] = tuple(pihole_frozen) + tuple(local_frozen)
        alphabetised_tuple: Tuple[str, ...] = tuple(sorted(combined_tuple))

        atomic_write_blacklist(blacklist_file_path, alphabetised_tuple)

        if pihole_frozen:
            purge_pihole_domains(pihole_frozen, DB_PATH)

        logger.info("Pipeline executed successfully to completion.")

    except BlacklistSyncError as e:
        logger.critical(f"Pipeline failed due to operational error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Pipeline failed due to an unexpected exception: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
