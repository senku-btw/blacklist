import os
import re
import sqlite3
import logging
from typing import Set, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("PiholeManager")

DB_PATH = "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"

EXCLUSION_URLS = [
    "https://raw.githubusercontent.com/senku-btw/blacklist/refs/heads/main/blacklists/blacklist-extra.txt",
    "https://raw.githubusercontent.com/senku-btw/blacklist/refs/heads/main/blacklists/blacklist.txt",
    "https://raw.githubusercontent.com/senku-btw/whitelist/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/senku-btw/whitelist/refs/heads/main/healthcheck.txt",
]

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def sanitize_domain(domain: str) -> str:
    """Sanitize domain string by stripping whitespace and converting to lowercase."""
    return domain.strip().lower()

def is_valid_domain(domain: str) -> bool:
    """Verify if a domain string is valid."""
    if not domain or len(domain) > 253:
        return false
    return bool(DOMAIN_REGEX.match(domain))

def is_valid_regex(pattern: str) -> bool:
    """Verify if a regex pattern compiles successfully and is compatible."""
    if not pattern or not pattern.strip():
        return False
    try:
        re.compile(pattern.strip())
        return True
    except re.error:
        return False

def step_a(script_dir: str) -> None:
    """Step a: Extract exact blacklist domains from DB, sync with blacklist.txt, and cleanup DB."""
    logger.info("Starting Step A: Processing exact blacklist domains...")
    
    if not os.path.exists(DB_PATH):
        logger.error(f"Gravity database not found at {DB_PATH}")
        return

    db_domains: Set[str] = set()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            query = """
                SELECT DISTINCT d.domain FROM domainlist d
                JOIN domainlist_by_group dlg ON d.id = dlg.domainlist_id
                JOIN "group" g ON dlg.group_id = g.id
                WHERE d.type = 1 
                  AND (g.name = 'Default' OR g.id = 1)
                  AND (d.comment IS NULL OR d.comment = '')
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                sanitized = sanitize_domain(row[0])
                if is_valid_domain(sanitized):
                    db_domains.add(sanitized)
    except Exception as e:
        logger.error(f"Error querying database for exact blacklists: {e}")
        return

    immutable_db_domains: frozenset = frozenset(db_domains)

    blacklists_dir = os.path.join(script_dir, "blacklists")
    os.makedirs(blacklists_dir, exist_ok=True)
    blacklist_file_path = os.path.join(blacklists_dir, "blacklist.txt")

    file_domains: Set[str] = set()
    if os.path.exists(blacklist_file_path):
        try:
            with open(blacklist_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    sanitized = sanitize_domain(line)
                    if sanitized and not sanitized.startswith("#"):
                        if is_valid_domain(sanitized):
                            file_domains.add(sanitized)
        except Exception as e:
            logger.error(f"Error reading {blacklist_file_path}: {e}")

    immutable_file_domains: frozenset = frozenset(file_domains)

    combined_superset: frozenset = immutable_db_domains.union(immutable_file_domains)
    sorted_domains: List[str] = sorted(list(combined_superset))

    try:
        with open(blacklist_file_path, "w", encoding="utf-8") as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")
        logger.info(f"Successfully updated {blacklist_file_path} with {len(sorted_domains)} unique domains.")
    except Exception as e:
        logger.error(f"Error writing to {blacklist_file_path}: {e}")
        return

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            deleted_count = 0
            for domain in sorted_domains:
                cursor.execute(
                    "DELETE FROM domainlist WHERE type = 1 AND domain = ?",
                    (domain,)
                )
                deleted_count += cursor.rowcount
            conn.commit()
            logger.info(f"Removed {deleted_count} matching exact blacklist entries from gravity.db.")
    except Exception as e:
        logger.error(f"Error deleting exact blacklist entries from database: {e}")

def step_b(script_dir: str) -> None:
    """Step b: Fetch, validate, alphabetise regex rules and export to regex_deny.txt."""
    logger.info("Starting Step B: Processing regex deny rules...")
    
    if not os.path.exists(DB_PATH):
        logger.error(f"Gravity database not found at {DB_PATH}")
        return

    regex_rules: Set[str] = set()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM domainlist WHERE type = 3")
            rows = cursor.fetchall()
            for row in rows:
                pattern = row[0].strip()
                if is_valid_regex(pattern):
                    regex_rules.add(pattern)
                else:
                    logger.warning(f"Invalid or incompatible Pi-hole regex encountered in DB and skipped: {pattern}")
    except Exception as e:
        logger.error(f"Error fetching regex rules from database: {e}")
        return

    immutable_regex: frozenset = frozenset(regex_rules)
    sorted_regex: List[str] = sorted(list(immutable_regex))

    regex_dir = os.path.join(script_dir, "regex")
    os.makedirs(regex_dir, exist_ok=True)
    regex_file_path = os.path.join(regex_dir, "regex_deny.txt")

    try:
        with open(regex_file_path, "w", encoding="utf-8") as f:
            for pattern in sorted_regex:
                f.write(f"{pattern}\n")
        logger.info(f"Successfully exported {len(sorted_regex)} valid regex rules to {regex_file_path}.")
    except Exception as e:
        logger.error(f"Error writing to {regex_file_path}: {e}")

def step_c(script_dir: str) -> None:
    """Step c: Identify empty or inaccessible adlists (excluding status 3), update empty-lists.txt, and delete from DB."""
    logger.info("Starting Step C: Processing empty or inaccessible adlists...")
    
    if not os.path.exists(DB_PATH):
        logger.error(f"Gravity database not found at {DB_PATH}")
        return

    lists_to_remove: List[str] = []
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT address, number, status FROM adlist")
            rows = cursor.fetchall()
            for address, number, status in rows:
                if address in EXCLUSION_URLS:
                    continue
                if status == 3:
                    # Status 3: unavailable with local copy, must be left untouched
                    continue
                if number == 0 or status == 4:
                    lists_to_remove.append(address)
    except Exception as e:
        logger.error(f"Error querying adlists from database: {e}")
        return

    empty_lists_file_path = os.path.join(script_dir, "empty-lists.txt")
    file_urls: Set[str] = set()
    if os.path.exists(empty_lists_file_path):
        try:
            with open(empty_lists_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#") and url not in EXCLUSION_URLS:
                        file_urls.add(url)
        except Exception as e:
            logger.error(f"Error reading {empty_lists_file_path}: {e}")

    combined_empty_superset: Set[str] = file_urls.union(set(lists_to_remove))
    sorted_empty_urls: List[str] = sorted(list(combined_empty_superset))

    try:
        with open(empty_lists_file_path, "w", encoding="utf-8") as f:
            for url in sorted_empty_urls:
                f.write(f"{url}\n")
        logger.info(f"Successfully updated {empty_lists_file_path} with {len(sorted_empty_urls)} entries.")
    except Exception as e:
        logger.error(f"Error writing to {empty_lists_file_path}: {e}")
        return

    if lists_to_remove:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                for url in lists_to_remove:
                    cursor.execute("DELETE FROM adlist WHERE address = ?", (url,))
                    logger.info(f"Confirmed deletion of empty/inaccessible adlist from database: {url}")
                conn.commit()
        except Exception as e:
            logger.error(f"Error deleting adlists from database: {e}")
    else:
        logger.info("No empty or inaccessible adlists met the criteria for database removal.")

def step_d(script_dir: str) -> None:
    """Step d: Extract minor blocklists matching criteria, sync with minor-lists.txt, and delete from DB."""
    logger.info("Starting Step D: Processing minor blocklists...")
    
    if not os.path.exists(DB_PATH):
        logger.error(f"Gravity database not found at {DB_PATH}")
        return

    minor_urls: Set[str] = set()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            query = """
                SELECT DISTINCT a.address FROM adlist a
                JOIN adlist_by_group alg ON a.id = alg.adlist_id
                JOIN "group" g ON alg.group_id = g.id
                WHERE (g.name = 'Default' OR g.id = 1)
                  AND (a.comment IS NULL OR a.comment = '')
                  AND a.number < 100000
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                url = row[0].strip()
                if url and url not in EXCLUSION_URLS:
                    minor_urls.add(url)
    except Exception as e:
        logger.error(f"Error querying minor lists from database: {e}")
        return

    immutable_minor_urls: frozenset = frozenset(minor_urls)
    minor_lists_file_path = os.path.join(script_dir, "minor-lists.txt")

    existing_minor_file_urls: List[str] = []
    if os.path.exists(minor_lists_file_path):
        try:
            with open(minor_lists_file_path, "r", encoding="utf-8") as f:
                existing_minor_file_urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading {minor_lists_file_path}: {e}")

    updated_minor_file_urls: List[str] = list(existing_minor_file_urls)
    newly_added = 0

    for url in sorted(list(immutable_minor_urls)):
        if url not in updated_minor_file_urls:
            updated_minor_file_urls.append(url)
            newly_added += 1

    try:
        with open(minor_lists_file_path, "w", encoding="utf-8") as f:
            for url in updated_minor_file_urls:
                f.write(f"{url}\n")
        logger.info(f"Appended {newly_added} new entries to {minor_lists_file_path}.")
    except Exception as e:
        logger.error(f"Error writing to {minor_lists_file_path}: {e}")
        return

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            deleted_count = 0
            for url in immutable_minor_urls:
                cursor.execute("DELETE FROM adlist WHERE address = ?", (url,))
                deleted_count += cursor.rowcount
            conn.commit()
            logger.info(f"Successfully deleted {deleted_count} minor lists from gravity.db.")
    except Exception as e:
        logger.error(f"Error deleting minor lists from database: {e}")

def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logger.info("Starting Pi-hole maintenance and synchronization script.")
    
    step_a(script_dir)
    step_b(script_dir)
    step_c(script_dir)
    step_d(script_dir)
    
    logger.info("All maintenance steps completed successfully.")

if __name__ == "__main__":
    main()
