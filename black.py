import os
import re
import sys
import sqlite3
import logging
import argparse
import tempfile
import subprocess
import urllib.request
import urllib.error
from typing import Set, FrozenSet, Tuple, Iterable

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

def sanitize_regex_rule(rule: str) -> str:
    """
    Multi-step sanitization and validation for regex blacklist rules:
    1. Checks type and non-emptiness.
    2. Strips leading/trailing whitespace and invisible/control characters.
    3. Validates compilation via Python's re engine for PCRE/Pi-hole compatibility.
    """
    if not rule or not isinstance(rule, str):
        return ""
    
    cleaned = rule.strip()
    cleaned = "".join(ch for ch in cleaned if ord(ch) >= 32 and ch != 127)
    
    if not cleaned:
        return ""
        
    try:
        re.compile(cleaned)
    except re.error as e:
        logger.warning(f"Invalid regex rule encountered ('{rule}'): {e}")
        return ""
        
    return cleaned

def sanitize_regex_batch(regexes: Iterable[str]) -> FrozenSet[str]:
    """
    Processes a batch of regex rules into an immutable, unique frozenset object.
    """
    valid_regexes: Set[str] = set()
    for r in regexes:
        sanitized = sanitize_regex_rule(r)
        if sanitized:
            valid_regexes.add(sanitized)
    return frozenset(valid_regexes)

def sanitize_url(url: str) -> str:
    """
    Sanitizes an adlist URL/address by stripping whitespace and invisible characters.
    """
    if not url or not isinstance(url, str):
        return ""
    cleaned = url.strip()
    cleaned = "".join(ch for ch in cleaned if ord(ch) >= 32 and ch != 127)
    return cleaned

def sanitize_url_batch(urls: Iterable[str]) -> FrozenSet[str]:
    """
    Processes a batch of adlist URLs into an immutable, unique frozenset object.
    """
    valid_urls: Set[str] = set()
    for u in urls:
        sanitized = sanitize_url(u)
        if sanitized:
            valid_urls.add(sanitized)
    return frozenset(valid_urls)

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

def fetch_pihole_regex_blacklist(db_path: str) -> Set[str]:
    """
    Queries Pi-hole's gravity.db for blacklist regex rules belonging exclusively
    to the Default group and having a non-empty comment.
    """
    if not os.path.exists(db_path):
        logger.warning(f"Pi-hole database not found at '{db_path}'. Skipping regex blacklist extraction.")
        return set()

    extracted_regexes: Set[str] = set()
    try:
        with sqlite3.connect(db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            query = """
                SELECT DISTINCT d.domain 
                FROM domainlist d
                JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
                JOIN "group" g ON dg.group_id = g.id
                WHERE d.type = 3
                  AND d.comment IS NOT NULL 
                  AND TRIM(d.comment) != ''
                GROUP BY d.id, d.domain
                HAVING COUNT(dg.group_id) = 1 AND MAX(g.name) = 'Default'
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                if row and row[0]:
                    extracted_regexes.add(row[0])
                    
    except sqlite3.Error as e:
        logger.error(f"SQLite error while fetching regex blacklist from Pi-hole database: {e}")
        raise BlacklistSyncError(f"Database regex read failed: {e}") from e

    return extracted_regexes

def fetch_pihole_adlists(db_path: str) -> Set[str]:
    """
    Queries Pi-hole's gravity.db for adlists belonging to the Default group,
    having a non-empty comment, and a status of 1, 2, or 3.
    """
    if not os.path.exists(db_path):
        logger.warning(f"Pi-hole database not found at '{db_path}'. Skipping adlist extraction.")
        return set()

    extracted_urls: Set[str] = set()
    try:
        with sqlite3.connect(db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            query = """
                SELECT DISTINCT a.address
                FROM adlist a
                JOIN adlist_by_group abg ON a.id = abg.adlist_id
                JOIN "group" g ON abg.group_id = g.id
                WHERE g.name = 'Default'
                  AND a.comment IS NOT NULL
                  AND TRIM(a.comment) != ''
                  AND a.status IN (1, 2, 3)
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                if row and row[0]:
                    extracted_urls.add(row[0])
                    
    except sqlite3.Error as e:
        logger.error(f"SQLite error while fetching adlists from Pi-hole database: {e}")
        raise BlacklistSyncError(f"Database adlist read failed: {e}") from e

    return extracted_urls

def fetch_pihole_candidate_empty_adlists(db_path: str) -> Set[str]:
    """
    Queries Pi-hole's gravity.db for adlists with status 1, 2, or 3 that have 0 domain entries.
    """
    if not os.path.exists(db_path):
        logger.warning(f"Pi-hole database not found at '{db_path}'. Skipping candidate empty adlist extraction.")
        return set()

    extracted_urls: Set[str] = set()
    try:
        with sqlite3.connect(db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            query = """
                SELECT DISTINCT a.address
                FROM adlist a
                WHERE a.status IN (1, 2, 3)
                  AND (a.number = 0 OR a.number IS NULL)
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                if row and row[0]:
                    extracted_urls.add(row[0])
                    
    except sqlite3.Error as e:
        logger.error(f"SQLite error while fetching candidate empty adlists from Pi-hole database: {e}")
        raise BlacklistSyncError(f"Database candidate empty adlist read failed: {e}") from e

    return extracted_urls

def fetch_pihole_candidate_unavailable_adlists(db_path: str) -> Set[str]:
    """
    Queries Pi-hole's gravity.db for adlists with status 4 (unavailable).
    """
    if not os.path.exists(db_path):
        logger.warning(f"Pi-hole database not found at '{db_path}'. Skipping candidate unavailable adlist extraction.")
        return set()

    extracted_urls: Set[str] = set()
    try:
        with sqlite3.connect(db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            query = """
                SELECT DISTINCT a.address
                FROM adlist a
                WHERE a.status = 4
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                if row and row[0]:
                    extracted_urls.add(row[0])
                    
    except sqlite3.Error as e:
        logger.error(f"SQLite error while fetching candidate unavailable adlists from Pi-hole database: {e}")
        raise BlacklistSyncError(f"Database candidate unavailable adlist read failed: {e}") from e

    return extracted_urls

def fetch_pihole_minor_adlists(db_path: str) -> Set[str]:
    """
    Queries Pi-hole's gravity.db for adlists with status 1, 2, or 3,
    having no comment, and having strictly fewer than 15,000 domain entries (non-empty).
    """
    if not os.path.exists(db_path):
        logger.warning(f"Pi-hole database not found at '{db_path}'. Skipping minor adlist extraction.")
        return set()

    extracted_urls: Set[str] = set()
    try:
        with sqlite3.connect(db_path, timeout=10.0) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            
            query = """
                SELECT DISTINCT a.address
                FROM adlist a
                WHERE a.status IN (1, 2, 3)
                  AND (a.comment IS NULL OR TRIM(a.comment) = '')
                  AND a.number IS NOT NULL
                  AND a.number > 0
                  AND a.number < 15000
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                if row and row[0]:
                    extracted_urls.add(row[0])
                    
    except sqlite3.Error as e:
        logger.error(f"SQLite error while fetching minor adlists from Pi-hole database: {e}")
        raise BlacklistSyncError(f"Database minor adlist read failed: {e}") from e

    return extracted_urls

def verify_url_is_empty(url: str) -> bool:
    """
    Independently verifies via HTTP/HTTPS fetch whether a blocklist URL contains zero valid domain entries.
    Ignores blank lines and comments starting with '#'.
    """
    if not url or not isinstance(url, str):
        return False

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PiholeSync-Verifier/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as response:
            if response.status != 200:
                logger.warning(f"Failed to fetch '{url}': HTTP status {response.status}")
                return False
            
            for line_bytes in response:
                try:
                    line = line_bytes.decode('utf-8', errors='ignore').strip()
                except Exception:
                    continue
                
                if line and not line.startswith('#'):
                    return False
        return True
    except urllib.error.URLError as e:
        logger.warning(f"Network error fetching '{url}' for verification: {e}")
        return False
    except Exception as e:
        logger.warning(f"Unexpected error verifying URL '{url}': {e}")
        return False

def verify_url_is_unavailable(url: str) -> bool:
    """
    Independently verifies via HTTP/HTTPS fetch whether a blocklist URL is unavailable/failing 
    (e.g., HTTP error status >= 400, connection timeout, or URLError). Returns True if unavailable.
    """
    if not url or not isinstance(url, str):
        return False

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PiholeSync-Verifier/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10.0) as response:
            if response.status >= 400:
                logger.warning(f"URL '{url}' returned HTTP status {response.status}")
                return True
            return False
    except urllib.error.HTTPError as e:
        logger.warning(f"HTTP error verifying URL '{url}': {e.code} {e.reason}")
        return True
    except urllib.error.URLError as e:
        logger.warning(f"Network error verifying URL '{url}': {e.reason}")
        return True
    except Exception as e:
        logger.warning(f"Unexpected error verifying URL '{url}': {e}")
        return True

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

def purge_pihole_adlists(urls: FrozenSet[str], db_path: str) -> None:
    """
    Atomically purges extracted unavailable adlists from Pi-hole's gravity.db within a transaction boundary.
    """
    if not urls or not os.path.exists(db_path):
        return

    url_list = list(urls)
    try:
        with sqlite3.connect(db_path, timeout=15.0) as conn:
            cursor = conn.cursor()
            conn.execute("BEGIN TRANSACTION;")
            
            batch_size = 500
            total_purged = 0
            
            for i in range(0, len(url_list), batch_size):
                chunk = url_list[i:i + batch_size]
                placeholders = ",".join(["?"] * len(chunk))
                
                cursor.execute(f"SELECT id FROM adlist WHERE address IN ({placeholders})", tuple(chunk))
                adlist_ids = [row[0] for row in cursor.fetchall()]

                if adlist_ids:
                    id_placeholders = ",".join(["?"] * len(adlist_ids))
                    cursor.execute(f"DELETE FROM adlist_by_group WHERE adlist_id IN ({id_placeholders})", tuple(adlist_ids))
                    cursor.execute(f"DELETE FROM adlist WHERE id IN ({id_placeholders})", tuple(adlist_ids))
                    total_purged += len(adlist_ids)

            conn.commit()
            logger.info(f"Successfully purged {total_purged} unavailable adlists from Pi-hole gravity database.")
            
    except sqlite3.Error as e:
        logger.error(f"Transaction failed during adlist database purge, rolling back: {e}")
        raise BlacklistSyncError(f"Database adlist purge failed: {e}") from e

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

def atomic_write_regex_deny(file_path: str, regex_tuple: Tuple[str, ...]) -> None:
    """
    Performs an atomic write operation via temporary file replacement for regex_deny.txt.
    Ensures no empty lines.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
        
    fd, temp_path = tempfile.mkstemp(dir=dir_name, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            content = "\n".join(regex_tuple)
            if content:
                f.write(content)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully updated '{file_path}' atomically with {len(regex_tuple)} regex rules.")
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Failed to write regex_deny.txt atomically: {e}")
        raise BlacklistSyncError(f"Atomic regex file write failed: {e}") from e

def atomic_write_blocklists(file_path: str, url_tuple: Tuple[str, ...]) -> None:
    """
    Performs an atomic write operation via temporary file replacement for blocklists.txt.
    Ensures no empty lines.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
        
    fd, temp_path = tempfile.mkstemp(dir=dir_name, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            content = "\n".join(url_tuple)
            if content:
                f.write(content)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully updated '{file_path}' atomically with {len(url_tuple)} blocklists.")
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Failed to write blocklists.txt atomically: {e}")
        raise BlacklistSyncError(f"Atomic blocklists file write failed: {e}") from e

def update_empty_lists_file(file_path: str, new_urls: Iterable[str]) -> None:
    """
    Safely reads existing empty-lists.txt, merges new unique URLs avoiding duplicates,
    and performs an atomic write to prevent data loss while correctly reporting overall totals.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    existing_urls: Set[str] = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    u = line.strip()
                    if u:
                        existing_urls.add(u)
        except OSError as e:
            logger.error(f"Failed to read existing empty-lists.txt: {e}")
            raise BlacklistSyncError(f"Failed to read empty-lists.txt: {e}") from e

    added_count = 0
    for url in new_urls:
        sanitized = sanitize_url(url)
        if sanitized and sanitized not in existing_urls:
            existing_urls.add(sanitized)
            added_count += 1

    total_count = len(existing_urls)

    if added_count == 0:
        logger.info(f"No new unique empty blocklists to append. Total unique tracked: {total_count}.")
        return

    sorted_urls = sorted(existing_urls)
    fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            content = "\n".join(sorted_urls)
            if content:
                f.write(content)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully updated '{file_path}' with {added_count} new empty blocklist(s). Total unique tracked: {total_count}.")
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Failed to write empty-lists.txt atomically: {e}")
        raise BlacklistSyncError(f"Atomic empty-lists file write failed: {e}") from e

def update_unavailable_lists_file(file_path: str, new_urls: Iterable[str]) -> None:
    """
    Safely reads existing unavailable-lists.txt, merges new unique URLs avoiding duplicates,
    and performs an atomic write to prevent data loss while correctly reporting overall totals.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    existing_urls: Set[str] = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    u = line.strip()
                    if u:
                        existing_urls.add(u)
        except OSError as e:
            logger.error(f"Failed to read existing unavailable-lists.txt: {e}")
            raise BlacklistSyncError(f"Failed to read unavailable-lists.txt: {e}") from e

    added_count = 0
    for url in new_urls:
        sanitized = sanitize_url(url)
        if sanitized and sanitized not in existing_urls:
            existing_urls.add(sanitized)
            added_count += 1

    total_count = len(existing_urls)

    if added_count == 0:
        logger.info(f"No new unique unavailable blocklists to append. Total unique tracked: {total_count}.")
        return

    sorted_urls = sorted(existing_urls)
    fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            content = "\n".join(sorted_urls)
            if content:
                f.write(content)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully updated '{file_path}' with {added_count} new unavailable blocklist(s). Total unique tracked: {total_count}.")
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Failed to write unavailable-lists.txt atomically: {e}")
        raise BlacklistSyncError(f"Atomic unavailable-lists file write failed: {e}") from e

def update_minor_lists_file(file_path: str, new_urls: Iterable[str]) -> None:
    """
    Safely reads existing minor-lists.txt, merges new unique URLs avoiding duplicates,
    and performs an atomic write to prevent data loss while correctly reporting overall totals.
    """
    dir_name = os.path.dirname(file_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    existing_urls: Set[str] = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    u = line.strip()
                    if u:
                        existing_urls.add(u)
        except OSError as e:
            logger.error(f"Failed to read existing minor-lists.txt: {e}")
            raise BlacklistSyncError(f"Failed to read minor-lists.txt: {e}") from e

    added_count = 0
    for url in new_urls:
        sanitized = sanitize_url(url)
        if sanitized and sanitized not in existing_urls:
            existing_urls.add(sanitized)
            added_count += 1

    total_count = len(existing_urls)

    if added_count == 0:
        logger.info(f"No new unique minor blocklists to append. Total unique tracked: {total_count}.")
        return

    sorted_urls = sorted(existing_urls)
    fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            content = "\n".join(sorted_urls)
            if content:
                f.write(content)
        os.replace(temp_path, file_path)
        logger.info(f"Successfully updated '{file_path}' with {added_count} new minor blocklist(s). Total unique tracked: {total_count}.")
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        logger.error(f"Failed to write minor-lists.txt atomically: {e}")
        raise BlacklistSyncError(f"Atomic minor-lists file write failed: {e}") from e

def filter_minor_lists_against_blocklists(blocklists_path: str, minor_lists_path: str) -> None:
    """
    Compares blocklists.txt and minor-lists.txt, removing any matching entries 
    found in blocklists.txt from minor-lists.txt atomically.
    """
    if not os.path.exists(blocklists_path) or not os.path.exists(minor_lists_path):
        return

    blocklists: Set[str] = set()
    try:
        with open(blocklists_path, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    blocklists.add(u)
    except OSError as e:
        logger.error(f"Failed to read blocklists.txt for filtering: {e}")
        raise BlacklistSyncError(f"Failed to read blocklists.txt: {e}") from e

    minor_urls: Set[str] = set()
    try:
        with open(minor_lists_path, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    minor_urls.add(u)
    except OSError as e:
        logger.error(f"Failed to read minor-lists.txt for filtering: {e}")
        raise BlacklistSyncError(f"Failed to read minor-lists.txt: {e}") from e

    initial_count = len(minor_urls)
    filtered_urls = minor_urls - blocklists
    removed_count = initial_count - len(filtered_urls)

    if removed_count > 0:
        dir_name = os.path.dirname(minor_lists_path)
        sorted_urls = sorted(filtered_urls)
        fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                content = "\n".join(sorted_urls)
                if content:
                    f.write(content)
            os.replace(temp_path, minor_lists_path)
            logger.info(f"Successfully filtered out {removed_count} overlapping URL(s) from '{minor_lists_path}' matching blocklists.txt.")
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            logger.error(f"Failed to write filtered minor-lists.txt atomically: {e}")
            raise BlacklistSyncError(f"Atomic filtered minor-lists file write failed: {e}") from e
    else:
        logger.info("No overlapping URLs found between blocklists.txt and minor-lists.txt.")

def filter_minor_lists_against_empty_lists(empty_lists_path: str, minor_lists_path: str) -> None:
    """
    Compares empty-lists.txt and minor-lists.txt, removing any matching entries 
    found in empty-lists.txt from minor-lists.txt atomically.
    """
    if not os.path.exists(empty_lists_path) or not os.path.exists(minor_lists_path):
        return

    empty_lists: Set[str] = set()
    try:
        with open(empty_lists_path, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    empty_lists.add(u)
    except OSError as e:
        logger.error(f"Failed to read empty-lists.txt for filtering: {e}")
        raise BlacklistSyncError(f"Failed to read empty-lists.txt: {e}") from e

    minor_urls: Set[str] = set()
    try:
        with open(minor_lists_path, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    minor_urls.add(u)
    except OSError as e:
        logger.error(f"Failed to read minor-lists.txt for filtering: {e}")
        raise BlacklistSyncError(f"Failed to read minor-lists.txt: {e}") from e

    initial_count = len(minor_urls)
    filtered_urls = minor_urls - empty_lists
    removed_count = initial_count - len(filtered_urls)

    if removed_count > 0:
        dir_name = os.path.dirname(minor_lists_path)
        sorted_urls = sorted(filtered_urls)
        fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                content = "\n".join(sorted_urls)
                if content:
                    f.write(content)
            os.replace(temp_path, minor_lists_path)
            logger.info(f"Successfully filtered out {removed_count} overlapping URL(s) from '{minor_lists_path}' matching empty-lists.txt.")
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            logger.error(f"Failed to write filtered minor-lists.txt atomically: {e}")
            raise BlacklistSyncError(f"Atomic filtered minor-lists file write failed: {e}") from e
    else:
        logger.info("No overlapping URLs found between empty-lists.txt and minor-lists.txt.")

def filter_minor_lists_against_unavailable_lists(unavailable_lists_path: str, minor_lists_path: str) -> None:
    """
    Compares unavailable-lists.txt and minor-lists.txt, removing any matching entries 
    found in unavailable-lists.txt from minor-lists.txt atomically.
    """
    if not os.path.exists(unavailable_lists_path) or not os.path.exists(minor_lists_path):
        return

    unavailable_lists: Set[str] = set()
    try:
        with open(unavailable_lists_path, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    unavailable_lists.add(u)
    except OSError as e:
        logger.error(f"Failed to read unavailable-lists.txt for filtering: {e}")
        raise BlacklistSyncError(f"Failed to read unavailable-lists.txt: {e}") from e

    minor_urls: Set[str] = set()
    try:
        with open(minor_lists_path, "r", encoding="utf-8") as f:
            for line in f:
                u = line.strip()
                if u:
                    minor_urls.add(u)
    except OSError as e:
        logger.error(f"Failed to read minor-lists.txt for filtering: {e}")
        raise BlacklistSyncError(f"Failed to read minor-lists.txt: {e}") from e

    initial_count = len(minor_urls)
    filtered_urls = minor_urls - unavailable_lists
    removed_count = initial_count - len(filtered_urls)

    if removed_count > 0:
        dir_name = os.path.dirname(minor_lists_path)
        sorted_urls = sorted(filtered_urls)
        fd, temp_path = tempfile.mkstemp(dir=dir_name if dir_name else ".", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                content = "\n".join(sorted_urls)
                if content:
                    f.write(content)
            os.replace(temp_path, minor_lists_path)
            logger.info(f"Successfully filtered out {removed_count} overlapping URL(s) from '{minor_lists_path}' matching unavailable-lists.txt.")
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            logger.error(f"Failed to write filtered minor-lists.txt atomically: {e}")
            raise BlacklistSyncError(f"Atomic filtered minor-lists file write failed: {e}") from e
    else:
        logger.info("No overlapping URLs found between unavailable-lists.txt and minor-lists.txt.")

def git_commit_and_push_changes(repo_dir: str) -> None:
    """
    Checks for local changes in the repository. If changes exist, stages them,
    commits them using a randomized hexadecimal string message, and pushes to GitHub.
    """
    if not os.path.exists(os.path.join(repo_dir, ".git")):
        logger.warning(f"No git repository found at '{repo_dir}'. Skipping git push.")
        return

    try:
        status_result = subprocess.run(
            ["git", "-C", repo_dir, "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True
        )
        
        if not status_result.stdout.strip():
            logger.info("No changes detected in the repository. Skipping git push.")
            return

        logger.info("Changes detected. Staging changes...")
        subprocess.run(["git", "-C", repo_dir, "add", "."], check=True)

        commit_message = os.urandom(8).hex()
        logger.info(f"Committing changes with message: {commit_message}")
        subprocess.run(["git", "-C", repo_dir, "commit", "-m", commit_message], check=True)

        logger.info("Pushing changes to GitHub...")
        subprocess.run(["git", "-C", repo_dir, "push"], check=True)
        logger.info("Successfully pushed changes to GitHub.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e}")
        raise BlacklistSyncError(f"Git push failed: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error during git commit and push: {e}")
        raise BlacklistSyncError(f"Git automation failed: {e}") from e

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
    regex_deny_path = os.path.join(current_dir, "regex", "regex_deny.txt")
    blocklists_path = os.path.join(current_dir, "blocklists.txt")
    empty_lists_path = os.path.join(current_dir, "empty-lists.txt")
    unavailable_lists_path = os.path.join(current_dir, "unavailable-lists.txt")
    minor_lists_path = os.path.join(current_dir, "minor-lists.txt")
    
    logger.info("Initializing Pi-hole blacklist synchronization pipeline...")

    try:
        # Phase 1: Domain Blacklist Sync
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

        # Phase 2: Regex Blacklist Export
        logger.info("Initializing Phase 2: Regex blacklist extraction and validation...")
        regex_raw = fetch_pihole_regex_blacklist(DB_PATH)
        regex_frozen: FrozenSet[str] = sanitize_regex_batch(regex_raw)
        logger.info(f"Sanitized and validated {len(regex_frozen)} unique regex blacklist rules from gravity.db.")

        regex_sorted_tuple: Tuple[str, ...] = tuple(sorted(regex_frozen))
        atomic_write_regex_deny(regex_deny_path, regex_sorted_tuple)

        # Phase 3: Blocklists Export
        logger.info("Initializing Phase 3: Adlists extraction and validation...")
        adlist_raw = fetch_pihole_adlists(DB_PATH)
        adlist_frozen: FrozenSet[str] = sanitize_url_batch(adlist_raw)
        logger.info(f"Sanitized and validated {len(adlist_frozen)} unique blocklist URLs from gravity.db.")

        adlist_sorted_tuple: Tuple[str, ...] = tuple(sorted(adlist_frozen))
        atomic_write_blocklists(blocklists_path, adlist_sorted_tuple)

        # Phase 4: Independent Verification of Empty Blocklists
        logger.info("Initializing Phase 4: Empty blocklists independent verification and tracking...")
        candidate_empty_raw = fetch_pihole_candidate_empty_adlists(DB_PATH)
        logger.info(f"Found {len(candidate_empty_raw)} candidate empty adlists in gravity.db. Verifying via direct fetch...")

        confirmed_empty_urls: Set[str] = set()
        for url in candidate_empty_raw:
            sanitized_u = sanitize_url(url)
            if sanitized_u and verify_url_is_empty(sanitized_u):
                confirmed_empty_urls.add(sanitized_u)
                logger.info(f"Confirmed empty blocklist: '{sanitized_u}'")

        update_empty_lists_file(empty_lists_path, confirmed_empty_urls)

        # Phase 4.5: Independent Verification and Tracking of Status 4 Unavailable Blocklists
        logger.info("Initializing Phase 4.5: Unavailable blocklists independent verification and tracking...")
        candidate_unavailable_raw = fetch_pihole_candidate_unavailable_adlists(DB_PATH)
        logger.info(f"Found {len(candidate_unavailable_raw)} candidate unavailable adlists with status 4 in gravity.db. Verifying via direct fetch...")

        confirmed_unavailable_urls: Set[str] = set()
        for url in candidate_unavailable_raw:
            sanitized_u = sanitize_url(url)
            if sanitized_u and verify_url_is_unavailable(sanitized_u):
                confirmed_unavailable_urls.add(sanitized_u)
                logger.info(f"Confirmed unavailable blocklist: '{sanitized_u}'")

        update_unavailable_lists_file(unavailable_lists_path, confirmed_unavailable_urls)

        if confirmed_unavailable_urls:
            purge_pihole_adlists(sanitize_url_batch(confirmed_unavailable_urls), DB_PATH)

        # Phase 5: Minor Blocklists Export (< 15,000 entries, no comment, status 1, 2, or 3)
        logger.info("Initializing Phase 5: Minor blocklists extraction and tracking...")
        minor_raw = fetch_pihole_minor_adlists(DB_PATH)
        minor_frozen: FrozenSet[str] = sanitize_url_batch(minor_raw)
        logger.info(f"Sanitized and validated {len(minor_frozen)} unique minor blocklist URLs from gravity.db.")
        update_minor_lists_file(minor_lists_path, minor_frozen)

        # Phase 6: Filter Minor Blocklists Against Main Blocklists
        logger.info("Initializing Phase 6: Filtering minor-lists against blocklists...")
        filter_minor_lists_against_blocklists(blocklists_path, minor_lists_path)

        # Phase 7: Filter Minor Blocklists Against Empty Blocklists
        logger.info("Initializing Phase 7: Filtering minor-lists against empty-lists...")
        filter_minor_lists_against_empty_lists(empty_lists_path, minor_lists_path)

        # Phase 7.5: Filter Minor Blocklists Against Unavailable Blocklists
        logger.info("Initializing Phase 7.5: Filtering minor-lists against unavailable-lists...")
        filter_minor_lists_against_unavailable_lists(unavailable_lists_path, minor_lists_path)

        # Phase 8: Git Commit and Push Automation
        logger.info("Initializing Phase 8: Checking and pushing updates to GitHub...")
        git_commit_and_push_changes(current_dir)

        logger.info("Pipeline executed successfully to completion.")

    except BlacklistSyncError as e:
        logger.critical(f"Pipeline failed due to operational error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Pipeline failed due to an unexpected exception: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
