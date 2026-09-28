"""Pi-hole blocklist sync, minor list consolidation, and DB purging tool."""

import logging
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    cast,
)

# --- Configuration & Environment Defaults ---
GRAVITY_DB_PATH = Path(
    os.getenv(
        "PIHOLE_GRAVITY_DB",
        "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db",
    )
).resolve()
BLACKLIST_PATH = Path(
    os.getenv(
        "PIHOLE_BLACKLIST_FILE",
        "/mnt/dietpi_userdata/docker/blacklist/blacklist.txt",
    )
).resolve()
MINOR_LISTS_PATH = Path(
    os.getenv(
        "PIHOLE_MINOR_LISTS_FILE",
        "/mnt/dietpi_userdata/docker/blacklist/minor_lists.txt",
    )
).resolve()
CONTAINER_NAME = os.getenv("PIHOLE_CONTAINER_NAME", "pihole")

IS_VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv

# --- Logging Configuration ---
logger = logging.getLogger("pihole_blacklist")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

F = TypeVar("F", bound=Callable[..., Any])


# --- Terminal Spinner UI ---
class TerminalSpinner:
    """Terminal spinner animation for visual progress feedback."""

    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.delay = 0.08
        self._running = False
        self._spinner_thread: Optional[threading.Thread] = None
        self._is_tty = sys.stdout.isatty() and IS_VERBOSE

    def _spin(self) -> None:
        """Runs the loop that prints animated spinner characters to stdout."""
        i = 0
        while self._running:
            char = self.spinner_chars[i % len(self.spinner_chars)]
            sys.stdout.write(f"\r  [{char}] {self.message}")
            sys.stdout.flush()
            time.sleep(self.delay)
            i += 1

    def start(self) -> None:
        """Starts the spinner thread or prints fallback output for non-TTY."""
        if not IS_VERBOSE:
            return
        if not self._is_tty:
            sys.stdout.write(f"{self.message} (Started)\n")
            sys.stdout.flush()
            return
        self._running = True
        self._spinner_thread = threading.Thread(target=self._spin, daemon=True)
        self._spinner_thread.start()

    def stop(self, success: bool = True) -> None:
        """Stops the spinner thread and prints completion state."""
        if not IS_VERBOSE:
            return
        if not self._is_tty:
            status = "Completed" if success else "Failed"
            sys.stdout.write(f"{self.message} ({status})\n")
            sys.stdout.flush()
            return
        self._running = False
        if self._spinner_thread and self._spinner_thread.is_alive():
            self._spinner_thread.join()

        icon = "\033[92m\u2714\033[0m" if success else "\033[91m\u2718\033[0m"
        sys.stdout.write(f"\r  [{icon}] {self.message}\n")
        sys.stdout.flush()


def with_spinner(message: str = "Loading...") -> Callable[[F], F]:
    """Decorator that wraps function execution with visual spinner feedback."""

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            spinner = TerminalSpinner(message)
            spinner.start()
            try:
                result = func(*args, **kwargs)
                if result is False:
                    spinner.stop(success=False)
                    return False
                spinner.stop(success=True)
                return result
            except KeyboardInterrupt:
                spinner.stop(success=False)
                sys.exit(130)
            except Exception as err:  # pylint: disable=broad-exception-caught
                logger.error("Unhandled exception in %s: %s", func.__name__, err, exc_info=True)
                spinner.stop(success=False)
                return False

        return cast(F, wrapper)

    return decorator


# --- System & DB Health Verification ---
def check_system_dependencies() -> bool:
    """Verifies all required CLI dependencies are present in system PATH."""
    required_cmds = ["docker", "git"]
    missing = [cmd for cmd in required_cmds if shutil.which(cmd) is None]
    if missing:
        logger.error("Missing system dependencies: %s", missing)
    else:
        logger.debug("System dependencies check passed: %s", required_cmds)
    return not missing


def does_file_exist(filepath: Path) -> bool:
    """Verifies that a path exists and is a regular non-empty file."""
    assert isinstance(filepath, Path), f"Expected Path object, got {type(filepath)}"
    try:
        path = filepath.resolve()
        exists = path.is_file() and path.stat().st_size > 0
        logger.debug("File existence check for %s: %s", path, exists)
        return exists
    except (TypeError, ValueError, OSError) as err:
        logger.warning("Error checking file existence for %s: %s", filepath, err)
        return False


def is_db(filepath: Path) -> bool:
    """Validates if a file is a non-corrupt SQLite3 database."""
    assert isinstance(filepath, Path), f"Expected Path object, got {type(filepath)}"
    try:
        path = filepath.resolve()
        if not path.is_file() or path.stat().st_size < 512:
            logger.warning("DB check failed: %s is not a file or too small (<512 bytes)", path)
            return False

        with path.open("rb") as f:
            header = f.read(16)
            if header != b"SQLite format 3\x00":
                logger.warning("DB check failed: %s invalid header %r", path, header)
                return False

        uri = f"file:{path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            conn.execute("SELECT count(*) FROM sqlite_schema;")
        logger.debug("Database integrity verified for %s", path)
        return True
    except (sqlite3.Error, OSError) as err:
        logger.error("DB integrity check failed for %s: %s", filepath, err)
        return False


# --- Core Task Functions ---
@with_spinner("Parsing and validating blacklist file entries...")
def parse_blacklist(filepath: Path) -> FrozenSet[str]:
    """Reads and sanitizes domain entries from the blacklist file."""
    assert isinstance(filepath, Path), f"Expected Path object, got {type(filepath)}"
    path = filepath.resolve()
    if not path.is_file():
        logger.warning("Blacklist file not found at %s", path)
        return frozenset()

    cleaned_entries: Set[str] = set()
    invisible_chars_re = re.compile(r"[\s\u200b\ufeff\u200e\u200f]+")
    domain_re = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    total_lines = 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                total_lines += 1
                raw_line = line.split("#", 1)[0].strip()
                if not raw_line:
                    continue

                raw_line = raw_line.replace("https://", "").replace("http://", "")
                raw_line = raw_line.split("/")[0].split(":")[0]
                cleaned_line = invisible_chars_re.sub("", raw_line).lower()

                if domain_re.match(cleaned_line):
                    cleaned_entries.add(cleaned_line)
                else:
                    logger.debug("Skipped invalid domain line %d in %s: %s", total_lines, path, raw_line)
    except OSError as err:
        logger.error("Failed to read blacklist file %s: %s", path, err)
        return frozenset()

    logger.info("Parsed %d valid domains from %d total lines in %s", len(cleaned_entries), total_lines, path)
    return frozenset(cleaned_entries)


@with_spinner("Identifying minor blocklists (1-100 entries) in gravity database...")
def fetch_minor_blocklists(db_path: Path) -> Tuple[List[int], List[str]]:
    """Identifies blocklists in gravity.db that contain between 1 and 100 entries."""
    assert isinstance(db_path, Path), f"Expected Path object, got {type(db_path)}"
    path = db_path.resolve()
    assert path.is_file(), f"Database path does not exist: {path}"

    uri = f"file:{path.as_posix()}?mode=ro"
    minor_ids: List[int] = []
    minor_urls: List[str] = []

    try:
        with sqlite3.connect(uri, uri=True, timeout=20) as conn:
            cursor = conn.cursor()
            query = """
                SELECT a.id, a.address, COUNT(g.domain) AS domain_count
                FROM adlist a
                JOIN gravity g ON a.id = g.adlist_id
                GROUP BY a.id, a.address
                HAVING COUNT(g.domain) >= 1 AND COUNT(g.domain) <= 100;
            """
            cursor.execute(query)
            for adlist_id, address, count in cursor.fetchall():
                assert isinstance(adlist_id, int), f"adlist ID must be int, got {type(adlist_id)}"
                if address:
                    minor_ids.append(adlist_id)
                    url_str = address.strip()
                    minor_urls.append(url_str)
                    logger.info(
                        "FLAGGED MINOR LIST (1-100 entries): ID=%s | Domain Count=%d | URL=%s",
                        adlist_id,
                        count,
                        url_str,
                    )
    except sqlite3.Error as err:
        logger.error("Error querying minor blocklists: %s", err)

    assert len(minor_ids) == len(minor_urls), "Mismatch between minor IDs and URLs count"
    return minor_ids, minor_urls


@with_spinner("Identifying empty blocklists (0 entries) in gravity database...")
def fetch_empty_blocklists(db_path: Path) -> List[int]:
    """Identifies totally empty blocklists in gravity.db to be cleansed."""
    assert isinstance(db_path, Path), f"Expected Path object, got {type(db_path)}"
    path = db_path.resolve()
    assert path.is_file(), f"Database path does not exist: {path}"

    uri = f"file:{path.as_posix()}?mode=ro"
    empty_ids: List[int] = []

    try:
        with sqlite3.connect(uri, uri=True, timeout=20) as conn:
            cursor = conn.cursor()
            query = """
                SELECT a.id, a.address
                FROM adlist a
                LEFT JOIN gravity g ON a.id = g.adlist_id
                GROUP BY a.id, a.address
                HAVING COUNT(g.domain) = 0;
            """
            cursor.execute(query)
            for adlist_id, address in cursor.fetchall():
                assert isinstance(adlist_id, int), f"adlist ID must be int, got {type(adlist_id)}"
                empty_ids.append(adlist_id)
                logger.info(
                    "FLAGGED EMPTY LIST (0 entries): ID=%s | URL=%s",
                    adlist_id,
                    address,
                )
    except sqlite3.Error as err:
        logger.error("Error querying empty blocklists: %s", err)

    return empty_ids


def _fetch_matching_adlist_ids(db_path: Path, urls: List[str]) -> List[int]:
    """Fetches adlist IDs from the database that match the given URLs."""
    assert isinstance(db_path, Path), f"Expected Path object, got {type(db_path)}"
    assert isinstance(urls, list), f"Expected list for urls, got {type(urls)}"

    matched_ids: List[int] = []
    if not urls:
        return matched_ids

    try:
        db_file = db_path.resolve()
        with sqlite3.connect(db_file, timeout=20) as conn:
            cursor = conn.cursor()
            batch_size = 900
            for i in range(0, len(urls), batch_size):
                batch = urls[i : i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                query = f"SELECT id, address FROM adlist WHERE address IN ({placeholders});"
                cursor.execute(query, batch)
                for adlist_id, address in cursor.fetchall():
                    assert isinstance(adlist_id, int), f"ID expected int, got {type(adlist_id)}"
                    matched_ids.append(adlist_id)
                    logger.info(
                        "MATCHED MINOR_LISTS.TXT URL TO DB: ID=%s | URL=%s",
                        adlist_id,
                        address,
                    )
    except sqlite3.Error as err:
        logger.error("Error matching adlist URLs in database: %s", err)

    return matched_ids


@with_spinner("Checking minor_lists.txt for duplicates and database matches...")
def process_minor_lists_file(filepath: Path, db_path: Path) -> List[int]:
    """Reads minor_lists.txt, deduplicates it in place, and returns matching DB IDs to delete."""
    assert isinstance(filepath, Path), f"Expected Path for filepath, got {type(filepath)}"
    assert isinstance(db_path, Path), f"Expected Path for db_path, got {type(db_path)}"

    path = filepath.resolve()
    if not path.is_file():
        logger.debug("Minor lists file %s does not exist yet", path)
        return []

    unique_urls: Set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    unique_urls.add(cleaned)
    except OSError as err:
        logger.error("Error reading minor_lists file %s: %s", path, err)
        return []

    sorted_urls = sorted(unique_urls)
    logger.info("Loaded %d unique URLs from %s", len(sorted_urls), path)

    temp_path = path.with_suffix(".tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(sorted_urls) + ("\n" if sorted_urls else ""))
        temp_path.replace(path)
    except OSError as err:
        logger.error("Error writing deduplicated minor_lists file: %s", err)
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)

    if not sorted_urls:
        return []

    return _fetch_matching_adlist_ids(db_path, sorted_urls)


@with_spinner("Storing origin URLs of minor lists to file...")
def update_minor_lists_file(filepath: Path, urls: Sequence[str]) -> bool:
    """Saves and deduplicates origin URLs to the designated minor lists file."""
    assert isinstance(filepath, Path), f"Expected Path for filepath, got {type(filepath)}"
    assert hasattr(urls, "__iter__"), "urls must be iterable"

    path = filepath.resolve()
    existing_urls: Set[str] = set()

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        existing_urls.add(cleaned)
        except OSError as err:
            logger.warning("Error reading existing minor lists from %s: %s", path, err)

    before_count = len(existing_urls)
    existing_urls.update(u for u in urls if u)
    added_count = len(existing_urls) - before_count
    sorted_urls = sorted(existing_urls)

    logger.info("Adding %d new URLs to minor lists file (Total: %d)", added_count, len(sorted_urls))

    temp_path = path.with_suffix(".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(sorted_urls) + ("\n" if sorted_urls else ""))
        temp_path.replace(path)
        return True
    except OSError as err:
        logger.error("Error updating minor lists file %s: %s", path, err)
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        return False


def _fetch_minor_list_domains(url: str, headers: Dict[str, str]) -> Set[str]:
    """Fetches and parses a single minor list URL for valid domains."""
    assert isinstance(url, str) and url.startswith("http"), f"Invalid HTTP URL: {url}"

    domains: Set[str] = set()
    invisible_chars_re = re.compile(r"[\s\u200b\ufeff\u200e\u200f]+")
    domain_re = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                raw = line.split("#", 1)[0].strip()
                if not raw:
                    continue

                if raw.startswith(("127.0.0.1", "0.0.0.0")):
                    parts = raw.split()
                    if len(parts) > 1:
                        raw = parts[1]

                raw = raw.replace("https://", "").replace("http://", "")
                raw = raw.split("/")[0].split(":")[0]
                cleaned = invisible_chars_re.sub("", raw).lower()

                if domain_re.match(cleaned):
                    domains.add(cleaned)

        logger.debug("Successfully fetched %d domains from URL: %s", len(domains), url)
    except (urllib.error.URLError, OSError, TimeoutError) as err:
        logger.warning("Failed to fetch minor list content from %s: %s", url, err)

    return domains


@with_spinner("Pulling and parsing content from minor list URLs...")
def pull_and_parse_minor_list_domains(filepath: Path) -> FrozenSet[str]:
    """Downloads minor list URLs concurrently and extracts unique domain entries."""
    assert isinstance(filepath, Path), f"Expected Path object, got {type(filepath)}"
    path = filepath.resolve()
    if not path.is_file():
        logger.debug("Minor lists file does not exist: %s", path)
        return frozenset()

    urls: List[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            urls = [
                line.strip()
                for line in file
                if line.strip() and not line.startswith("#")
            ]
    except OSError as err:
        logger.error("Error reading minor list file %s: %s", path, err)
        return frozenset()

    if not urls:
        logger.info("No URLs found in minor lists file %s", path)
        return frozenset()

    logger.info("Pulling domains from %d minor list URLs in parallel...", len(urls))
    extracted_domains: Set[str] = set()
    headers = {"User-Agent": "Mozilla/5.0 (Pi-hole Blocklist Consolidation Tool)"}

    max_workers = min(10, len(urls))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_fetch_minor_list_domains, url, headers) for url in urls
        ]
        for future in as_completed(futures):
            extracted_domains.update(future.result())

    logger.info("Extracted %d total unique domains from minor list URLs", len(extracted_domains))
    return frozenset(extracted_domains)


@with_spinner("Fetching existing blocklist entries from gravity database...")
def load_gravity_db_entries(db_path: Path) -> FrozenSet[str]:
    """Retrieves unique exact block (type 1) domains from gravity.db."""
    assert isinstance(db_path, Path), f"Expected Path object, got {type(db_path)}"
    path = db_path.resolve()
    assert path.is_file(), f"Database file missing at {path}"

    uri = f"file:{path.as_posix()}?mode=ro"
    db_domains: Set[str] = set()

    try:
        with sqlite3.connect(uri, uri=True, timeout=20) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM domainlist WHERE type = 1;")
            for (domain,) in cursor.fetchall():
                if domain:
                    cleaned = domain.strip().lower()
                    if cleaned:
                        db_domains.add(cleaned)
    except sqlite3.Error as err:
        logger.error("Error reading domainlist from gravity.db: %s", err)
        return frozenset()

    logger.info("Loaded %d exact block domains (type=1) from gravity.db", len(db_domains))
    return frozenset(db_domains)


@with_spinner("Merging, deduplicating, and sorting domain entries...")
def merge_domain_entries(*domain_sets: FrozenSet[str]) -> Tuple[str, ...]:
    """Merges multiple sets of domains, deduplicates, and sorts alphabetically."""
    merged: Set[str] = set()
    for idx, domain_set in enumerate(domain_sets, 1):
        assert isinstance(domain_set, frozenset), f"Set #{idx} must be frozenset, got {type(domain_set)}"
        merged.update(domain_set)

    logger.info("Merged %d input domain sets into %d total unique domains", len(domain_sets), len(merged))
    return tuple(sorted(merged))


@with_spinner("Writing updated entries to blacklist file...")
def update(filepath: Path, domains: Sequence[str]) -> bool:
    """Atomically updates the blacklist file using a temporary file replacement."""
    assert isinstance(filepath, Path), f"Expected Path object, got {type(filepath)}"
    assert hasattr(domains, "__len__"), "domains must have a length"

    path = filepath.resolve()
    assert path.parent.exists(), f"Parent directory does not exist: {path.parent}"

    temp_path = path.with_suffix(".tmp")

    try:
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(domains) + ("\n" if domains else ""))

        assert temp_path.is_file(), "Temporary update file was not written properly"
        temp_path.replace(path)
        logger.info("Successfully updated %s with %d domains", path, len(domains))
        return True
    except OSError as err:
        logger.error("Error writing updated domains to %s: %s", path, err)
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        return False


def _execute_batch_delete(
    cursor: sqlite3.Cursor, query_template: str, items: Sequence[Any]
) -> int:
    """Executes chunked batch delete queries to prevent SQLite variable limits."""
    assert items, "Cannot execute batch delete on empty item sequence"
    batch_size = 900
    deleted = 0
    for i in range(0, len(items), batch_size):
        batch = items[i : i + batch_size]
        placeholders = ",".join("?" for _ in batch)
        query = query_template.format(placeholders=placeholders)
        cursor.execute(query, batch)
        deleted += cursor.rowcount

    logger.debug("Executed batch delete query. Target count: %d | Rows affected: %d", len(items), deleted)
    return deleted


@with_spinner("Purging matching domains from gravity database...")
def purge_domains(domains: Sequence[str], db_path: Path) -> int:
    """Deletes exact blocklist domains from gravity.db in atomic batch queries."""
    assert isinstance(db_path, Path), f"Expected Path object, got {type(db_path)}"
    path = db_path.resolve()

    if not path.is_file() or not domains:
        logger.info("Purge skipped: Empty domain list or missing DB file %s", path)
        return 0

    domain_set = set(domains)

    try:
        with sqlite3.connect(path, timeout=20) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("SELECT id, domain FROM domainlist WHERE type = 1;")

            target_ids = []
            target_domains = []

            for domain_id, domain_name in cursor.fetchall():
                if domain_name and domain_name.strip().lower() in domain_set:
                    target_ids.append(domain_id)
                    target_domains.append(domain_name)
                    logger.info(
                        "PURGING DOMAIN FROM DOMAINLIST: ID=%s | Domain=%s",
                        domain_id,
                        domain_name,
                    )

            if not target_ids:
                logger.info("No matching domains found in domainlist table to purge.")
                return 0

            group_query = (
                "DELETE FROM domainlist_by_group "
                "WHERE domainlist_id IN ({placeholders});"
            )
            domain_query = (
                "DELETE FROM domainlist WHERE type = 1 "
                "AND LOWER(domain) IN ({placeholders});"
            )

            with conn:
                del_groups = _execute_batch_delete(cursor, group_query, target_ids)
                deleted_count = _execute_batch_delete(
                    cursor, domain_query, target_domains
                )

            assert deleted_count == len(target_ids), f"Expected to delete {len(target_ids)} domains, deleted {deleted_count}"
            logger.info("Purged %d domains and %d group references from gravity.db", deleted_count, del_groups)
            return deleted_count
    except sqlite3.Error as err:
        logger.error("Error purging domains from gravity.db: %s", err)
        return 0


@with_spinner("Deleting targeted adlists from gravity database...")
def delete_minor_adlists(adlist_ids: Sequence[int], db_path: Path) -> bool:
    """Removes minor and empty adlists and associated group references from gravity.db."""
    assert isinstance(db_path, Path), f"Expected Path object, got {type(db_path)}"
    assert all(isinstance(i, int) for i in adlist_ids), "All adlist_ids must be integers"

    path = db_path.resolve()
    if not path.is_file() or not adlist_ids:
        logger.info("No adlist IDs supplied or DB file missing; skipping deletion.")
        return True

    logger.info("Preparing to delete %d adlists from database...", len(adlist_ids))

    try:
        with sqlite3.connect(path, timeout=20) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")

            placeholders = ",".join("?" for _ in adlist_ids)
            cursor.execute(
                f"SELECT id, address FROM adlist WHERE id IN ({placeholders});",
                list(adlist_ids),
            )
            found_records = cursor.fetchall()
            for aid, url in found_records:
                logger.warning(
                    "--> DELETING ADLIST FROM DB: ID=%s | URL=%s", aid, url
                )

            adlist_group_query = (
                "DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders});"
            )
            gravity_query = "DELETE FROM gravity WHERE adlist_id IN ({placeholders});"
            adlist_query = "DELETE FROM adlist WHERE id IN ({placeholders});"

            with conn:
                del_groups = _execute_batch_delete(cursor, adlist_group_query, adlist_ids)
                del_gravity = _execute_batch_delete(cursor, gravity_query, adlist_ids)
                del_adlists = _execute_batch_delete(cursor, adlist_query, adlist_ids)

            assert del_adlists == len(found_records), (
                f"Expected to delete {len(found_records)} adlist records, but deleted {del_adlists}"
            )

            logger.info(
                "DB PURGE COMPLETE: Removed %d adlists, %d gravity entries, %d group links",
                del_adlists,
                del_gravity,
                del_groups,
            )
            return True
    except sqlite3.Error as err:
        logger.error("Error executing adlist deletion queries: %s", err)
        return False


def _check_dns_socket(
    host: str = "127.0.0.1", port: int = 53, timeout: float = 1.0
) -> bool:
    """Verifies that local DNS port 53 is accepting TCP socket connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            logger.debug("DNS port check successful on %s:%d", host, port)
            return True
    except (OSError, socket.timeout) as err:
        logger.debug("DNS port check failed on %s:%d - %s", host, port, err)
        return False


def _wait_for_container_health(target_container: str, max_wait_sec: int = 30) -> bool:
    """Polls container state until reported healthy or running with DNS connectivity."""
    assert target_container, "Container name cannot be empty"
    start_time = time.time()

    while time.time() - start_time < max_wait_sec:
        try:
            inspect_cmd = [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}}|"
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                target_container,
            ]
            res = subprocess.run(
                inspect_cmd, capture_output=True, text=True, check=True, timeout=5
            )
            status, health = res.stdout.strip().split("|")
            logger.debug("Container %s state: Status=%s | Health=%s", target_container, status, health)

            if status == "running" and health in ("healthy", "none"):
                if _check_dns_socket():
                    logger.info("Container %s is healthy and DNS port 53 is active", target_container)
                    return True
        except (subprocess.SubprocessError, ValueError) as err:
            logger.debug("Waiting for container health check: %s", err)
        time.sleep(1)

    logger.error("Container %s health wait timed out after %d seconds", target_container, max_wait_sec)
    return False


@with_spinner("Reloading Pi-hole DNS engine & verifying service health...")
def restart_pihole_container(
    target_container: str = CONTAINER_NAME, timeout: int = 30
) -> bool:
    """Flushes FTL cache via container commands or performs restart as fallback."""
    assert target_container, "Target container name must be provided"
    logger.info("Reloading Pi-hole DNS engine in container: %s", target_container)

    try:
        res = subprocess.run(
            ["docker", "exec", target_container, "killall", "-HUP", "pihole-FTL"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        subprocess.run(
            ["docker", "exec", target_container, "pihole", "restartdns", "reload"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if res.returncode == 0 and _check_dns_socket():
            logger.info("Successfully reloaded FTL cache and verified DNS socket")
            return True
    except subprocess.SubprocessError as err:
        logger.warning("DNS reload failed; attempting full container restart: %s", err)

    try:
        subprocess.run(
            ["docker", "stop", "-t", str(timeout), target_container],
            capture_output=True,
            check=True,
            timeout=timeout + 5,
        )
        subprocess.run(
            ["docker", "start", target_container],
            capture_output=True,
            check=True,
            timeout=15,
        )
        return _wait_for_container_health(target_container, max_wait_sec=timeout)
    except (subprocess.SubprocessError, OSError) as err:
        logger.error("Error restarting container %s: %s", target_container, err)
        return False


@with_spinner("Verifying blacklist file count and gravity database state...")
def verify_updates(
    filepath: Path, expected_domains: Sequence[str], db_path: Path
) -> bool:
    """Validates line counts and confirms entries were purged from database."""
    assert isinstance(filepath, Path), f"Expected Path for filepath, got {type(filepath)}"
    assert isinstance(db_path, Path), f"Expected Path for db_path, got {type(db_path)}"

    file_path = filepath.resolve()
    db_file = db_path.resolve()

    try:
        with file_path.open("r", encoding="utf-8") as f:
            file_lines = sum(1 for line in f if line.strip())
    except OSError as err:
        logger.error("Error reading file lines from %s: %s", file_path, err)
        return False

    if file_lines != len(expected_domains):
        logger.warning(
            "VERIFICATION FAILED: Line count mismatch in %s. Expected=%d | Found=%d",
            file_path,
            len(expected_domains),
            file_lines,
        )
        return False

    batch_size = 900
    exact_match_count = 0

    try:
        with sqlite3.connect(db_file, timeout=15) as conn:
            cursor = conn.cursor()
            for i in range(0, len(expected_domains), batch_size):
                batch = expected_domains[i : i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                query = (
                    f"SELECT COUNT(*) FROM domainlist "
                    f"WHERE type = 1 AND LOWER(domain) IN ({placeholders});"
                )
                cursor.execute(query, batch)
                exact_match_count += cursor.fetchone()[0]
    except sqlite3.Error as err:
        logger.error("Error verifying database purge status: %s", err)
        return False

    assert exact_match_count == 0, f"Verification failed: {exact_match_count} domains still remain in DB domainlist"
    logger.info("Verification check passed: Blacklist count matches and DB purged successfully")
    return True


@with_spinner("Staging, committing, and pushing updates to GitHub...")
def push_to_github(filepath: Path, commit_msg: Optional[str] = None) -> bool:
    """Commits changes to Git repo using a generated hex commit message if omitted."""
    assert isinstance(filepath, Path), f"Expected Path object, got {type(filepath)}"
    path = filepath.resolve()
    repo_dir = path.parent

    if not commit_msg:
        commit_msg = secrets.token_hex(4)

    logger.info("Executing Git workflow in directory: %s", repo_dir)

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )

        if not status.stdout.strip():
            logger.info("No modified files detected in git repo; skipping push.")
            return True

        subprocess.run(
            ["git", "add", "."],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=15,
        )
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=15,
        )
        subprocess.run(
            ["git", "push"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=30,
        )

        logger.info("Git commit and push completed successfully (Commit message: %s)", commit_msg)
        return True
    except subprocess.SubprocessError as err:
        logger.error("Git operation failed: %s", err)
        return False


@with_spinner("Verifying gravity database existence...")
def check_gravity_db() -> bool:
    """Checks if gravity database exists."""
    return does_file_exist(GRAVITY_DB_PATH)


@with_spinner("Verifying blacklist file existence...")
def check_blacklist_file() -> bool:
    """Checks if blacklist file exists."""
    return does_file_exist(BLACKLIST_PATH)


@with_spinner("Verifying gravity database structure...")
def check_gravity_db_integrity() -> bool:
    """Checks if gravity database is valid."""
    return is_db(GRAVITY_DB_PATH)


def main() -> None:
    """Main execution pipeline."""
    logger.info("=== Starting Pi-hole blacklist sync and database audit ===")

    assert check_system_dependencies(), "System dependencies missing (docker/git)"
    assert check_gravity_db(), f"Gravity DB path does not exist: {GRAVITY_DB_PATH}"
    assert check_blacklist_file(), f"Blacklist file path does not exist: {BLACKLIST_PATH}"
    assert check_gravity_db_integrity(), f"Gravity DB at {GRAVITY_DB_PATH} failed integrity check"

    # 1. Deduplicate minor_lists.txt and find matching adlist IDs in DB
    existing_minor_ids = process_minor_lists_file(MINOR_LISTS_PATH, GRAVITY_DB_PATH)
    logger.info("Existing minor list DB match count: %d", len(existing_minor_ids))

    # 2. Fetch active minor blocklists (1-100 entries) from DB
    minor_ids, minor_urls = fetch_minor_blocklists(GRAVITY_DB_PATH)

    # 3. Fetch empty blocklists (0 entries) from DB
    empty_ids = fetch_empty_blocklists(GRAVITY_DB_PATH)

    # 4. Save/merge minor list origin URLs to minor_lists.txt
    if minor_urls:
        update_minor_lists_file(MINOR_LISTS_PATH, minor_urls)

    # 5. Extract domain content from minor list URLs
    minor_domains = pull_and_parse_minor_list_domains(MINOR_LISTS_PATH)

    # 6. Parse blacklist file and existing type-1 domains from DB
    file_entries = parse_blacklist(BLACKLIST_PATH)
    db_entries = load_gravity_db_entries(GRAVITY_DB_PATH)

    # 7. Merge all domain sets into deduplicated tuple
    combined_domains = merge_domain_entries(file_entries, db_entries, minor_domains)
    assert len(combined_domains) >= len(file_entries), "Combined set cannot be smaller than existing blacklist file"

    # 8. Write updated merged entries back to blacklist file
    assert update(BLACKLIST_PATH, combined_domains), "Failed to write blacklist file"

    # 9. Purge exact block domains from domainlist table in gravity DB
    purged_count = purge_domains(combined_domains, GRAVITY_DB_PATH)
    logger.info("Total exact block domains purged from DB: %d", purged_count)

    # 10. Delete matched minor, new minor, and empty adlists from DB
    all_adlists_to_delete = list(set(minor_ids + empty_ids + existing_minor_ids))
    logger.info("Target deletion list IDs (Merged): %s", all_adlists_to_delete)

    if all_adlists_to_delete:
        assert delete_minor_adlists(all_adlists_to_delete, GRAVITY_DB_PATH), "Failed to delete adlists"

    assert verify_updates(BLACKLIST_PATH, combined_domains, GRAVITY_DB_PATH), "Verification failed"
    assert restart_pihole_container(CONTAINER_NAME), "Failed to reload or restart Pi-hole container"

    commit_hex = secrets.token_hex(4)
    push_to_github(BLACKLIST_PATH, commit_msg=commit_hex)

    logger.info("=== Sync pipeline completed successfully ===")


if __name__ == "__main__":
    main()
