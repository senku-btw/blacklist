"""Pi-hole blocklist sync, minor list consolidation, and DB purging tool."""

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
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, TypeVar, cast

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

# --- Logging Configuration (Disabled globally) ---
logging_module = __import__("logging")
logging_module.disable(logging_module.CRITICAL)
logger = logging_module.getLogger("pihole_blacklist")

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
    """Decorator that wraps function execution with terminal spinner visual feedback."""

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
            except Exception:  # pylint: disable=broad-exception-caught
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
        return False
    return True


def does_file_exist(filepath: Path) -> bool:
    """Verifies that a path exists and is a regular file."""
    try:
        path = Path(filepath).resolve()
        return path.is_file() and path.stat().st_size > 0
    except (TypeError, ValueError, OSError):
        return False


def is_db(filepath: Path) -> bool:
    """Validates if a file is a non-corrupt SQLite3 database."""
    try:
        path = Path(filepath).resolve()
        if not path.is_file() or path.stat().st_size < 512:
            return False

        with path.open("rb") as f:
            if f.read(16) != b"SQLite format 3\x00":
                return False

        uri = f"file:{path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            conn.execute("SELECT count(*) FROM sqlite_schema;")
        return True
    except (sqlite3.Error, OSError):
        return False


# --- Core Task Functions ---
@with_spinner("Parsing and validating blacklist file entries...")
def parse_blacklist(filepath: Path) -> FrozenSet[str]:
    """Reads and sanitizes domain entries from the blacklist file."""
    path = Path(filepath).resolve()
    if not path.is_file():
        return frozenset()

    cleaned_entries: Set[str] = set()
    invisible_chars_re = re.compile(r"[\s\u200b\ufeff\u200e\u200f]+")
    domain_re = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                raw_line = line.split("#", 1)[0].strip()
                if not raw_line:
                    continue

                raw_line = raw_line.replace("https://", "").replace("http://", "")
                raw_line = raw_line.split("/")[0].split(":")[0]
                cleaned_line = invisible_chars_re.sub("", raw_line).lower()

                if domain_re.match(cleaned_line):
                    cleaned_entries.add(cleaned_line)
    except OSError:
        return frozenset()

    return frozenset(cleaned_entries)


@with_spinner("Identifying minor blocklists (1-20 entries) in gravity database...")
def fetch_minor_blocklists(db_path: Path) -> Tuple[List[int], List[str]]:
    """Identifies blocklists in gravity.db that contain between 1 and 20 domain entries."""
    path = Path(db_path).resolve()
    uri = f"file:{path.as_posix()}?mode=ro"

    minor_ids: List[int] = []
    minor_urls: List[str] = []

    try:
        with sqlite3.connect(uri, uri=True, timeout=20) as conn:
            cursor = conn.cursor()
            query = """
                SELECT a.id, a.address 
                FROM adlist a 
                JOIN gravity g ON a.id = g.adlist_id 
                GROUP BY a.id, a.address 
                HAVING COUNT(g.domain) >= 1 AND COUNT(g.domain) <= 20;
            """
            cursor.execute(query)
            for adlist_id, address in cursor.fetchall():
                if address:
                    minor_ids.append(adlist_id)
                    minor_urls.append(address.strip())
    except sqlite3.Error:
        pass

    return minor_ids, minor_urls


@with_spinner("Storing origin URLs of minor lists to file...")
def update_minor_lists_file(filepath: Path, urls: Sequence[str]) -> bool:
    """Saves and deduplicates origin URLs to the designated minor lists file."""
    path = Path(filepath).resolve()
    existing_urls: Set[str] = set()

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        existing_urls.add(cleaned)
        except OSError:
            pass

    existing_urls.update(u for u in urls if u)
    sorted_urls = sorted(existing_urls)

    temp_path = path.with_suffix(".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(sorted_urls) + ("\n" if sorted_urls else ""))
        temp_path.replace(path)
        return True
    except OSError:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        return False


def _fetch_minor_list_domains(url: str, headers: Dict[str, str]) -> Set[str]:
    """Fetches and parses a single minor list URL for valid domains."""
    domains: Set[str] = set()
    invisible_chars_re = re.compile(r"[\s\u200b\ufeff\u200e\u200f]+")
    domain_re = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
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
    except (urllib.error.URLError, OSError, TimeoutError):
        pass
        
    return domains


@with_spinner("Pulling and parsing content from minor list URLs...")
def pull_and_parse_minor_list_domains(filepath: Path) -> FrozenSet[str]:
    """Downloads content from all minor list URLs and extracts unique domain entries."""
    path = Path(filepath).resolve()
    if not path.is_file():
        return frozenset()

    urls: List[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file:
            urls = [line.strip() for line in file if line.strip() and not line.startswith("#")]
    except OSError:
        return frozenset()

    extracted_domains: Set[str] = set()
    headers = {"User-Agent": "Mozilla/5.0 (Pi-hole Blocklist Consolidation Tool)"}

    for url in urls:
        extracted_domains.update(_fetch_minor_list_domains(url, headers))

    return frozenset(extracted_domains)


@with_spinner("Fetching existing blocklist entries from gravity database...")
def load_gravity_db_entries(db_path: Path) -> FrozenSet[str]:
    """Retrieves unique exact block (type 1) domains from gravity.db."""
    path = Path(db_path).resolve()
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
    except sqlite3.Error:
        return frozenset()

    return frozenset(db_domains)


@with_spinner("Merging, deduplicating, and sorting domain entries...")
def merge_domain_entries(
    *domain_sets: FrozenSet[str],
) -> Tuple[str, ...]:
    """Merges multiple sets of domains, deduplicates them, and sorts alphabetically."""
    merged: Set[str] = set()
    for domain_set in domain_sets:
        merged.update(domain_set)
    return tuple(sorted(merged))


@with_spinner("Writing updated entries to blacklist file...")
def update(filepath: Path, domains: Sequence[str]) -> bool:
    """Atomically updates the blacklist file using a temporary file replacement."""
    path = Path(filepath).resolve()
    temp_path = path.with_suffix(".tmp")

    try:
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(domains) + ("\n" if domains else ""))
        temp_path.replace(path)
        return True
    except OSError:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        return False


def _execute_batch_delete(
    cursor: sqlite3.Cursor, query_template: str, items: Sequence[Any]
) -> int:
    """Executes chunked batch delete queries to prevent SQLite variable limits."""
    batch_size = 900
    deleted = 0
    for i in range(0, len(items), batch_size):
        batch = items[i : i + batch_size]
        placeholders = ",".join("?" for _ in batch)
        cursor.execute(query_template.format(placeholders=placeholders), batch)
        deleted += cursor.rowcount
    return deleted


@with_spinner("Purging matching domains from gravity database...")
def purge_domains(domains: Sequence[str], db_path: Path) -> int:
    """Deletes exact blocklist domains from gravity.db in chunked batch queries."""
    path = Path(db_path).resolve()
    if not path.is_file() or not domains:
        return 0

    deleted_count = 0
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

            if not target_ids:
                return 0

            group_query = (
                "DELETE FROM domainlist_by_group "
                "WHERE domainlist_id IN ({placeholders});"
            )
            domain_query = (
                "DELETE FROM domainlist WHERE type = 1 "
                "AND LOWER(domain) IN ({placeholders});"
            )

            _execute_batch_delete(cursor, group_query, target_ids)
            deleted_count = _execute_batch_delete(
                cursor, domain_query, target_domains
            )

            conn.commit()
    except sqlite3.Error:
        return False

    return deleted_count


@with_spinner("Deleting minor blocklists from gravity database...")
def delete_minor_adlists(adlist_ids: Sequence[int], db_path: Path) -> bool:
    """Removes minor adlist records and associated domain/group references from gravity.db."""
    path = Path(db_path).resolve()
    if not path.is_file() or not adlist_ids:
        return True

    try:
        with sqlite3.connect(path, timeout=20) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")

            adlist_group_query = (
                "DELETE FROM adlist_by_group WHERE adlist_id IN ({placeholders});"
            )
            gravity_query = (
                "DELETE FROM gravity WHERE adlist_id IN ({placeholders});"
            )
            adlist_query = (
                "DELETE FROM adlist WHERE id IN ({placeholders});"
            )

            _execute_batch_delete(cursor, adlist_group_query, adlist_ids)
            _execute_batch_delete(cursor, gravity_query, adlist_ids)
            _execute_batch_delete(cursor, adlist_query, adlist_ids)

            conn.commit()
            return True
    except sqlite3.Error:
        return False


def _check_dns_socket(
    host: str = "127.0.0.1", port: int = 53, timeout: float = 1.0
) -> bool:
    """Verifies that local DNS port 53 is accepting TCP socket connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _wait_for_container_health(
    target_container: str, max_wait_sec: int = 30
) -> bool:
    """Polls container state until reported healthy or running with active socket connectivity."""
    start_time = time.time()
    while time.time() - start_time < max_wait_sec:
        try:
            inspect_cmd = [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                target_container,
            ]
            res = subprocess.run(
                inspect_cmd, capture_output=True, text=True, check=True
            )
            status, health = res.stdout.strip().split("|")

            if status == "running" and health in ("healthy", "none"):
                if _check_dns_socket():
                    return True
        except (subprocess.SubprocessError, ValueError):
            pass
        time.sleep(1)
    return False


@with_spinner("Reloading Pi-hole DNS engine & verifying service health...")
def restart_pihole_container(
    target_container: str = CONTAINER_NAME, timeout: int = 30
) -> bool:
    """Flushes FTL cache via container commands or performs container restart as fallback."""
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
            return True
    except subprocess.SubprocessError:
        pass

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
    except (subprocess.SubprocessError, OSError):
        return False


@with_spinner("Verifying blacklist file count and gravity database state...")
def verify_updates(
    filepath: Path, expected_domains: Sequence[str], db_path: Path
) -> bool:
    """Validates line counts and confirms target entries were successfully purged from database."""
    file_path = Path(filepath).resolve()
    db_file = Path(db_path).resolve()

    try:
        with file_path.open("r", encoding="utf-8") as f:
            file_lines = sum(1 for line in f if line.strip())
    except OSError:
        return False

    if file_lines != len(expected_domains):
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
    except sqlite3.Error:
        return False

    if exact_match_count != 0:
        return False

    return True


@with_spinner("Staging, committing, and pushing updates to GitHub...")
def push_to_github(
    filepath: Path, commit_msg: Optional[str] = None
) -> bool:
    """Commits changes to Git repo using a generated hex commit message if omitted."""
    path = Path(filepath).resolve()
    repo_dir = path.parent

    # Generate an 8-character hex code if no custom message is provided
    if not commit_msg:
        commit_msg = secrets.token_hex(4)

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=True,
        )

        if not status.stdout.strip():
            return True

        subprocess.run(
            ["git", "add", "."],
            cwd=repo_dir,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=repo_dir,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "push"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
        )

        return True
    except subprocess.CalledProcessError:
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
    if not check_system_dependencies():
        sys.exit(1)

    if not (
        check_gravity_db()
        and check_blacklist_file()
        and check_gravity_db_integrity()
    ):
        sys.exit(1)

    # 1. Detect minor blocklists (1–20 entries) from gravity DB
    minor_ids, minor_urls = fetch_minor_blocklists(GRAVITY_DB_PATH)

    # 2. Save/merge minor list origin URLs to minor_lists.txt
    if minor_urls:
        update_minor_lists_file(MINOR_LISTS_PATH, minor_urls)

    # 3. Pull minor list contents from origin URLs and extract unique domains
    minor_domains = pull_and_parse_minor_list_domains(MINOR_LISTS_PATH)

    # 4. Parse existing blacklist entries and gravity DB type-1 domains
    file_entries = parse_blacklist(BLACKLIST_PATH)
    db_entries = load_gravity_db_entries(GRAVITY_DB_PATH)

    if file_entries is False or db_entries is False:
        sys.exit(1)

    # 5. Merge all domain sources (file, DB exact blocks, minor adlists) into a deduplicated set
    combined_domains = merge_domain_entries(file_entries, db_entries, minor_domains)

    # 6. Write merged domains to blacklist.txt
    if not update(BLACKLIST_PATH, combined_domains):
        sys.exit(1)

    # 7. Delete exact block domains from domainlist table in gravity.db
    purged_count = purge_domains(combined_domains, GRAVITY_DB_PATH)
    if purged_count is False:
        sys.exit(1)

    # 8. Delete the minor adlists from gravity DB
    if minor_ids:
        delete_minor_adlists(minor_ids, GRAVITY_DB_PATH)

    verify_updates(BLACKLIST_PATH, combined_domains, GRAVITY_DB_PATH)
    restart_pihole_container(CONTAINER_NAME)

    # Generate 8-character hex commit string (e.g. "1ba0037a")
    commit_hex = secrets.token_hex(4)
    push_to_github(
        BLACKLIST_PATH,
        commit_msg=commit_hex,
    )


if __name__ == "__main__":
    main()
