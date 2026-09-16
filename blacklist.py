import os
import re
import sys
import time
import socket
import sqlite3
import threading
import logging
import subprocess
import shutil
from pathlib import Path
from functools import wraps
from typing import Callable, Any, TypeVar, cast, Sequence, Set, FrozenSet, Tuple, Optional

# --- Configuration & Environment Defaults ---
GRAVITY_DB_PATH = Path(os.getenv("PIHOLE_GRAVITY_DB", "/root/pihole/etc-pihole/gravity.db")).resolve()
BLACKLIST_PATH = Path(os.getenv("PIHOLE_BLACKLIST_FILE", Path(__file__).parent / "blacklist.txt")).resolve()
CONTAINER_NAME = os.getenv("PIHOLE_CONTAINER_NAME", "pihole")

IS_VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO if IS_VERBOSE else logging.CRITICAL + 1,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("pihole_blacklist")

F = TypeVar('F', bound=Callable[..., Any])

# --- Terminal Spinner UI ---
class TerminalSpinner:
    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.delay = 0.08
        self._running = False
        self._spinner_thread: Optional[threading.Thread] = None
        self._is_tty = sys.stdout.isatty() and IS_VERBOSE

    def _spin(self) -> None:
        i = 0
        while self._running:
            char = self.spinner_chars[i % len(self.spinner_chars)]
            sys.stdout.write(f"\r  [{char}] {self.message}")
            sys.stdout.flush()
            time.sleep(self.delay)
            i += 1

    def start(self) -> None:
        if not IS_VERBOSE:
            return
        if not self._is_tty:
            logger.info(f"{self.message} (Started)")
            return
        self._running = True
        self._spinner_thread = threading.Thread(target=self._spin, daemon=True)
        self._spinner_thread.start()

    def stop(self, success: bool = True) -> None:
        if not IS_VERBOSE:
            return
        if not self._is_tty:
            status = "Completed" if success else "Failed"
            logger.info(f"{self.message} ({status})")
            return
        self._running = False
        if self._spinner_thread and self._spinner_thread.is_alive():
            self._spinner_thread.join()

        icon = "\033[92m\u2714\033[0m" if success else "\033[91m\u2718\033[0m"
        sys.stdout.write(f"\r  [{icon}] {self.message}\n")
        sys.stdout.flush()

def with_spinner(message: str = "Loading...") -> Callable[[F], F]:
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
            except Exception as e:
                spinner.stop(success=False)
                logger.exception(f"Unhandled exception in '{func.__name__}': {e}")
                return False
        return cast(F, wrapper)
    return decorator

# --- System & DB Health Verification ---
def check_system_dependencies() -> bool:
    """Verifies all required CLI dependencies are present in system PATH."""
    required_cmds = ["docker", "git"]
    missing = [cmd for cmd in required_cmds if shutil.which(cmd) is None]
    if missing:
        logger.error(f"Missing required system binaries: {', '.join(missing)}")
        return False
    return True

def does_file_exist(filepath: Path) -> bool:
    """Verifies that a path exists and is a regular file."""
    try:
        path = Path(filepath).resolve()
        return path.is_file() and path.stat().st_size > 0
    except (TypeError, ValueError, OSError) as exc:
        logger.debug(f"File validation failed for {filepath}: {exc}")
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
    except (sqlite3.Error, OSError) as exc:
        logger.debug(f"SQLite validation failed for {filepath}: {exc}")
        return False

# --- Core Task Functions ---
@with_spinner("Parsing and validating blacklist file entries...")
def parse_blacklist(filepath: Path) -> FrozenSet[str]:
    """Reads and sanitizes domain entries from the blacklist file."""
    path = Path(filepath).resolve()
    if not path.is_file():
        logger.error(f"Blacklist file not found: {path}")
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
                elif cleaned_line:
                    logger.debug(f"Filtered invalid domain entry: '{cleaned_line}'")
    except OSError as exc:
        logger.error(f"Error reading blacklist file {path}: {exc}")
        return frozenset()

    return frozenset(cleaned_entries)

@with_spinner("Fetching existing blocklist entries from gravity database...")
def load_gravity_db_entries(db_path: Path) -> FrozenSet[str]:
    """Retrieves unique exact block (type 1) and wildcard block (type 3) domains from gravity.db."""
    path = Path(db_path).resolve()
    uri = f"file:{path.as_posix()}?mode=ro"
    db_domains: Set[str] = set()

    try:
        with sqlite3.connect(uri, uri=True, timeout=20) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM domainlist WHERE type IN (1, 3);")
            for (domain,) in cursor.fetchall():
                if domain:
                    cleaned = domain.strip().lower()
                    if cleaned:
                        db_domains.add(cleaned)
    except sqlite3.Error as exc:
        logger.error(f"Database error reading gravity DB {path}: {exc}")
        return frozenset()

    return frozenset(db_domains)

@with_spinner("Merging, deduplicating, and sorting domain entries...")
def merge_domain_entries(set_a: FrozenSet[str], set_b: FrozenSet[str]) -> Tuple[str, ...]:
    """Merges two sets of domains, deduplicates them, and sorts alphabetically."""
    return tuple(sorted(set_a.union(set_b)))

@with_spinner("Writing updated entries to blacklist file...")
def update(filepath: Path, domains: Sequence[str]) -> bool:
    """Atomically updates the blacklist file using a temporary file replacement."""
    path = Path(filepath).resolve()
    temp_path = path.with_suffix('.tmp')

    try:
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(domains) + ("\n" if domains else ""))
        temp_path.replace(path)
        return True
    except OSError as exc:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        logger.error(f"Atomic update failed for {path}: {exc}")
        return False

@with_spinner("Purging matching domains from gravity database...")
def purge_domains(domains: Sequence[str], db_path: Path) -> int:
    """Deletes targeted blocklist domains from gravity.db in chunked batch queries."""
    path = Path(db_path).resolve()
    if not path.is_file() or not domains:
        return 0

    deleted_count = 0
    domain_set = set(domains)

    try:
        with sqlite3.connect(path, timeout=20) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("SELECT id, domain FROM domainlist WHERE type IN (1, 3);")
            
            target_ids = []
            target_domains = []

            for domain_id, domain_name in cursor.fetchall():
                if domain_name and domain_name.strip().lower() in domain_set:
                    target_ids.append(domain_id)
                    target_domains.append(domain_name)

            if not target_ids:
                return 0

            batch_size = 900
            for i in range(0, len(target_ids), batch_size):
                batch = target_ids[i : i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                cursor.execute(f"DELETE FROM domainlist_by_group WHERE domainlist_id IN ({placeholders});", batch)

            for i in range(0, len(target_domains), batch_size):
                batch = target_domains[i : i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                cursor.execute(f"DELETE FROM domainlist WHERE type IN (1, 3) AND LOWER(domain) IN ({placeholders});", batch)
                deleted_count += cursor.rowcount

            conn.commit()
    except sqlite3.Error as exc:
        logger.error(f"Failed to purge domains from gravity DB: {exc}")
        return False

    return deleted_count

def _check_dns_socket(host: str = "127.0.0.1", port: int = 53, timeout: float = 1.0) -> bool:
    """Verifies that local DNS port 53 is accepting TCP socket connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def _wait_for_container_health(target_container: str, max_wait_sec: int = 30) -> bool:
    """Polls container state until reported healthy or running with active socket connectivity."""
    start_time = time.time()
    while time.time() - start_time < max_wait_sec:
        try:
            inspect_cmd = [
                "docker", "inspect",
                "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                target_container
            ]
            res = subprocess.run(inspect_cmd, capture_output=True, text=True, check=True)
            status, health = res.stdout.strip().split("|")

            if status == "running" and health in ("healthy", "none"):
                if _check_dns_socket():
                    return True
        except (subprocess.SubprocessError, ValueError):
            pass
        time.sleep(1)
    return False

@with_spinner("Reloading Pi-hole DNS engine & verifying service health...")
def restart_pihole_container(target_container: str = CONTAINER_NAME, timeout: int = 30) -> bool:
    """Flushes FTL cache via container commands or performs container restart as fallback."""
    try:
        res = subprocess.run(["docker", "exec", target_container, "killall", "-HUP", "pihole-FTL"], capture_output=True, text=True, timeout=10)
        subprocess.run(["docker", "exec", target_container, "pihole", "restartdns", "reload"], capture_output=True, text=True, timeout=10)

        if res.returncode == 0 and _check_dns_socket():
            return True
    except subprocess.SubprocessError as exc:
        logger.warning(f"Fast reload failed ({exc}). Falling back to container restart...")

    try:
        subprocess.run(["docker", "stop", "-t", str(timeout), target_container], capture_output=True, check=True, timeout=timeout + 5)
        subprocess.run(["docker", "start", target_container], capture_output=True, check=True, timeout=15)
        return _wait_for_container_health(target_container, max_wait_sec=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error(f"Failed to restart container '{target_container}': {exc}")
        return False

@with_spinner("Verifying blacklist file count and gravity database state...")
def verify_updates(filepath: Path, expected_domains: Sequence[str], db_path: Path) -> bool:
    """Validates line counts and confirms target entries were successfully purged from database."""
    file_path = Path(filepath).resolve()
    db_file = Path(db_path).resolve()

    try:
        with file_path.open("r", encoding="utf-8") as f:
            file_lines = sum(1 for line in f if line.strip())
    except OSError as exc:
        logger.error(f"File count verification failed: {exc}")
        return False

    if file_lines != len(expected_domains):
        logger.error(f"Mismatch: expected {len(expected_domains)} lines in file, found {file_lines}.")
        return False

    batch_size = 900
    exact_match_count = 0

    try:
        with sqlite3.connect(db_file, timeout=15) as conn:
            cursor = conn.cursor()
            for i in range(0, len(expected_domains), batch_size):
                batch = expected_domains[i : i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                query = f"SELECT COUNT(*) FROM domainlist WHERE type = 1 AND LOWER(domain) IN ({placeholders});"
                cursor.execute(query, batch)
                exact_match_count += cursor.fetchone()[0]
    except sqlite3.Error as exc:
        logger.error(f"Database verification check failed: {exc}")
        return False

    if exact_match_count != 0:
        logger.error(f"Verification failed: {exact_match_count} exact block entries remain in gravity DB.")
        return False

    return True

@with_spinner("Staging, committing, and pushing blacklist to GitHub...")
def push_to_github(filepath: Path, commit_msg: str = "Automated update of blacklist.txt") -> bool:
    """Commissions changes to Git repository if modifications are detected."""
    path = Path(filepath).resolve()
    repo_dir = path.parent

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain", path.name],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=True
        )

        if not status.stdout.strip():
            logger.info("No git changes detected in blacklist.txt.")
            return True

        subprocess.run(["git", "add", path.name], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "push"], cwd=repo_dir, check=True, capture_output=True)

        return True
    except subprocess.CalledProcessError as exc:
        err_out = exc.stderr.strip() if exc.stderr else str(exc)
        logger.error(f"Git operation failed: {err_out}")
        return False

@with_spinner("Verifying gravity database existence...")
def check_gravity_db() -> bool:
    return does_file_exist(GRAVITY_DB_PATH)

@with_spinner("Verifying blacklist file existence...")
def check_blacklist_file() -> bool:
    return does_file_exist(BLACKLIST_PATH)

@with_spinner("Verifying gravity database structure...")
def check_gravity_db_integrity() -> bool:
    return is_db(GRAVITY_DB_PATH)

def main() -> None:
    if not check_system_dependencies():
        sys.exit(1)

    if not (check_gravity_db() and check_blacklist_file() and check_gravity_db_integrity()):
        logger.error("Environment check failed: missing database or invalid file format.")
        sys.exit(1)

    file_entries = parse_blacklist(BLACKLIST_PATH)
    db_entries = load_gravity_db_entries(GRAVITY_DB_PATH)

    if file_entries is False or db_entries is False:
        logger.error("Failed to parse initial datasets. Execution aborted.")
        sys.exit(1)

    combined_domains = merge_domain_entries(file_entries, db_entries)

    if not update(BLACKLIST_PATH, combined_domains):
        logger.error("Failed to write updated blacklist file.")
        sys.exit(1)

    purged_count = purge_domains(combined_domains, GRAVITY_DB_PATH)

    if purged_count is False:
        logger.error("Database purge operation failed.")
        sys.exit(1)

    if purged_count == 0:
        if IS_VERBOSE:
            print("\n[!] 0 matching domains found to purge. Skipping container restart.")
            print("\nSuccessfully executed.")
        sys.exit(0)

    verification_passed = verify_updates(BLACKLIST_PATH, combined_domains, GRAVITY_DB_PATH)
    container_restarted = restart_pihole_container(CONTAINER_NAME)
    github_pushed = push_to_github(BLACKLIST_PATH, f"Auto-update: synchronized {len(combined_domains)} entries")

    if IS_VERBOSE:
        print(
            f"\nPipeline execution summary:\n"
            f" - Updated blacklist.txt: {len(combined_domains)} unique entries\n"
            f" - Purged gravity DB entries: {purged_count}\n"
            f" - Verification: {'Passed' if verification_passed else 'Failed'}\n"
            f" - Container Restart ({CONTAINER_NAME}): {'Success' if container_restarted else 'Failed'}\n"
            f" - GitHub Push: {'Success' if github_pushed else 'Failed'}\n"
            f"\nSuccessfully executed."
        )

if __name__ == "__main__":
    main()
