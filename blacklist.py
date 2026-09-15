import os
import re
import sys
import time
import random
import socket
import sqlite3
import threading
import logging
import subprocess
import shutil
from pathlib import Path
from functools import wraps
from typing import Callable, Any, TypeVar, cast

# Paths
gravitydb = Path("/root/pihole/etc-pihole/gravity.db")
blacklist = (Path(__file__).parent / "blacklist.txt").resolve()
container_name = os.getenv("PIHOLE_CONTAINER_NAME", "pihole")

# Verbose mode detection
is_verbose = "--verbose" in sys.argv or "-v" in sys.argv

# Configure Logging
logging.basicConfig(
    level=logging.INFO if is_verbose else logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])

def print_final_status() -> None:
    """Prints the execution status message, including a blank line only in verbose mode."""
    if is_verbose:
        print()
    print("Successfully executed.")

class TerminalSpinner:
    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.delay = 0.1
        self._running = False
        self._spinner_thread: threading.Thread | None = None
        self._is_tty = sys.stdout.isatty() and is_verbose

    def _spin(self) -> None:
        i = 0
        while self._running:
            char = self.spinner_chars[i % len(self.spinner_chars)]
            sys.stdout.write(f"\r  [{char}] {self.message}")
            sys.stdout.flush()
            time.sleep(self.delay)
            i += 1

    def start(self) -> None:
        if not is_verbose:
            return

        if not self._is_tty:
            logger.info(f"{self.message} (Started)")
            return

        self._running = True
        self._spinner_thread = threading.Thread(target=self._spin, daemon=True)
        self._spinner_thread.start()

    def stop(self, success: bool = True) -> None:
        if not is_verbose:
            return

        if not self._is_tty:
            status = "Completed" if success else "Failed"
            logger.info(f"{self.message} ({status})")
            return

        self._running = False
        if self._spinner_thread:
            self._spinner_thread.join()

        if success:
            sys.stdout.write(f"\r  [\033[92m\u2714\033[0m] {self.message}\n")
        else:
            sys.stdout.write(f"\r  [\033[91m\u2718\033[0m] {self.message}\n")
        
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
                logger.exception(f"Exception occurred in {func.__name__}: {e}")
                return False
        return cast(F, wrapper)
    return decorator

def check_system_dependencies() -> bool:
    """Ensures required system binaries are available in PATH."""
    required_cmds = ["docker", "git"]
    for cmd in required_cmds:
        if shutil.which(cmd) is None:
            logger.error(f"Critical dependency '{cmd}' is missing from system PATH.")
            return False
    return True

def does_file_exist(filepath: Path | str) -> bool:
    """Verifies that a filepath is valid, exists, and points strictly to a regular file."""
    if not filepath or not str(filepath).strip():
        return False
    try:
        return Path(filepath).is_file()
    except (TypeError, ValueError, OSError):
        return False

def is_db(filepath: Path | str) -> bool:
    """
    Rigorously evaluates if a filepath points to a valid, structurally sound SQLite 3 database.
    Uses a lightweight engine-level query to confirm usability.
    """
    try:
        path = Path(filepath).resolve()
        
        # 1. File health and minimum size check
        # A valid SQLite DB must be at least one page. The absolute minimum page size is 512 bytes.
        if not path.is_file() or path.stat().st_size < 512:
            return False

        # 2. Magic header check (Fast-fail for text files, binaries, etc.)
        with open(path, "rb") as f:
            if f.read(16) != b"SQLite format 3\x00":
                return False

        # 3. Engine-level parse check
        # mode=ro ensures we NEVER accidentally create a file if it doesn't exist
        # timeout=5 prevents hanging if the file system is locked
        uri = f"file:{path.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=5) as conn:
            cursor = conn.cursor()
            # Attempting to read the schema instantly verifies that the internal b-tree 
            # structure of the database is intact and readable by the SQLite engine.
            cursor.execute("SELECT count(*) FROM sqlite_schema;")
            cursor.fetchone()
            
        return True

    except sqlite3.DatabaseError as e:
        # Specifically catches SQLite corruption errors (e.g., "database disk image is malformed")
        logger.debug(f"SQLite engine rejected the file {filepath}: {e}")
        return False
    except OSError as e:
        # Catches file permission errors, missing files, or disk IO issues
        logger.debug(f"OS error while accessing {filepath}: {e}")
        return False
    except Exception as e:
        # Failsafe for any other unexpected errors
        logger.debug(f"Unexpected error validating SQLite file {filepath}: {e}")
        return False

@with_spinner("Reading, sanitizing, and validating blacklist file entries...")
def parse_blacklist(filepath: Path | str) -> frozenset[str]:
    """Reads a blacklist file, strips comments/URLs, sanitizes inputs, and validates domain formats."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(filepath).resolve()
    cleaned_entries: set[str] = set()

    if not path.is_file():
        logger.error(f"Blacklist file not found: {path}")
        return frozenset()

    # Compile regexes locally to keep the global namespace clean.
    # Compiled once per function call, before the loop starts.
    invisible_chars_re = re.compile(r"[\s\u200b\ufeff\u200e\u200f]+")
    
    # Matches a valid standard domain name (RFC 1123)
    domain_re = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            # 1. Strip comments first
            raw_line = line.split("#", 1)[0]
            
            # Fast pre-check: skip immediately if the line is empty or just whitespace
            if not raw_line.strip():
                continue
                
            # 2. Handle accidental URL pastes
            raw_line = raw_line.replace("https://", "").replace("http://", "")
            raw_line = raw_line.split("/")[0].split(":")[0]
            
            # 3. Sanitize: Remove invisible chars & convert to lowercase
            cleaned_line = invisible_chars_re.sub("", raw_line).lower()
            
            # 4. Strict Domain Validation
            if domain_re.match(cleaned_line):
                cleaned_entries.add(cleaned_line)
            elif cleaned_line:
                logger.debug(f"Dropped malformed domain entry: '{cleaned_line}'")

    return frozenset(cleaned_entries)

@with_spinner("Fetching existing blacklist entries from Pi-hole database...")
def load_gravity_db_entries(db_path: Path | str) -> frozenset[str]:
    """Retrieves unique, sanitized blacklisted domains from Pi-hole gravity.db."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(db_path).resolve()
    uri = f"file:{path.as_posix()}?mode=ro"
    db_domains: set[str] = set()

    with sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=20) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM domainlist WHERE type IN (1, 3);")
        for row in cursor.fetchall():
            if row[0]:
                cleaned = row[0].strip().lower()
                if cleaned:
                    db_domains.add(cleaned)

    return frozenset(db_domains)

@with_spinner("Found no new domains in the gravity.db....")
def notify_no_new_domains() -> bool:
    """Displays completion spinner when no new domains are detected in the gravity database."""
    time.sleep(random.uniform(0.5, 0.8))
    return True

@with_spinner("Merging, deduplicating, and sorting domain entries...")
def merge_domain_entries(set_a: frozenset[str], set_b: frozenset[str]) -> tuple[str, ...]:
    """Merges two domain sets, eliminates all duplicates, and returns an alphabetically sorted tuple."""
    time.sleep(random.uniform(0.8, 1.3))
    return tuple(sorted(set_a.union(set_b)))

@with_spinner("Writing clean, unique, sorted entries to blacklist file...")
def update(filepath: Path | str, domains: tuple[str, ...]) -> bool:
    """Overwrites blacklist.txt atomically to prevent corruption during system crashes."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(filepath).resolve()
    temp_path = path.with_suffix('.tmp')

    try:
        with temp_path.open("w", encoding="utf-8") as file:
            file.write("\n".join(domains) + "\n")
        
        # Atomic replacement ensures file integrity
        temp_path.replace(path)
        return True
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"Failed to update blacklist atomically: {e}")
        raise

@with_spinner("Purging matching domains from gravity database and updating counters...")
def purge_domains(domains: tuple[str, ...], db_path: Path | str, target_container: str = container_name) -> int:
    """Purges matching domains from gravity.db and flushes FTL shared memory counters."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(db_path).resolve()

    if not path.is_file() or not domains:
        return 0

    deleted_count = 0
    domain_set = set(domains)

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

    # Force FTL to flush name cache and reset dashboard metrics
    try:
        subprocess.run(["docker", "exec", target_container, "pihole", "restartdns", "reload"], capture_output=True, text=True, timeout=15)
        subprocess.run(["docker", "exec", target_container, "pihole-FTL", "cc", "flush-name-cache"], capture_output=True, text=True, timeout=15)
    except subprocess.SubprocessError as exc:
        logger.warning(f"Failed to reset FTL dashboard cache: {exc}")

    return deleted_count

def _check_dns_socket(host: str = "127.0.0.1", port: int = 53, timeout: float = 1.0) -> bool:
    """Verifies that the DNS port is responding to TCP sockets."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def _wait_for_container_health(target_container: str, max_wait_sec: int = 30) -> bool:
    """Polls container state until status is running and healthcheck (if configured) is healthy."""
    start_time = time.time()
    while time.time() - start_time < max_wait_sec:
        try:
            inspect_cmd = ["docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", target_container]
            res = subprocess.run(inspect_cmd, capture_output=True, text=True, check=True)
            status, health = res.stdout.strip().split("|")
            
            if status == "running" and health in ("healthy", "none"):
                if _check_dns_socket():
                    return True
        except subprocess.SubprocessError:
            pass
        time.sleep(1)
    return False

@with_spinner("Reloading Pi-hole DNS engine & verifying service health...")
def restart_pihole_container(target_container: str = container_name, timeout: int = 30) -> bool:
    """Forces FTL to flush shared memory, restarts web server daemons, and verifies health."""
    time.sleep(random.uniform(0.5, 1.0))
    
    # Strategy 1: Signal FTL, flush cache, and restart web services inside container
    try:
        res = subprocess.run(["docker", "exec", target_container, "killall", "-HUP", "pihole-FTL"], capture_output=True, text=True, timeout=10)
        subprocess.run(["docker", "exec", target_container, "pihole", "restartdns", "reload"], capture_output=True, text=True, timeout=10)
        subprocess.run(["docker", "exec", target_container, "service", "lighttpd", "reload"], capture_output=True, text=True, timeout=10)

        if res.returncode == 0 and _check_dns_socket():
            return True
    except subprocess.SubprocessError as exc:
        logger.warning(f"SIGHUP cache flush failed ({exc}). Trying container restart fallback.")

    # Strategy 2: Complete container restart with graceful stop/start sequence
    try:
        subprocess.run(["docker", "stop", "-t", str(timeout), target_container], capture_output=True, check=True, timeout=timeout + 5)
        subprocess.run(["docker", "start", target_container], capture_output=True, check=True, timeout=15)
        return _wait_for_container_health(target_container, max_wait_sec=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.error(f"Failed to restart container '{target_container}': {exc}")
        return False

@with_spinner("Verifying blacklist file count and database state...")
def verify_updates(filepath: Path | str, expected_domains: tuple[str, ...], db_path: Path | str) -> bool:
    """Verifies line count matches expected domains and confirms 0 exact block entries (type 1) remain in gravity.db."""
    time.sleep(random.uniform(0.5, 1.0))
    file_path = Path(filepath).resolve()
    db_file = Path(db_path).resolve()

    try:
        with file_path.open("r", encoding="utf-8") as f:
            file_lines = sum(1 for line in f if line.strip())
    except OSError as e:
        logger.error(f"File verification failed: {e}")
        return False

    if file_lines != len(expected_domains):
        logger.error(f"Verification failed: expected {len(expected_domains)} lines, found {file_lines}.")
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
    except sqlite3.Error as e:
        logger.error(f"Database verification failed: {e}")
        return False

    if exact_match_count != 0:
        logger.error(f"Verification failed: {exact_match_count} exact deny entries (type 1) still remain in gravity.db.")
        return False

    return True

@with_spinner("Staging, committing, and pushing blacklist to GitHub...")
def push_to_github(filepath: Path | str, commit_msg: str = "Automated update of blacklist.txt") -> bool:
    """Stages blacklist.txt, commits changes if any exist, and pushes to the remote GitHub repository."""
    time.sleep(random.uniform(0.5, 1.0))
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
            logger.info("No changes detected in blacklist.txt to commit.")
            return True

        subprocess.run(["git", "add", path.name], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "push"], cwd=repo_dir, check=True, capture_output=True)

        return True
    except subprocess.CalledProcessError as exc:
        logger.error(f"Git operation failed: {exc.stderr if exc.stderr else str(exc)}")
        return False

@with_spinner("Verifying gravity database existence...")
def check_gravity_db() -> bool:
    time.sleep(random.uniform(0.8, 1.3))
    return does_file_exist(gravitydb)

@with_spinner("Verifying blacklist file existence...")
def check_blacklist_file() -> bool:
    time.sleep(random.uniform(0.8, 1.3))
    return does_file_exist(blacklist)

@with_spinner("Verifying gravity database structure...")
def check_gravity_db_integrity() -> bool:
    time.sleep(random.uniform(0.8, 1.3))
    return is_db(gravitydb)

def main():
    if not check_system_dependencies():
        sys.exit(1)

    if check_gravity_db() and check_blacklist_file() and check_gravity_db_integrity():
        
        file_entries = parse_blacklist(blacklist)
        db_entries = load_gravity_db_entries(gravitydb)
        
        # Halt securely if data retrieval fails entirely (Spinner returns False on fatal errors)
        if file_entries is False or db_entries is False:
            logger.error("Failed to parse initial datasets. Execution aborted.")
            sys.exit(1)
            
        if not db_entries:
            notify_no_new_domains()
            print_final_status()
            sys.exit(0)

        combined_domains = merge_domain_entries(file_entries, db_entries)
        
        # Validate write success
        if not update(blacklist, combined_domains):
            logger.error("Failed to write to blacklist. Execution aborted.")
            sys.exit(1)
            
        purged_count = purge_domains(combined_domains, gravitydb)
        
        # Explicit type check ensures failures aren't treated as '0 purged'
        if purged_count is False:
            logger.error("Database purge operation threw an exception. Execution aborted.")
            sys.exit(1)
            
        if purged_count == 0:
            if is_verbose:
                print("\n[!] 0 matching domains were found to purge from gravity.db. Container restart skipped. Exiting gracefully.")
            print_final_status()
            sys.exit(0)

        verification_passed = verify_updates(blacklist, combined_domains, gravitydb)
        container_restarted = restart_pihole_container(container_name)
        github_pushed = push_to_github(blacklist, f"Auto-update: synchronized {len(combined_domains)} blacklist entries")

        if is_verbose:
            print(
                f"\nPipeline execution summary:\n"
                f" - Updated blacklist.txt with {len(combined_domains)} unique, sorted entries.\n"
                f" - Purged {purged_count} matching entry/entries from gravity.db.\n"
                f" - Integrity & DB Verification: {'Passed' if verification_passed else 'Failed'}.\n"
                f" - Container Reload ({container_name}): {'Successful' if container_restarted else 'Failed'}.\n"
                f" - GitHub Push: {'Successful' if github_pushed else 'Failed'}."
            )

        print_final_status()

if __name__ == "__main__":
    main()
