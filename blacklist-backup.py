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
from pathlib import Path
from functools import wraps
from typing import Callable, Any, TypeVar, Union, cast

# Paths
gravitydb = Path("/root/pihole/etc-pihole/gravity.db")
cdf = Path(__file__).resolve().parent
blacklist = (Path(__file__).parent / "blacklist.txt").resolve()
CONTAINER_NAME = os.getenv("PIHOLE_CONTAINER_NAME", "pihole")

# Verbose mode detection
IS_VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv

logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])

def print_final_status() -> None:
    """Prints the execution status message, including a blank line only in verbose mode."""
    if IS_VERBOSE:
        print()
    print("Successfully executed.")

class TerminalSpinner:
    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.delay = 0.1
        self._running = False
        self._spinner_thread: threading.Thread | None = None
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
            except Exception:
                spinner.stop(success=False)
                return False
        return cast(F, wrapper)
    return decorator

def does_file_exist(filepath: Union[str, os.PathLike]) -> bool:
    """Verifies that a filepath is valid, exists, and points strictly to a regular file."""
    if not isinstance(filepath, (str, os.PathLike)) or not str(filepath).strip():
        return False

    try:
        path = Path(filepath)
        return path.is_file()
    except (TypeError, ValueError, OSError):
        return False

def is_valid_sqlite_db(filepath: Union[str, os.PathLike], deep_check: bool = False) -> bool:
    """Evaluates if a filepath points to a valid SQLite 3 database."""
    try:
        if not isinstance(filepath, (str, os.PathLike)):
            return False

        path = Path(filepath).resolve()

        if not path.is_file() or path.stat().st_size < 100:
            return False

        with open(path, "rb") as f:
            if f.read(16) != b"SQLite format 3\x00":
                return False

        if deep_check:
            uri = f"file:{path.as_posix()}?mode=ro"
            with sqlite3.connect(uri, uri=True, check_same_thread=False) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA quick_check;")
                result = cursor.fetchone()
                if not result or result[0] != "ok":
                    return False

        return True
    except Exception:
        return False

@with_spinner("Reading and sanitizing blacklist file entries...")
def load_blacklist_file(filepath: Union[str, os.PathLike]) -> frozenset[str]:
    """Reads a blacklist text file, strips comments, unicode spaces, and BOM markers."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(filepath).resolve()
    cleaned_entries: set[str] = set()

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line_content = line.split("#", 1)[0]
            cleaned_line = re.sub(r"[\s\u200b\ufeff\u200e\u200f]+", "", line_content).strip().lower()
            if cleaned_line:
                cleaned_entries.add(cleaned_line)

    return frozenset(cleaned_entries)

@with_spinner("Fetching existing blacklist entries from Pi-hole database...")
def load_gravity_db_entries(db_path: Union[str, os.PathLike]) -> frozenset[str]:
    """Retrieves unique, sanitized blacklisted domains from Pi-hole gravity.db."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(db_path).resolve()
    uri = f"file:{path.as_posix()}?mode=ro"
    db_domains: set[str] = set()

    with sqlite3.connect(uri, uri=True, check_same_thread=False) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM domainlist WHERE type IN (1, 3);")
        rows = cursor.fetchall()
        for row in rows:
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
def combine_domain_entries(set_a: frozenset[str], set_b: frozenset[str]) -> tuple[str, ...]:
    """Merges two domain sets, eliminates all duplicates, and returns an alphabetically sorted tuple."""
    time.sleep(random.uniform(0.8, 1.3))
    return tuple(sorted(set_a.union(set_b)))

@with_spinner("Writing clean, unique, sorted entries to blacklist file...")
def update_blacklist(filepath: Union[str, os.PathLike], domains: tuple[str, ...]) -> bool:
    """Overwrites blacklist.txt permanently with clean, unique, alphabetically sorted entries."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(filepath).resolve()

    with path.open("w", encoding="utf-8") as file:
        for domain in domains:
            file.write(f"{domain}\n")

    return True

@with_spinner("Purging matching domains from gravity database and updating counters...")
def purge_matching_domains(domains: tuple[str, ...], db_path: Union[str, os.PathLike], container_name: str = CONTAINER_NAME) -> int:
    """Purges matching domains from gravity.db and flushes FTL shared memory counters."""
    time.sleep(random.uniform(0.8, 1.3))
    path = Path(db_path).resolve()

    if not path.is_file() or not domains:
        return 0

    deleted_count = 0

    with sqlite3.connect(path) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id, domain FROM domainlist WHERE type IN (1, 3);")
        rows = cursor.fetchall()
        
        target_ids = []
        target_domains = []
        domain_set = set(domains)

        for domain_id, domain_name in rows:
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
            delete_query = f"DELETE FROM domainlist WHERE type IN (1, 3) AND LOWER(domain) IN ({placeholders});"
            cursor.execute(delete_query, batch)
            deleted_count += cursor.rowcount

        conn.commit()

    # Force FTL to flush name cache and reset dashboard metrics
    try:
        subprocess.run(
            ["docker", "exec", container_name, "pihole", "restartdns", "reload"],
            capture_output=True,
            text=True,
            timeout=15
        )
        subprocess.run(
            ["docker", "exec", container_name, "pihole-FTL", "cc", "flush-name-cache"],
            capture_output=True,
            text=True,
            timeout=15
        )
    except Exception as exc:
        logger.warning(f"Failed to reset FTL dashboard cache: {exc}")

    return deleted_count

def _check_dns_socket(host: str = "127.0.0.1", port: int = 53, timeout: float = 1.0) -> bool:
    """Verifies that the DNS port is responding to TCP sockets."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def _wait_for_container_health(container_name: str, max_wait_sec: int = 30) -> bool:
    """Polls container state until status is running and healthcheck (if configured) is healthy."""
    start_time = time.time()
    while time.time() - start_time < max_wait_sec:
        try:
            inspect_cmd = ["docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container_name]
            res = subprocess.run(inspect_cmd, capture_output=True, text=True, check=True)
            status, health = res.stdout.strip().split("|")
            
            if status == "running" and health in ("healthy", "none"):
                if _check_dns_socket():
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False

@with_spinner("Reloading Pi-hole DNS engine & verifying service health...")
def restart_pihole_container(container_name: str = CONTAINER_NAME, timeout: int = 30) -> bool:
    """Forces FTL to flush shared memory, restarts web server daemons, and verifies health."""
    time.sleep(random.uniform(0.5, 1.0))
    
    # Strategy 1: Signal FTL, flush cache, and restart web services inside container
    try:
        flush_cmd = ["docker", "exec", container_name, "killall", "-HUP", "pihole-FTL"]
        res = subprocess.run(flush_cmd, capture_output=True, text=True, timeout=10)
        
        # Restart internal web server/PHP services to clear dashboard session cache
        subprocess.run(["docker", "exec", container_name, "pihole", "restartdns", "reload"], capture_output=True, text=True, timeout=10)
        subprocess.run(["docker", "exec", container_name, "service", "lighttpd", "reload"], capture_output=True, text=True, timeout=10)

        if res.returncode == 0 and _check_dns_socket():
            return True
    except Exception as exc:
        logger.warning(f"SIGHUP cache flush failed ({exc}). Trying container restart fallback.")

    # Strategy 2: Complete container restart with graceful stop/start sequence
    try:
        subprocess.run(["docker", "stop", "-t", str(timeout), container_name], capture_output=True, check=True, timeout=timeout + 5)
        subprocess.run(["docker", "start", container_name], capture_output=True, check=True, timeout=15)
        return _wait_for_container_health(container_name, max_wait_sec=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error(f"Failed to restart container '{container_name}': {exc}")
        return False

@with_spinner("Verifying blacklist file count and database state...")
def verify_updates(filepath: Union[str, os.PathLike], expected_domains: tuple[str, ...], db_path: Union[str, os.PathLike]) -> bool:
    """Verifies line count matches expected domains and confirms 0 exact block entries (type 1) remain in gravity.db."""
    time.sleep(random.uniform(0.5, 1.0))
    file_path = Path(filepath).resolve()
    db_file = Path(db_path).resolve()

    with file_path.open("r", encoding="utf-8") as f:
        file_lines = sum(1 for line in f if line.strip())

    if file_lines != len(expected_domains):
        logger.error(f"Verification failed: expected {len(expected_domains)} lines, found {file_lines}.")
        return False

    batch_size = 900
    exact_match_count = 0

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        for i in range(0, len(expected_domains), batch_size):
            batch = expected_domains[i : i + batch_size]
            placeholders = ",".join("?" for _ in batch)
            query = f"SELECT COUNT(*) FROM domainlist WHERE type = 1 AND LOWER(domain) IN ({placeholders});"
            cursor.execute(query, batch)
            exact_match_count += cursor.fetchone()[0]

    if exact_match_count != 0:
        logger.error(f"Verification failed: {exact_match_count} exact deny entries (type 1) still remain in gravity.db.")
        return False

    return True

@with_spinner("Staging, committing, and pushing blacklist to GitHub...")
def push_to_github(filepath: Union[str, os.PathLike], commit_msg: str = "Automated update of blacklist.txt") -> bool:
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
        logger.error(f"Git operation failed: {exc.stderr if exc.stderr else exc}")
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
    return is_valid_sqlite_db(gravitydb, deep_check=False)

if __name__ == "__main__":
    if check_gravity_db() and check_blacklist_file() and check_gravity_db_integrity():
        file_entries = load_blacklist_file(blacklist)
        db_entries = load_gravity_db_entries(gravitydb)
        
        if not db_entries:
            notify_no_new_domains()
            print_final_status()
            sys.exit(0)

        combined_domains = combine_domain_entries(file_entries, db_entries)
        update_blacklist(blacklist, combined_domains)
        purged_count = purge_matching_domains(combined_domains, gravitydb)
        
        if purged_count == 0:
            if IS_VERBOSE:
                print("\n[!] 0 matching domains were found to purge from gravity.db. Container restart skipped. Exiting gracefully.")
            print_final_status()
            sys.exit(0)

        verification_passed = verify_updates(blacklist, combined_domains, gravitydb)
        container_restarted = restart_pihole_container(CONTAINER_NAME)
        github_pushed = push_to_github(blacklist, f"Auto-update: synchronized {len(combined_domains)} blacklist entries")

        if IS_VERBOSE:
            print(
                f"\nPipeline execution summary:\n"
                f" - Updated blacklist.txt with {len(combined_domains)} unique, sorted entries.\n"
                f" - Purged {purged_count} matching entry/entries from gravity.db.\n"
                f" - Integrity & DB Verification: {'Passed' if verification_passed else 'Failed'}.\n"
                f" - Container Reload ({CONTAINER_NAME}): {'Successful' if container_restarted else 'Failed'}.\n"
                f" - GitHub Push: {'Successful' if github_pushed else 'Failed'}."
            )

        print_final_status()
