import os
import re
import sqlite3
import logging
import tempfile
import subprocess
import secrets
import urllib.request
from pathlib import Path
from typing import Set, List, Final, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field

# Configure robust logging with granular formatting
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s"
)
logger = logging.getLogger("PiholeProductionManager")

@dataclass(frozen=True)
class Config:
    db_path: Path = field(default_factory=lambda: Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"))
    script_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    exclusion_urls: Final[Set[str]] = field(default_factory=lambda: {
        "https://raw.githubusercontent.com/senku-btw/blacklist/refs/heads/main/blacklists/blacklist-extra.txt",
        "https://raw.githubusercontent.com/senku-btw/blacklist/refs/heads/main/blacklists/blacklist.txt",
        "https://raw.githubusercontent.com/senku-btw/whitelist/refs/heads/main/whitelist.txt",
        "https://raw.githubusercontent.com/senku-btw/whitelist/refs/heads/main/healthcheck.txt",
    })

DOMAIN_REGEX: Final[re.Pattern] = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

class PiholeManager:
    def __init__(self, config: Config = Config()) -> None:
        self.config = config

    @contextmanager
    def _get_db_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Establish a robust, safe SQLite connection context manager with WAL mode and proper cleanup."""
        if not self.config.db_path.exists():
            raise FileNotFoundError(f"Gravity database not found at {self.config.db_path}")
        
        conn = sqlite3.connect(self.config.db_path, timeout=15.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _atomic_write(file_path: Path, lines: List[str]) -> None:
        """Write lines atomically using a temporary file to prevent file corruption during failures."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        base_name = file_path.name
        
        tf_name = None
        try:
            with tempfile.NamedTemporaryFile("w", dir=file_path.parent, prefix=f".{base_name}.", delete=False, encoding="utf-8") as tf:
                for line in lines:
                    tf.write(f"{line}\n")
                tf_name = tf.name
            
            os.replace(tf_name, file_path)
        except Exception:
            if tf_name and os.path.exists(tf_name):
                try:
                    os.unlink(tf_name)
                except OSError:
                    pass
            raise

    @staticmethod
    def sanitize_domain(domain: str) -> str:
        return domain.strip().lower()

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        if not domain or len(domain) > 253 or domain.startswith("#"):
            return False
        return bool(DOMAIN_REGEX.match(domain))

    @staticmethod
    def is_valid_regex(pattern: str) -> bool:
        if not pattern or not pattern.strip():
            return False
        try:
            re.compile(pattern.strip())
            return True
        except re.error:
            return False

    @staticmethod
    def normalize_url(url: str) -> str:
        return url.strip().rstrip("/")

    def run_step_a(self) -> None:
        """Step A: Extract exact blacklist domains from DB, sync with blacklist.txt atomically, cleanup DB."""
        logger.info("Starting Step A: Processing exact blacklist domains...")
        
        db_domains: Set[str] = set()
        try:
            with self._get_db_connection() as conn:
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
                for row in cursor.fetchall():
                    sanitized = self.sanitize_domain(row[0])
                    if self.is_valid_domain(sanitized):
                        db_domains.add(sanitized)
        except Exception as e:
            logger.error(f"Database query failed in Step A: {e}")
            return

        immutable_db_domains: frozenset = frozenset(db_domains)

        blacklists_dir = self.config.script_dir / "blacklists"
        blacklist_file_path = blacklists_dir / "blacklist.txt"

        file_domains: Set[str] = set()
        if blacklist_file_path.exists():
            try:
                with open(blacklist_file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        sanitized = self.sanitize_domain(line)
                        if self.is_valid_domain(sanitized):
                            file_domains.add(sanitized)
            except Exception as e:
                logger.error(f"Error reading {blacklist_file_path}: {e}")

        immutable_file_domains: frozenset = frozenset(file_domains)
        combined_superset: frozenset = immutable_db_domains.union(immutable_file_domains)
        sorted_domains: List[str] = sorted(list(combined_superset))

        try:
            self._atomic_write(blacklist_file_path, sorted_domains)
            logger.info(f"Successfully updated {blacklist_file_path} with {len(sorted_domains)} unique domains.")
        except Exception as e:
            logger.error(f"Atomic write failed for {blacklist_file_path}: {e}")
            return

        try:
            with self._get_db_connection() as conn:
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
            logger.error(f"Database deletion failed in Step A: {e}")

    def run_step_b(self) -> None:
        """Step B: Fetch, validate, alphabetise regex rules and export atomically to regex_deny.txt."""
        logger.info("Starting Step B: Processing regex deny rules...")
        
        regex_rules: Set[str] = set()
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT domain FROM domainlist WHERE type = 3")
                for row in cursor.fetchall():
                    pattern = row[0].strip()
                    if self.is_valid_regex(pattern):
                        regex_rules.add(pattern)
                    else:
                        logger.warning(f"Invalid or incompatible Pi-hole regex encountered in DB and skipped: {pattern}")
        except Exception as e:
            logger.error(f"Database query failed in Step B: {e}")
            return

        immutable_regex: frozenset = frozenset(regex_rules)
        sorted_regex: List[str] = sorted(list(immutable_regex))

        regex_dir = self.config.script_dir / "regex"
        regex_file_path = regex_dir / "regex_deny.txt"

        try:
            self._atomic_write(regex_file_path, sorted_regex)
            logger.info(f"Successfully exported {len(sorted_regex)} valid regex rules to {regex_file_path}.")
        except Exception as e:
            logger.error(f"Atomic write failed for {regex_file_path}: {e}")

    def run_step_c(self) -> None:
        """Step C: Identify empty/inaccessible adlists (excluding status 3), update empty-lists.txt, and delete from DB."""
        logger.info("Starting Step C: Processing empty or inaccessible adlists...")
        
        normalized_exclusions = {self.normalize_url(url) for url in self.config.exclusion_urls}
        lists_to_remove: List[str] = []

        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT address, number, status FROM adlist")
                for address, number, status in cursor.fetchall():
                    norm_addr = self.normalize_url(address)
                    if norm_addr in normalized_exclusions:
                        continue
                    if status == 3:
                        continue
                    if number == 0 or status == 4:
                        lists_to_remove.append(address)
        except Exception as e:
            logger.error(f"Database query failed in Step C: {e}")
            return

        empty_lists_file_path = self.config.script_dir / "empty-lists.txt"
        file_urls: Set[str] = set()
        if empty_lists_file_path.exists():
            try:
                with open(empty_lists_file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith("#"):
                            norm_url = self.normalize_url(url)
                            if norm_url not in normalized_exclusions:
                                file_urls.add(url)
            except Exception as e:
                logger.error(f"Error reading {empty_lists_file_path}: {e}")

        combined_empty_superset: Set[str] = file_urls.union(set(lists_to_remove))
        sorted_empty_urls: List[str] = sorted(list(combined_empty_superset))

        try:
            self._atomic_write(empty_lists_file_path, sorted_empty_urls)
            logger.info(f"Successfully updated {empty_lists_file_path} with {len(sorted_empty_urls)} entries.")
        except Exception as e:
            logger.error(f"Atomic write failed for {empty_lists_file_path}: {e}")
            return

        if lists_to_remove:
            try:
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    for url in lists_to_remove:
                        cursor.execute("DELETE FROM adlist WHERE address = ?", (url,))
                        logger.info(f"Confirmed deletion of empty/inaccessible adlist from database: {url}")
                    conn.commit()
            except Exception as e:
                logger.error(f"Database deletion failed in Step C: {e}")
        else:
            logger.info("No empty or inaccessible adlists met the criteria for database removal.")

    def run_step_d(self) -> None:
        """Step D: Extract adlists with empty comments, sync atomically with minor-lists.txt, and delete from DB."""
        logger.info("Starting Step D: Processing adlists with empty comments...")
        
        normalized_exclusions = {self.normalize_url(url) for url in self.config.exclusion_urls}
        minor_urls: Set[str] = set()

        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT DISTINCT address FROM adlist
                    WHERE comment IS NULL OR comment = ''
                """
                cursor.execute(query)
                for row in cursor.fetchall():
                    url = row[0].strip()
                    norm_url = self.normalize_url(url)
                    if url and norm_url not in normalized_exclusions:
                        minor_urls.add(url)
        except Exception as e:
            logger.error(f"Database query failed in Step D: {e}")
            return

        immutable_minor_urls: frozenset = frozenset(minor_urls)
        minor_lists_file_path = self.config.script_dir / "minor-lists.txt"

        existing_minor_file_urls: List[str] = []
        if minor_lists_file_path.exists():
            try:
                with open(minor_lists_file_path, "r", encoding="utf-8") as f:
                    existing_minor_file_urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Error reading {minor_lists_file_path}: {e}")

        updated_minor_file_urls: List[str] = []
        for url in existing_minor_file_urls:
            if self.normalize_url(url) not in normalized_exclusions:
                updated_minor_file_urls.append(url)

        newly_added = 0
        for url in sorted(list(immutable_minor_urls)):
            if url not in updated_minor_file_urls:
                updated_minor_file_urls.append(url)
                newly_added += 1

        try:
            self._atomic_write(minor_lists_file_path, sorted(updated_minor_file_urls))
            logger.info(f"Appended {newly_added} new entries to {minor_lists_file_path}.")
        except Exception as e:
            logger.error(f"Atomic write failed for {minor_lists_file_path}: {e}")
            return

        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                deleted_count = 0
                for url in immutable_minor_urls:
                    cursor.execute("DELETE FROM adlist WHERE address = ?", (url,))
                    deleted_count += cursor.rowcount
                conn.commit()
                logger.info(f"Successfully deleted {deleted_count} empty-comment lists from gravity.db.")
        except Exception as e:
            logger.error(f"Database deletion failed in Step D: {e}")

    def run_step_e(self) -> None:
        """Step E: Fetch links from minor-lists.txt (strictly enforcing exclusions) and remove matching adlists from the database."""
        logger.info("Starting Step E: Processing minor-lists.txt database cleanup...")
        
        normalized_exclusions = {self.normalize_url(url) for url in self.config.exclusion_urls}
        minor_lists_file_path = self.config.script_dir / "minor-lists.txt"
        if not minor_lists_file_path.exists():
            logger.info(f"{minor_lists_file_path} does not exist. Skipping cleanup.")
            return

        file_urls: Set[str] = set()
        try:
            with open(minor_lists_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#"):
                        file_urls.add(url)
        except Exception as e:
            logger.error(f"Error reading {minor_lists_file_path}: {e}")
            return

        if not file_urls:
            logger.info("No URLs found in minor-lists.txt.")
            return

        cleaned_file_urls = [url for url in sorted(file_urls) if self.normalize_url(url) not in normalized_exclusions]
        if len(cleaned_file_urls) != len(file_urls):
            try:
                self._atomic_write(minor_lists_file_path, cleaned_file_urls)
                logger.info("Purged exclusion URLs from minor-lists.txt.")
            except Exception as e:
                logger.error(f"Failed to update minor-lists.txt during exclusion cleanup: {e}")

        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                deleted_count = 0
                for url in cleaned_file_urls:
                    norm_url = self.normalize_url(url)
                    if norm_url in normalized_exclusions:
                        logger.warning(f"Skipping exclusion URL in Step E cleanup: {url}")
                        continue
                    cursor.execute("DELETE FROM adlist WHERE address = ?", (url,))
                    if cursor.rowcount > 0:
                        logger.info(f"Removed adlist matching minor-lists.txt from database: {url}")
                        deleted_count += cursor.rowcount
                conn.commit()
                logger.info(f"Successfully deleted {deleted_count} matching adlists from gravity.db based on minor-lists.txt.")
        except Exception as e:
            logger.error(f"Database deletion failed in Step E: {e}")

    def run_step_f(self) -> None:
        """Step F: Stage changes, commit with a randomized hexadecimal message, and push to remote repository."""
        logger.info("Starting Step F: Committing and pushing changes to GitHub...")
        
        git_dir = self.config.script_dir
        if not (git_dir / ".git").is_dir():
            logger.error(f"Not a valid git repository: {git_dir}")
            return

        def run_git_cmd(args: List[str]) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["git"] + args,
                cwd=git_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )

        res_add = run_git_cmd(["add", "."])
        if res_add.returncode != 0:
            logger.error(f"Failed to stage git changes: {res_add.stderr.strip()}")
            return

        res_status = run_git_cmd(["status", "--porcelain"])
        if res_status.returncode != 0:
            logger.error(f"Failed to check git status: {res_status.stderr.strip()}")
            return

        if not res_status.stdout.strip():
            logger.info("No changes detected to commit. Skipping git commit and push.")
            return

        commit_message = secrets.token_hex(8)

        res_commit = run_git_cmd(["commit", "-m", commit_message])
        if res_commit.returncode != 0:
            logger.error(f"Failed to commit git changes: {res_commit.stderr.strip()}")
            return
        logger.info(f"Successfully committed changes with message: {commit_message}")

        res_push = run_git_cmd(["push"])
        if res_push.returncode != 0:
            logger.error(f"Failed to push changes to remote: {res_push.stderr.strip()}")
            return
        
        logger.info("Successfully pushed changes to GitHub remote repository.")

    def run_step_g(self) -> None:
        """Step G: Fetch remote blocklists and remove any matching entries from minor-lists.txt."""
        logger.info("Starting Step G: Processing remote blocklists against minor-lists.txt...")
        
        remote_url = "https://raw.githubusercontent.com/senku-btw/blocklists/refs/heads/main/blocklists.txt"
        remote_urls: Set[str] = set()
        
        try:
            req = urllib.request.Request(
                remote_url,
                headers={"User-Agent": "PiholeProductionManager"}
            )
            with urllib.request.urlopen(req, timeout=15) as response:
                for line in response:
                    decoded = line.decode("utf-8").strip()
                    if decoded and not decoded.startswith("#"):
                        remote_urls.add(decoded)
        except Exception as e:
            logger.error(f"Failed to fetch remote blocklists from {remote_url}: {e}")
            return

        minor_lists_file_path = self.config.script_dir / "minor-lists.txt"
        if not minor_lists_file_path.exists():
            logger.info(f"{minor_lists_file_path} does not exist. Skipping Step G cleanup.")
            return

        existing_minor_urls: List[str] = []
        try:
            with open(minor_lists_file_path, "r", encoding="utf-8") as f:
                existing_minor_urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading {minor_lists_file_path}: {e}")
            return

        normalized_remote_urls = {self.normalize_url(u) for u in remote_urls}
        
        filtered_minor_urls: List[str] = []
        removed_count = 0
        for url in existing_minor_urls:
            if self.normalize_url(url) in normalized_remote_urls:
                removed_count += 1
                logger.info(f"Removing URL present in remote blocklists from minor-lists.txt: {url}")
            else:
                filtered_minor_urls.append(url)

        if removed_count > 0:
            try:
                self._atomic_write(minor_lists_file_path, filtered_minor_urls)
                logger.info(f"Successfully removed {removed_count} matching entries from {minor_lists_file_path}.")
            except Exception as e:
                logger.error(f"Atomic write failed for {minor_lists_file_path} in Step G: {e}")
        else:
            logger.info("No matching entries found between remote blocklists and minor-lists.txt.")

    def execute(self) -> None:
        logger.info("Starting Pi-hole production maintenance and synchronization sequence.")
        try:
            self.run_step_a()
            self.run_step_b()
            self.run_step_c()
            self.run_step_d()
            self.run_step_e()
            self.run_step_g()
            self.run_step_f()
            logger.info("All maintenance sequences completed successfully.")
        except Exception as e:
            logger.critical(f"Critical unhandled exception during execution sequence: {e}", exc_info=True)
            raise

if __name__ == "__main__":
    manager = PiholeManager()
    manager.execute()
