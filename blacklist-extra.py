import os
import re
import sys
import time
import logging
import urllib.request
import argparse
from urllib.error import URLError, HTTPError
from pathlib import Path
import tempfile
import subprocess
import random
import string
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
INPUT_FILE = "minor-lists.txt"
MAJOR_INPUT_FILE = "major-lists.txt"
OUTPUT_DIR = Path("blacklists")
OUTPUT_FILE = OUTPUT_DIR / "blacklist-extra.txt"
TIMEOUT = 25
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds
USER_AGENT = "Mozilla/5.0 (Compatible; PiholeResilientAggregator/4.0)"
MAX_CONTENT_SIZE = 50 * 1024 * 1024  # 50MB safety cap per list
MAX_WORKERS = 3  # Reduced concurrent threads to prevent OOM kills
DOMAIN_THRESHOLD = 99000  # Threshold to move a list to major-lists.txt

# URLs explicitly excluded from any operation or inclusion
EXCLUSION_URLS = {
    "https://raw.githubusercontent.com/senku-btw/blacklist/refs/heads/main/blacklists/blacklist-extra.txt",
    "https://raw.githubusercontent.com/senku-btw/blacklist/refs/heads/main/blacklists/blacklist.txt",
    "https://raw.githubusercontent.com/senku-btw/whitelist/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/senku-btw/whitelist/refs/heads/main/healthcheck.txt",
}

# Setup robust logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# RFC-compliant domain validation regex
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Broad fallback domain extractor for messy or unstructured lists
FALLBACK_DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

EXCLUDED_DOMAINS = {
    "localhost", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
    "example.com", "example.org", "example.net", "test", "invalid", "localhost.localdomain"
}

def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    domain_lower = domain.lower()
    if domain_lower in EXCLUDED_DOMAINS:
        return False
    return bool(DOMAIN_REGEX.match(domain_lower))

def parse_line_strategic(line: str) -> set[str]:
    found_domains = set()
    line = line.strip()
    if not line:
        return found_domains

    if line.startswith("#"):
        uncommented = line.lstrip("#").strip()
        if uncommented.startswith(("0.0.0.0", "127.0.0.1", "::1", "localhost", "127.0.0.2", "0.0.0.1", "255.255.255.255")):
            line = uncommented
        else:
            return found_domains
    elif line.startswith(("!", "[", "//", "@", ":", ";")):
        return found_domains

    for char in ("#", "!", "//"):
        if char in line:
            line = line.split(char, 1)[0].strip()

    if line.startswith("||"):
        line = line[2:]
    elif line.startswith("|"):
        line = line[1:]
    
    line = line.split("^")[0].split("$")[0].strip()

    if "://" in line:
        line = line.split("://", 1)[1]
    line = line.split("/")[0].split(":")[0].strip()

    parts = line.split()
    if len(parts) >= 2:
        for part in parts[1:]:
            cleaned_part = part.strip(".,;:*")
            if is_valid_domain(cleaned_part):
                found_domains.add(cleaned_part.lower())
    elif len(parts) == 1:
        candidate = parts[0].strip(".,;:*")
        if is_valid_domain(candidate):
            found_domains.add(candidate.lower())

    if not found_domains and len(line) > 4:
        for match in FALLBACK_DOMAIN_REGEX.findall(line):
            if is_valid_domain(match):
                found_domains.add(match.lower())

    return found_domains

def fetch_and_parse_url(url: str) -> tuple[str, set[str], int]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain, application/text, */*"}
    )
    
    response = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = urllib.request.urlopen(req, timeout=TIMEOUT)
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" in content_type:
                logging.warning(f"Skipping {url}: Received HTML content instead of plain text blocklist.")
                response.close()
                return url, set(), 0

            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_CONTENT_SIZE:
                logging.warning(f"Skipping {url}: Payload exceeds safety limit ({content_length} bytes)")
                response.close()
                return url, set(), 0
            break
        except (URLError, HTTPError, TimeoutError, Exception) as e:
            logging.warning(f"Attempt {attempt}/{MAX_RETRIES} failed for {url}: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)
            else:
                logging.error(f"Failed to fetch {url} after {MAX_RETRIES} attempts.")
                return url, set(), 0

    if not response:
        return url, set(), 0

    domains = set()
    try:
        for line_bytes in response:
            try:
                try:
                    line = line_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    line = line_bytes.decode("latin-1", errors="ignore")

                extracted = parse_line_strategic(line)
                if extracted:
                    domains.update(extracted)
            except Exception:
                continue
    except Exception as e:
        logging.error(f"Error streaming response from {url}: {e}")
    finally:
        try:
            response.close()
        except Exception:
            pass

    return url, domains, len(domains)

def generate_random_commit_msg(length=8) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))

def git_commit_and_push():
    try:
        if not Path(".git").exists():
            logging.warning("Not a git repository. Skipping git commit and push.")
            return

        subprocess.run(["git", "config", "local.user.name", "Pihole Aggregator Bot"], capture_output=True, text=True)
        subprocess.run(["git", "config", "local.user.email", "aggregator@bot.local"], capture_output=True, text=True)
        subprocess.run(["git", "add", str(OUTPUT_FILE)], check=True, capture_output=True, text=True)

        status_res = subprocess.run(["git", "status", "--porcelain"], check=True, capture_output=True, text=True)
        if not status_res.stdout.strip():
            logging.info("No changes detected in git status. Skipping commit and push.")
            return

        commit_msg = generate_random_commit_msg(8)
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
        logging.info(f"Committed changes with message: {commit_msg}")

        push_success = False
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                push_res = subprocess.run(["git", "push"], capture_output=True, text=True)
                if push_res.returncode == 0:
                    push_success = True
                    break
                
                if "fetch first" in push_res.stderr or "rejected" in push_res.stderr or "diverged" in push_res.stderr:
                    logging.warning("Remote repository has diverged. Attempting git pull --rebase...")
                    subprocess.run(["git", "pull", "--rebase", "--autostash"], check=True, capture_output=True, text=True)
                else:
                    logging.warning(f"Push attempt {attempt} failed: {push_res.stderr.strip()}")

                time.sleep(RETRY_BACKOFF * attempt)
            except subprocess.CalledProcessError as e:
                logging.warning(f"Git push retry {attempt} encountered an error: {e.stderr.strip() if e.stderr else str(e)}")
                time.sleep(RETRY_BACKOFF * attempt)

        if push_success:
            logging.info("Successfully pushed changes to GitHub.")
        else:
            logging.error("All git push attempts failed. Local commit created successfully.")

    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else str(e)
        logging.error(f"Git operation failed: {error_output}")
    except Exception as e:
        logging.error(f"Unexpected error during git automation: {e}")

def main():
    parser = argparse.ArgumentParser(description="Pihole Blacklist Aggregator")
    parser.add_argument("--dry-run", action="store_true", help="Only count entries and migrate heavy lists without generating final outputs or git actions.")
    args = parser.parse_args()
    dry_run = args.dry_run

    if dry_run:
        logging.info("=== DRY RUN MODE ENABLED ===")

    input_path = Path(INPUT_FILE)
    if not input_path.exists():
        logging.error(f"Input file '{INPUT_FILE}' not found.")
        sys.exit(1)

    try:
        urls = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            if cleaned in EXCLUSION_URLS:
                logging.info(f"Skipping excluded URL found in {INPUT_FILE}: {cleaned}")
                continue
            urls.append(cleaned)
    except Exception as e:
        logging.error(f"Failed to read input file: {e}")
        sys.exit(1)

    total_urls = len(urls)
    logging.info(f"Loaded {total_urls} target URLs from {INPUT_FILE}")

    unique_domains = set()
    urls_to_migrate = []

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls}
            
            completed_count = 0
            try:
                for future in as_completed(future_to_url):
                    completed_count += 1
                    url, domains, count = future.result()
                    
                    if not dry_run:
                        unique_domains.update(domains)

                    logging.info(f"Processing [{completed_count}/{total_urls}]: {url} | {count}")

                    if count > DOMAIN_THRESHOLD:
                        logging.info(f"List exceeded threshold ({count} > {DOMAIN_THRESHOLD}). Marking for migration to {MAJOR_INPUT_FILE}.")
                        urls_to_migrate.append(url)
                    
                    if completed_count % 20 == 0:
                        gc.collect()
            except KeyboardInterrupt:
                logging.warning("\nKeyboard interrupt received during processing. Shutting down worker threads...")
                executor.shutdown(wait=False, cancel_futures=True)
                raise
    except KeyboardInterrupt:
        logging.error("Operation cancelled by user.")
        sys.exit(130)

    # Migrate heavy lists between minor-lists.txt and major-lists.txt
    if urls_to_migrate:
        try:
            current_minor_lines = input_path.read_text(encoding="utf-8").splitlines()
            new_minor_lines = [line for line in current_minor_lines if line.strip() not in urls_to_migrate]
            input_path.write_text("\n".join(new_minor_lines) + "\n", encoding="utf-8")
            logging.info(f"Removed {len(urls_to_migrate)} heavy lists from {INPUT_FILE}.")

            major_path = Path(MAJOR_INPUT_FILE)
            existing_major = set()
            if major_path.exists():
                existing_major = {line.strip() for line in major_path.read_text(encoding="utf-8").splitlines() if line.strip()}
            
            added_to_major = 0
            with open(major_path, "a", encoding="utf-8") as f_major:
                for u in urls_to_migrate:
                    if u not in existing_major:
                        f_major.write(u + "\n")
                        added_to_major += 1
            logging.info(f"Appended {added_to_major} unique lists to {MAJOR_INPUT_FILE}.")
        except Exception as e:
            logging.error(f"Failed to migrate heavy lists to {MAJOR_INPUT_FILE}: {e}")

    if dry_run:
        logging.info("Dry run complete. Skipping final output generation and git actions.")
        return

    if not unique_domains:
        logging.error("No valid domains collected. Aborting to protect existing blocklist integrity.")
        sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=OUTPUT_DIR, delete=False, encoding="utf-8") as tmp:
            temp_file_path = Path(tmp.name)
            sorted_domains = sorted(unique_domains)
            for domain in sorted_domains:
                tmp.write(domain + "\n")
        
        temp_file_path.replace(OUTPUT_FILE)
        logging.info(f"Successfully updated '{OUTPUT_FILE}' with {len(sorted_domains)} unique domains.")
    except Exception as e:
        logging.error(f"Failed to write output atomically: {e}")
        if temp_file_path and temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except Exception:
                pass
        sys.exit(1)

    try:
        git_commit_and_push()
    except KeyboardInterrupt:
        logging.error("Git operation cancelled by user.")
        sys.exit(130)

if __name__ == "__main__":
    main()
