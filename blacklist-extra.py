import os
import re
import sys
import time
import logging
import urllib.request
from urllib.error import URLError, HTTPError
from pathlib import Path
import tempfile
import subprocess
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
INPUT_FILE = "minor-lists.txt"
OUTPUT_DIR = Path("blacklists")
OUTPUT_FILE = OUTPUT_DIR / "blacklist-extra.txt"
TIMEOUT = 20
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds
USER_AGENT = "Mozilla/5.0 (Compatible; PiholeResilientAggregator/3.0)"
MAX_CONTENT_SIZE = 50 * 1024 * 1024  # 50MB safety cap per list
MAX_WORKERS = 8  # Concurrent threads for fetching lists

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

EXCLUDED_DOMAINS = {
    "localhost", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
    "example.com", "example.org", "example.net", "test", "invalid"
}

def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    domain_lower = domain.lower()
    if domain_lower in EXCLUDED_DOMAINS:
        return False
    return bool(DOMAIN_REGEX.match(domain_lower))

def parse_line_to_domain(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None

    # Handle commented-out hosts entries (e.g., #0.0.0.0 domain or # 127.0.0.1 domain)
    if line.startswith("#"):
        potential_hosts_line = line.lstrip("#").strip()
        if potential_hosts_line.startswith(("0.0.0.0", "127.0.0.1", "::1", "localhost", "127.0.0.2", "0.0.0.1")):
            line = potential_hosts_line
        else:
            return None
    elif line.startswith(("!", "[", "//", "@")):
        return None

    # Remove inline comments safely
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if "!" in line:
        line = line.split("!", 1)[0].strip()

    # Handle Adblock format (e.g., ||example.com^...)
    if line.startswith("||"):
        line = line[2:]
    line = line.split("^")[0].split("$")[0].strip()

    # Handle hosts file format or plain domain lists separated by whitespace/tabs
    parts = line.split()
    if len(parts) >= 2:
        for part in parts[1:]:
            if is_valid_domain(part):
                return part.lower()
    elif len(parts) == 1:
        candidate = parts[0]
        if is_valid_domain(candidate):
            return candidate.lower()

    return None

def fetch_and_parse_url(url: str) -> tuple[str, set[str], int]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain, */*"}
    )
    
    response = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = urllib.request.urlopen(req, timeout=TIMEOUT)
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
                # Fallback decoding strategy for mixed-encoding blocklists
                try:
                    line = line_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    line = line_bytes.decode("latin-1", errors="ignore")

                domain = parse_line_to_domain(line)
                if domain:
                    domains.add(domain)
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

    # Concurrent multithreaded execution for peak performance and resilience
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls}
        
        completed_count = 0
        for future in as_completed(future_to_url):
            completed_count += 1
            url, domains, count = future.result()
            unique_domains.update(domains)
            logging.info(f"Processing [{completed_count}/{total_urls}]: {url} | {count}")

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

    git_commit_and_push()

if __name__ == "__main__":
    main()
