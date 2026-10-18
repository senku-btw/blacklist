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

# Configuration
INPUT_FILE = "minor-lists.txt"
OUTPUT_DIR = Path("blacklists")
OUTPUT_FILE = OUTPUT_DIR / "blacklist-extra.txt"
TIMEOUT = 15
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds
USER_AGENT = "Mozilla/5.0 (Compatible; PiholeResilientAggregator/2.2)"
MAX_CONTENT_SIZE = 50 * 1024 * 1024  # 50MB safety cap per list

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
        if potential_hosts_line.startswith(("0.0.0.0", "127.0.0.1", "::1", "localhost", "127.0.0.2")):
            line = potential_hosts_line
        else:
            return None
    elif line.startswith(("!", "[", "//")):
        return None

    # Remove inline comments
    line = line.split("#")[0].split("!")[0].strip()

    # Handle Adblock format (e.g., ||example.com^...)
    if line.startswith("||"):
        line = line[2:]
    line = line.split("^")[0].split("$")[0].strip()

    # Handle hosts file format or plain domain lists
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

def fetch_url_stream(url: str):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT}
    )
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = urllib.request.urlopen(req, timeout=TIMEOUT)
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_CONTENT_SIZE:
                logging.warning(f"Skipping {url}: Payload exceeds safety limit ({content_length} bytes)")
                response.close()
                return None
            return response
        except (URLError, HTTPError, TimeoutError, Exception) as e:
            logging.warning(f"Attempt {attempt}/{MAX_RETRIES} failed for {url}: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)
            else:
                logging.error(f"Failed to fetch {url} after {MAX_RETRIES} attempts. Skipping.")
                return None
    return None

def generate_random_commit_msg(length=8) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))

def git_commit_and_push():
    try:
        if not Path(".git").exists():
            logging.warning("Not a git repository. Skipping git commit and push.")
            return

        # Ensure local git identity is configured to prevent commit rejections on fresh environments
        subprocess.run(["git", "config", "local.user.name", "Pihole Aggregator Bot"], capture_output=True, text=True)
        subprocess.run(["git", "config", "local.user.email", "aggregator@bot.local"], capture_output=True, text=True)

        # Stage the generated blacklist file
        subprocess.run(["git", "add", str(OUTPUT_FILE)], check=True, capture_output=True, text=True)

        # Check if there are actual changes to commit
        status_res = subprocess.run(["git", "status", "--porcelain"], check=True, capture_output=True, text=True)
        if not status_res.stdout.strip():
            logging.info("No changes detected in git status. Skipping commit and push.")
            return

        # Generate random alphanumeric commit message
        commit_msg = generate_random_commit_msg(8)

        # Commit changes
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True, text=True)
        logging.info(f"Committed changes with message: {commit_msg}")

        # Resilient push logic with automatic rebase/pull handling and retry attempts
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
            logging.error("All git push attempts failed. Local commit was created successfully, but remote push could not be completed.")

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

    logging.info(f"Loaded {len(urls)} target URLs from {INPUT_FILE}")

    unique_domains = set()

    for i, url in enumerate(urls, 1):
        response = fetch_url_stream(url)
        if not response:
            logging.info(f"Processing [{i}/{len(urls)}]: {url} | 0")
            time.sleep(1)
            continue

        list_domain_count = 0
        try:
            for line_bytes in response:
                try:
                    line = line_bytes.decode("utf-8", errors="ignore")
                    domain = parse_line_to_domain(line)
                    if domain:
                        list_domain_count += 1
                        unique_domains.add(domain)
                except Exception:
                    continue
        except Exception as e:
            logging.error(f"Error reading stream from {url}: {e}")
        finally:
            try:
                response.close()
            except Exception:
                pass

        logging.info(f"Processing [{i}/{len(urls)}]: {url} | {list_domain_count}")
        time.sleep(1)

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

    # Automatically commit and push changes to GitHub with bulletproof error recovery
    git_commit_and_push()

if __name__ == "__main__":
    main()
