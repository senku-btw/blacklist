import os
import re
import sys
import time
import logging
import urllib.request
from urllib.error import URLError, HTTPError
from pathlib import Path
import tempfile

# Configuration
INPUT_FILE = "minor-lists.txt"
OUTPUT_DIR = Path("blacklists")
OUTPUT_FILE = OUTPUT_DIR / "blacklist-extra.txt"
TIMEOUT = 15
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds
USER_AGENT = "Mozilla/5.0 (Compatible; PiholeResilientAggregator/2.0)"
MAX_CONTENT_SIZE = 50 * 1024 * 1024  # 50MB safety cap per list

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
    if not line or line.startswith(("#", "!", "[", "//")):
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

def main():
    input_path = Path(INPUT_FILE)
    if not input_path.exists():
        logging.error(f"Input file '{INPUT_FILE}' not found.")
        sys.exit(1)

    try:
        urls = [
            line.strip() for line in input_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except Exception as e:
        logging.error(f"Failed to read input file: {e}")
        sys.exit(1)

    logging.info(f"Loaded {len(urls)} target URLs from {INPUT_FILE}")

    unique_domains = set()

    for i, url in enumerate(urls, 1):
        logging.info(f"Processing [{i}/{len(urls)}]: {url}")
        response = fetch_url_stream(url)
        if not response:
            time.sleep(1)
            continue

        try:
            # Stream line-by-line to maintain minimal RAM usage
            for line_bytes in response:
                try:
                    line = line_bytes.decode("utf-8", errors="ignore")
                    domain = parse_line_to_domain(line)
                    if domain:
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

        # Polite delay between requests to protect target servers
        time.sleep(1)

    if not unique_domains:
        logging.error("No valid domains collected. Aborting to protect existing blocklist integrity.")
        sys.exit(1)

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Atomic write pattern to prevent half-written or corrupted output files
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=OUTPUT_DIR, delete=False, encoding="utf-8") as tmp:
            temp_file_path = Path(tmp.name)
            sorted_domains = sorted(unique_domains)
            for domain in sorted_domains:
                tmp.write(domain + "\n")
        
        # Atomic file replacement
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

if __name__ == "__main__":
    main()
