import argparse
import requests
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the vscan-url-fuzzer tool.
    """
    parser = argparse.ArgumentParser(description="Fuzzes URL paths with common directory and file names to discover hidden resources.")
    parser.add_argument("url", help="The base URL to fuzz.")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file (default: common.txt, shipped with this tool).", default="common.txt")
    parser.add_argument("-o", "--output", help="Path to the output file to save discovered URLs.", default="discovered_urls.txt")
    parser.add_argument("-t", "--threads", type=int, help="Number of worker threads used to send requests (default: 1).", default=1)
    parser.add_argument("-s", "--status-codes", help="Comma-separated list of accepted status codes (default: 200,301,302,403).", default="200,301,302,403")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds (default: 5).", default=5)
    parser.add_argument("--recursive", action="store_true", help="Fuzz one level under each discovered directory as well.")
    parser.add_argument("--user-agent", help="Custom User-Agent header (default: vscan-url-fuzzer).", default="vscan-url-fuzzer")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification (not recommended).")


    return parser.parse_args()


def is_valid_url(url):
    """
    Validates if the given URL is in a correct format.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def read_wordlist(wordlist_path):
    """
    Reads the wordlist from the given file path.
    Handles file not found and empty wordlist errors.

    When the default common.txt is not in the working directory, the
    copy shipped next to this script is used, so a default run works
    from any directory.
    """
    path = wordlist_path
    if not os.path.exists(path):
        bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common.txt")
        if os.path.abspath(bundled) != os.path.abspath(path) and os.path.exists(bundled):
            path = bundled
    try:
        with open(path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        if not words:
            raise ValueError("Wordlist file is empty.")
        return words
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading wordlist: {e}")
        sys.exit(1)


def join_word(base_url, word):
    """
    Join one wordlist entry onto the base URL, keeping the base path.

    The base is treated as a directory: a base of http://host/app and
    the word sentinelok produce http://host/app/sentinelok, never a
    path at the host root.
    """
    base = base_url if base_url.endswith("/") else base_url + "/"
    # A wordlist entry that is itself a full URL survives the slash stripping and replaces the base entirely inside urljoin. One such line in a borrowed wordlist sends a probe to somebody else's server under my user agent.
    return urljoin(base, word.lstrip("/"))


def _probe(url, headers, timeout, verify_ssl):
    """Send one request. Returns (url, status) or (url, None) on failure."""
    try:
        # requests follows redirects for me, so the status I judge is the landing page's, not the probed path's. Against a catch all that redirects everything to a login page, every word in the list lands on the same 200 and I report the whole wordlist as discovered. I never probe a nonsense word first to learn what this target does with paths that cannot exist.
        response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
        return url, response.status_code
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for {url}: {e}")
        return url, None
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing {url}: {e}")
        return url, None


def fuzz_level(base_url, wordlist, accepted_status_codes, timeout, user_agent, verify_ssl, threads):
    """
    Fuzz one level under base_url.

    Returns (discovered_urls, succeeded, failed), where succeeded is
    the count of requests that received any response at all.
    """
    headers = {'User-Agent': user_agent}
    urls = [join_word(base_url, word) for word in wordlist]
    discovered = []
    succeeded = 0
    failed = 0
    if threads and threads > 1:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            # pool.map hands me results back in wordlist order however the requests actually finished, which keeps the output file stable between threaded and serial runs. The log lines inside _probe are not so lucky: with several workers they interleave in whatever order the responses landed.
            results = list(pool.map(lambda u: _probe(u, headers, timeout, verify_ssl), urls))
    else:
        results = [_probe(u, headers, timeout, verify_ssl) for u in urls]
    for url, status in results:
        if status is None:
            failed += 1
            continue
        succeeded += 1
        if status in accepted_status_codes:
            logging.info(f"Found: {url} - Status Code: {status}")
            discovered.append(url)
    return discovered, succeeded, failed


def fuzz_url(base_url, wordlist, output_file, accepted_status_codes, timeout, user_agent, verify_ssl, threads=1, recursive=False):
    """
    Fuzzes the given URL with the provided wordlist and saves discovered URLs to the output file.

    With recursive set, each discovered entry whose last path segment
    has no file extension is treated as a directory and fuzzed one
    level deeper with the same wordlist. Recursion stops there.

    Returns (succeeded, failed) request counts across all levels.
    """
    discovered_urls = set()
    succeeded = 0
    failed = 0
    try:
        # Append is deliberate for long runs, but it means the output file accumulates across runs while my dedupe set only remembers this run. A second run over the same target writes duplicates of everything the first run found, and stale entries from a changed site stay in the file forever.
        with open(output_file, "a") as outfile:  # Open file in append mode
            discovered, ok, bad = fuzz_level(base_url, wordlist, accepted_status_codes, timeout, user_agent, verify_ssl, threads)
            succeeded += ok
            failed += bad
            for url in discovered:
                if url not in discovered_urls:
                    outfile.write(url + "\n")
                    discovered_urls.add(url)
            if recursive:
                for url in discovered:
                    last_segment = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
                    # A dot is my whole test for file versus directory. A directory named v1.0 is never recursed into, and an extensionless file is fuzzed as if it were a directory, spending a full wordlist pass underneath a path that cannot hold children.
                    if "." in last_segment:
                        continue
                    deeper, ok, bad = fuzz_level(url, wordlist, accepted_status_codes, timeout, user_agent, verify_ssl, threads)
                    succeeded += ok
                    failed += bad
                    for found in deeper:
                        if found not in discovered_urls:
                            outfile.write(found + "\n")
                            discovered_urls.add(found)
    except IOError as e:
        logging.error(f"Error writing to output file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)
    return succeeded, failed



def main():
    """
    Main function to orchestrate the URL fuzzing process.
    """
    args = setup_argparse()

    # Input validation
    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    if args.threads < 1:
        logging.error("Threads must be at least 1.")
        sys.exit(1)

    try:
        accepted_status_codes = [int(code) for code in args.status_codes.split(",")]
    except ValueError:
        logging.error("Invalid status codes provided.  Must be comma-separated integers.")
        sys.exit(1)

    # Disable SSL verification if requested (not recommended)
    verify_ssl = not args.no_verify_ssl

    wordlist = read_wordlist(args.wordlist)

    succeeded, failed = fuzz_url(args.url, wordlist, args.output, accepted_status_codes, args.timeout, args.user_agent, verify_ssl, threads=args.threads, recursive=args.recursive)

    if succeeded == 0:
        logging.error(f"Fuzzing failed: no request succeeded ({failed} failed). The target was not reached, so no completion is reported.")
        sys.exit(1)

    logging.info("Fuzzing completed.")


if __name__ == "__main__":
    # Usage example:
    # python main.py http://example.com -w custom_wordlist.txt -o output.txt -s 200,404 --timeout 10
    # python main.py http://example.com --no-verify-ssl
    main()
