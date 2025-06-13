import argparse
import requests
import logging
from bs4 import BeautifulSoup
import os
import sys
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the vscan-url-fuzzer tool.
    """
    parser = argparse.ArgumentParser(description="Fuzzes URL paths with common directory and file names to discover hidden resources.")
    parser.add_argument("url", help="The base URL to fuzz.")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file (default: common.txt).", default="common.txt")
    parser.add_argument("-o", "--output", help="Path to the output file to save discovered URLs.", default="discovered_urls.txt")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads (not implemented).", default=1) #Placeholder
    parser.add_argument("-s", "--status-codes", help="Comma-separated list of accepted status codes (default: 200,301,302,403).", default="200,301,302,403")
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds (default: 5).", default=5)
    parser.add_argument("--recursive", action="store_true", help="Recursively fuzz discovered directories (not implemented).") #Placeholder
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
    except:
        return False

def read_wordlist(wordlist_path):
    """
    Reads the wordlist from the given file path.
    Handles file not found and empty wordlist errors.
    """
    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f]
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


def fuzz_url(base_url, wordlist, output_file, accepted_status_codes, timeout, user_agent, verify_ssl):
    """
    Fuzzes the given URL with the provided wordlist and saves discovered URLs to the output file.
    """
    discovered_urls = set()
    headers = {'User-Agent': user_agent}

    try:
        with open(output_file, "a") as outfile:  # Open file in append mode

            for word in wordlist:
                url = urljoin(base_url, word)
                try:
                    response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
                    if response.status_code in accepted_status_codes:
                        logging.info(f"Found: {url} - Status Code: {response.status_code}")
                        if url not in discovered_urls:
                            outfile.write(url + "\n")
                            discovered_urls.add(url)
                except requests.exceptions.RequestException as e:
                    logging.error(f"Request failed for {url}: {e}")
                except Exception as e:
                    logging.error(f"An unexpected error occurred while processing {url}: {e}")


    except IOError as e:
        logging.error(f"Error writing to output file: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)



def main():
    """
    Main function to orchestrate the URL fuzzing process.
    """
    args = setup_argparse()

    # Input validation
    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    try:
        accepted_status_codes = [int(code) for code in args.status_codes.split(",")]
    except ValueError:
        logging.error("Invalid status codes provided.  Must be comma-separated integers.")
        sys.exit(1)

    # Disable SSL verification if requested (not recommended)
    verify_ssl = not args.no_verify_ssl

    wordlist = read_wordlist(args.wordlist)

    fuzz_url(args.url, wordlist, args.output, accepted_status_codes, args.timeout, args.user_agent, verify_ssl)

    logging.info("Fuzzing completed.")


if __name__ == "__main__":
    # Usage example:
    # python main.py http://example.com -w custom_wordlist.txt -o output.txt -s 200,404 --timeout 10
    # python main.py http://example.com --no-verify-ssl
    main()