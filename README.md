# vscan-url-fuzzer
Fuzzes URL paths with common directory and file names to discover hidden or sensitive resources. Wordlist entries are joined under the full base path, so a base of http://host/app is fuzzed under /app. A default wordlist, common.txt, ships with the tool and is used when no wordlist is given. The --threads option runs requests through a bounded worker pool, and --recursive fuzzes one level under each discovered directory. A run in which no request succeeds ends as failed at a non-zero exit instead of reporting completion. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-url-fuzzer`

## Usage
`./vscan-url-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-w`: Path to the wordlist file (default: common.txt, shipped with this tool)
- `-o`: Path to the output file to save discovered URLs.
- `-t`: Number of worker threads used to send requests (default: 1)
- `-s`: Comma-separated list of accepted status codes (default: 200,301,302,403)
- `--timeout`: Request timeout in seconds (default: 5)
- `--recursive`: Fuzz one level under each discovered directory as well
- `--user-agent`: Custom User-Agent header (default: vscan-url-fuzzer)
- `--no-verify-ssl`: Disable SSL certificate verification (not recommended)

## License
Copyright (c) ShadowStrikeHQ
