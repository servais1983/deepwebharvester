# DeepWebHarvester

> Advanced Python OSINT crawler for legitimate dark web intelligence gathering via Tor.

[![CI](https://github.com/servais1983/deepwebharvester/actions/workflows/ci.yml/badge.svg)](https://github.com/servais1983/deepwebharvester/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

DeepWebHarvester anonymously navigates and extracts intelligence from `.onion` hidden services using the Tor network. Built for cybersecurity professionals and OSINT practitioners who need structured, reproducible data from the dark web.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Docker](#docker)
- [Development](#development)
- [Security Considerations](#security-considerations)
- [Use Cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Features

| Feature | Description |
|---|---|
| **Anonymous Crawling** | All traffic routed via Tor SOCKS5 proxy — DNS resolved through Tor (`socks5h`) |
| **BFS Crawl Engine** | Configurable depth and page-count limits per site |
| **Concurrent Sites** | Thread-pool based parallel crawling of multiple seed URLs |
| **Content Deduplication** | SHA-256 hashing prevents duplicate pages across all sites |
| **Resume Support** | SQLite tracks crawled URLs — restart a crawl without re-visiting pages |
| **Circuit Renewal** | Automatically requests a new Tor exit node every N pages |
| **Retry + Backoff** | Exponential back-off retries on transient network failures |
| **Blacklist Filtering** | Skip authentication-required paths (`/login`, `/register`, …) |
| **Multi-format Output** | JSON, CSV, and SQLite simultaneously |
| **Layered Config** | Defaults → YAML file → environment variables → CLI flags |
| **Secure by Default** | Passwords via env vars only; no credentials in code or config files |
| **Docker Ready** | Two-stage Dockerfile + docker-compose with Tor sidecar |

---

## Architecture

```
deepwebharvester/
├── deepwebharvester/
│   ├── __init__.py      # Package metadata
│   ├── cli.py           # Argparse CLI entry point
│   ├── config.py        # Layered configuration (defaults → YAML → env)
│   ├── tor_manager.py   # Tor session creation & circuit renewal
│   ├── extractor.py     # HTML parsing, URL validation, link harvesting
│   ├── crawler.py       # BFS engine with dedup, retries, concurrency
│   └── storage.py       # JSON / CSV / SQLite persistence
├── tests/
│   ├── conftest.py      # Shared fixtures (mock Tor, temp storage)
│   ├── test_config.py
│   ├── test_extractor.py
│   ├── test_crawler.py
│   ├── test_storage.py
│   └── test_tor_manager.py
├── .github/workflows/ci.yml   # GitHub Actions CI (multi-Python, audit)
├── config.yaml.example
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── requirements.txt
```

**Data flow:**

```
CLI (cli.py)
  └─ loads config (config.py)
       └─ creates TorManager (tor_manager.py)
            └─ creates Crawler (crawler.py)
                 ├─ fetches pages via Tor session
                 ├─ extracts content (extractor.py)
                 └─ saves results (storage.py) → JSON + CSV + SQLite
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/servais1983/deepwebharvester.git
cd deepwebharvester

# 2. Install
pip install -e .

# 3. Configure secrets
cp .env.example .env
# Edit .env: set TOR_CONTROL_PASSWORD

# 4. Start Tor
sudo systemctl start tor

# 5. Run
deepwebharvester --url http://<56-char-v3-address>.onion/ --verify-tor
```

---

## Installation

### Requirements

- Python 3.9+
- Tor service (with control port enabled)
- Linux (tested on Kali, Ubuntu, Debian)

### From source

```bash
git clone https://github.com/servais1983/deepwebharvester.git
cd deepwebharvester

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install runtime dependencies
pip install -e .

# Or with development tools
pip install -e ".[dev]"
```

### Install Tor

```bash
sudo apt update && sudo apt install -y tor
```

### Configure the Tor control port

```bash
# Generate a hashed password
tor --hash-password YourStrongPassword123
# → 16:ABCDEF1234...

# Edit /etc/tor/torrc — add or uncomment:
sudo nano /etc/tor/torrc
```

```
ControlPort 9051
HashedControlPassword 16:ABCDEF1234...
```

```bash
sudo systemctl restart tor
sudo systemctl status tor   # should show "active (running)"
```

---

## Configuration

DeepWebHarvester uses a **layered configuration system** (highest priority wins):

```
CLI flags > environment variables > config.yaml > built-in defaults
```

### Environment variables (`.env`)

```bash
cp .env.example .env
```

```ini
# .env
TOR_CONTROL_PASSWORD=YourStrongPassword123
# TOR_SOCKS_PORT=9050
# TOR_CONTROL_PORT=9051
# LOG_LEVEL=INFO
# OUTPUT_DIR=results
```

> **Security:** Never hard-code credentials. Always use env vars or a secrets manager.

### YAML config file

```bash
cp config.yaml.example config.yaml
```

Key settings:

```yaml
tor:
  renew_circuit_every: 10   # new exit node after N pages

crawler:
  max_depth: 2              # 0 = seed page only
  max_pages: 20             # per-site limit
  crawl_delay: 7.0          # seconds between requests
  max_workers: 3            # concurrent sites
  blacklist_paths:
    - /login
    - /register

storage:
  output_dir: results
  sqlite_output: true       # also enables --resume

seed_urls:
  - "http://your56charv3addresshere.onion"
```

---

## Usage

### CLI reference

```
usage: deepwebharvester [-h] [--version] [--config PATH] [--url ONION_URL]
                        [--depth N] [--pages N] [--workers N] [--delay SECS]
                        [--output DIR] [--no-json] [--no-csv] [--no-sqlite]
                        [--log-level {DEBUG,INFO,WARNING,ERROR}]
                        [--verify-tor] [--resume]
```

### Common examples

```bash
# Basic crawl of a single site
deepwebharvester --url http://<hash>.onion/

# Use a config file with multiple seeds
deepwebharvester --config config.yaml

# Verify Tor, limit to 1 depth level, 5 pages
deepwebharvester --url http://<hash>.onion/ --verify-tor --depth 1 --pages 5

# Resume a previous crawl (skip already-seen URLs)
deepwebharvester --config config.yaml --resume

# High verbosity, JSON only, custom output folder
deepwebharvester --config config.yaml \
  --log-level DEBUG --no-csv --no-sqlite --output /tmp/hunt

# Multiple seed URLs from the command line
deepwebharvester \
  --url http://<hash1>.onion/ \
  --url http://<hash2>.onion/ \
  --workers 2
```

---

## Output Formats

Results are written to the `results/` directory (configurable via `--output`).

### JSON (`results_YYYYMMDD_HHMMSS.json`)

```json
[
  {
    "url": "http://<hash>.onion/page",
    "site": "http://<hash>.onion",
    "title": "Page Title",
    "depth": 0,
    "crawl_time_s": 4.21,
    "links_found": 12,
    "content_hash": "sha256...",
    "text": "Visible page text..."
  }
]
```

### CSV (`results_YYYYMMDD_HHMMSS.csv`)

Columns: `URL, Site, Title, Depth, CrawlTime(s), LinksFound, ContentHash, Text`

### SQLite (`deepwebharvester.db`)

```sql
SELECT url, title, site, depth, crawled_at
FROM crawl_results
WHERE site = 'http://<hash>.onion'
ORDER BY crawled_at DESC;
```

The SQLite database powers `--resume` mode: re-running with `--resume` skips
any URL already in the `crawl_results` table.

---

## Docker

### Build and run with docker-compose

```bash
# Set your Tor control password
export TOR_CONTROL_PASSWORD=YourStrongPassword123

# Build and start (Tor sidecar + harvester)
docker compose up --build

# Results appear in ./results/
```

### Run standalone container against an existing Tor service

```bash
docker build -t deepwebharvester .

docker run --rm \
  -e TOR_CONTROL_PASSWORD=YourStrongPassword123 \
  -v "$(pwd)/results:/app/results" \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  deepwebharvester --config /app/config.yaml --verify-tor
```

---

## Development

### Set up dev environment

```bash
pip install -e ".[dev]"
```

### Run tests

```bash
pytest                          # all tests with coverage
pytest tests/test_extractor.py  # single module
pytest -k "test_valid"          # run tests matching a pattern
```

### Code quality

```bash
black deepwebharvester tests        # format
isort deepwebharvester tests        # sort imports
flake8 deepwebharvester tests       # lint
mypy deepwebharvester               # type check
```

### Project conventions

- **Formatter:** [black](https://black.readthedocs.io/) (line length 100)
- **Import order:** [isort](https://pycqa.github.io/isort/) with `profile = "black"`
- **Type hints:** enforced via [mypy](https://mypy-lang.org/) in strict mode
- **Test coverage target:** ≥ 80 % (`fail_under = 80` in `pyproject.toml`)

---

## Security Considerations

| Concern | Mitigation |
|---|---|
| Credential leakage | Tor password via env var only; never stored in code or YAML |
| Traffic anonymity | `socks5h` DNS-over-Tor prevents DNS leaks |
| Detection | Configurable `crawl_delay` + periodic circuit renewal |
| Duplicate work | Content hashing deduplicates across sessions |
| Non-root execution | Docker image runs as an unprivileged `harvester` user |
| Dependency safety | CI runs `pip-audit` on every push |

---

## Use Cases

- **Threat Intelligence** — monitor dark web forums for emerging attack techniques,
  leaked credentials, or planned campaigns against your organisation.
- **Data Breach Detection** — identify when company data or customer PII appears
  on dark web marketplaces.
- **Law Enforcement** — support investigations by systematically indexing
  hidden service content.
- **Corporate Security** — detect brand abuse, phishing kits, or counterfeits
  distributed through hidden channels.
- **Academic Research** — study dark web ecosystem trends, service lifecycles,
  and underground market dynamics.
- **Proactive Defence** — enrich threat intelligence feeds with dark web
  indicators of compromise (IoCs).

---

## Troubleshooting

### Tor is not running

```bash
sudo systemctl status tor
# If active (exited) rather than active (running):
sudo systemctl restart tor
ss -aln | grep 9050          # SOCKS port should be listening
```

### Verify Tor connection manually

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Should return: {"IsTor":true, "IP":"..."}
```

### Circuit renewal fails

Check that `ControlPort` and `HashedControlPassword` are set in `/etc/tor/torrc`
and that the plain-text password in `TOR_CONTROL_PASSWORD` matches the hash.

```bash
journalctl -xeu tor          # inspect Tor service logs
```

### Slow crawling

`.onion` sites are inherently slower than the clear web. The default 7-second
`crawl_delay` is intentional. Reduce `max_pages` for faster exploratory runs
or increase `max_workers` to crawl multiple sites in parallel.

---

## Disclaimer

> This tool is intended **exclusively** for legitimate cybersecurity research,
> OSINT, and authorised investigations. Unauthorised access to computer systems,
> harassment, or any illegal activity using this tool is strictly prohibited and
> may be punishable under applicable national and international laws.
>
> The author accepts **no responsibility** for any misuse of this software.
> Users must obtain proper authorisation before targeting any system or service
> and must comply with all relevant legal and ethical standards.

---

**Creator:** Tech Enthusiast · [LinkedIn](http://linkedin.com/in/tech-enthusiast-669279263)
