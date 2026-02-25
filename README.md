# DeepWebHarvester

**Advanced Python OSINT intelligence platform for dark web analysis via Tor.**

[![CI](https://github.com/servais1983/deepwebharvester/actions/workflows/ci.yml/badge.svg)](https://github.com/servais1983/deepwebharvester/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-57.74%25-yellow)](htmlcov/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## Overview

DeepWebHarvester is a production-grade cybersecurity intelligence platform that anonymously crawls, parses, and stores structured data from Tor hidden services. It provides both a full graphical desktop interface and a headless command-line interface, making it suitable for threat analysts who need an accessible tool as well as for automated pipelines and scheduled intelligence gathering workflows.

The platform routes all network traffic through the Tor SOCKS5 proxy, performs BFS-based crawling with configurable depth and page limits, deduplicates results globally using SHA-256 content hashing, and persists findings simultaneously to JSON, CSV, and SQLite. A built-in resume mechanism allows interrupted sessions to continue exactly where they left off.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Graphical Interface](#graphical-interface)
- [Installation](#installation)
- [Configuration](#configuration)
- [Command-Line Usage](#command-line-usage)
- [Output Formats](#output-formats)
- [Docker Deployment](#docker-deployment)
- [Development](#development)
- [Security Model](#security-model)
- [Use Cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Features

### Core engine

- **Anonymous crawling** — All traffic routed via `socks5h` (DNS resolution through Tor, preventing leaks)
- **BFS crawl engine** — Configurable depth and per-site page limits; queue-based, memory-efficient
- **Global content deduplication** — SHA-256 hashing prevents re-storing identical pages across all seeds
- **Concurrent multi-site crawling** — Thread-pool based parallelism; multiple .onion sites crawled simultaneously
- **Tor circuit renewal** — Automatic identity rotation every N pages for operational security
- **Exponential back-off retries** — Graceful handling of unstable .onion servers
- **Blacklist filtering** — Configurable path exclusions (login pages, registration forms)
- **Resume support** — SQLite persistence tracks crawled URLs; restart without re-visiting known pages

### Interfaces

- **Desktop GUI** — Full graphical interface built with Tkinter: real-time log stream, progress tracking, settings panel, and one-click result export
- **CLI** — Feature-complete command-line interface with layered config override

### Data management

- **Multi-format output** — JSON, CSV, and SQLite written simultaneously
- **SQLite query support** — Results are immediately queryable for ad-hoc analysis
- **Timestamped exports** — Each run produces uniquely named output files

### Intelligence and reporting

- **Automated IOC extraction** — Regex-based extraction of IPv4 addresses, email addresses, MD5/SHA1/SHA256 hashes, CVE identifiers, Bitcoin and Monero wallet addresses, Tor v3 onion references, clearweb domains, HTTP(S) URLs, and PGP key blocks
- **Threat classification** — Nine threat categories (Malware, Financial Fraud, Credentials, Hacking Services, Marketplaces, and more) with keyword-density-based risk scoring on a 0–10 scale
- **Risk labels** — Low / Medium / High / Critical risk classification per page
- **HTML intelligence report** — Self-contained single-file report with executive summary, risk distribution chart, IOC registry, high-risk page index, and per-site threat breakdown; no CDN or JavaScript dependencies
- **IOC persistence** — All extracted IOC data serialised as JSON and stored in the SQLite `ioc_data` column alongside each crawl result

### Engineering quality

- **Layered configuration** — Defaults → YAML file → environment variables → CLI/GUI flags
- **Secrets via environment** — Tor control password never stored in code or config files
- **206 automated tests** — 57.74% code coverage across all modules
- **GitHub Actions CI** — Multi-Python matrix (3.9–3.12) plus dependency security audit
- **Two-stage Docker build** — Minimal runtime image, non-root execution
- **Type-annotated codebase** — Full type hints enforced by mypy in strict mode

---

## Architecture

```
deepwebharvester/
  __init__.py       Package metadata and version
  cli.py            Argparse CLI entry point
  gui.py            Tkinter desktop GUI
  config.py         Layered configuration loader (defaults, YAML, env)
  tor_manager.py    Tor session factory and circuit renewal
  extractor.py      HTML parser, URL validator, link harvester
  crawler.py        BFS engine with dedup, retries, concurrency, stats
  storage.py        JSON / CSV / SQLite persistence (with IOC column)
  intelligence.py   IOC extraction and threat classification engine
  report.py         Self-contained HTML intelligence report generator

tests/
  conftest.py            Shared fixtures (mock Tor, temp storage)
  test_cli.py
  test_config.py
  test_crawler.py
  test_extractor.py
  test_storage.py
  test_tor_manager.py
  test_intelligence.py   IOC extraction and threat classification tests
  test_report.py         HTML report generation tests

.github/workflows/
  ci.yml            GitHub Actions CI pipeline

Dockerfile          Two-stage build (builder + slim runtime)
docker-compose.yml  Tor sidecar + harvester service
pyproject.toml      Build config, linters, test runner, coverage
```

**Data flow:**

```
User (GUI or CLI)
  -> config.py           Load layered configuration
  -> tor_manager.py      Create Tor-proxied requests session
  -> crawler.py          BFS crawl loop
       -> extractor.py   Fetch, parse, extract links, hash content
       -> storage.py     Persist results (JSON + CSV + SQLite)
  -> intelligence.py     IOC extraction + threat classification
  -> report.py           Generate self-contained HTML report
```

---

## Graphical Interface

DeepWebHarvester ships a full desktop GUI accessible via:

```bash
deepwebharvester-gui
```

The interface is divided into four panels:

**Settings panel** — Configure seed URLs, crawl depth, page limit, concurrent workers, request delay, output directory, and Tor control password. All settings are validated before the crawl starts.

**Control bar** — Start, pause, and stop controls with a real-time progress indicator showing pages crawled, pages failed, and elapsed time.

**Live log stream** — Colour-coded, scrollable log output with DEBUG/INFO/WARNING/ERROR levels displayed in real time as the crawl progresses, without blocking the UI.

**Results summary** — On completion, shows aggregate statistics and the paths to all output files. Includes quick-open buttons for JSON, CSV, and SQLite results.

The GUI respects all the same configuration layering as the CLI: it pre-populates from `config.yaml` and `.env` if present, and writes back a session config when a crawl is started.

---

## Installation

### System requirements

- Python 3.9 or later
- Tor service with control port enabled (see below)
- Linux (tested on Kali Linux, Ubuntu 22.04, Debian 12)

### Install from source

```bash
git clone https://github.com/servais1983/deepwebharvester.git
cd deepwebharvester

python3 -m venv .venv
source .venv/bin/activate

# Runtime only
pip install -e .

# Runtime + development tools
pip install -e ".[dev]"
```

### Install and configure Tor

```bash
sudo apt update && sudo apt install -y tor

# Generate a hashed password for the control port
tor --hash-password YourStrongPassword123
# Output: 16:ABCDEF1234...

# Edit /etc/tor/torrc
sudo nano /etc/tor/torrc
```

Add or uncomment:

```
ControlPort 9051
HashedControlPassword 16:ABCDEF1234...
```

```bash
sudo systemctl restart tor
sudo systemctl status tor   # should display: active (running)
```

---

## Configuration

Configuration is resolved in the following priority order (highest wins):

```
GUI / CLI flags  >  Environment variables  >  config.yaml  >  Built-in defaults
```

### Environment variables

```bash
cp .env.example .env
```

```ini
# .env — never commit this file
TOR_CONTROL_PASSWORD=YourStrongPassword123

# Optional overrides
# TOR_SOCKS_PORT=9050
# TOR_CONTROL_PORT=9051
# LOG_LEVEL=INFO
# OUTPUT_DIR=results
```

Credentials must always be provided via environment variables. The YAML configuration file must never contain passwords.

### YAML configuration file

```bash
cp config.yaml.example config.yaml
```

Key settings:

```yaml
tor:
  renew_circuit_every: 10     # rotate exit node after N pages

crawler:
  max_depth: 2                # 0 = seed page only
  max_pages: 20               # per-site ceiling
  crawl_delay: 7.0            # seconds between requests
  max_workers: 3              # concurrent site threads
  blacklist_paths:
    - /login
    - /register
    - /signup
    - /auth

storage:
  output_dir: results
  sqlite_output: true         # required for --resume

seed_urls:
  - "http://your56charv3addresshere.onion"

log_level: INFO
log_file: logs/deepwebharvester.log
```

---

## Command-Line Usage

```
usage: deepwebharvester [-h] [--version] [--config PATH] [--url ONION_URL]
                        [--depth N] [--pages N] [--workers N] [--delay SECS]
                        [--output DIR] [--no-json] [--no-csv] [--no-sqlite]
                        [--log-level {DEBUG,INFO,WARNING,ERROR}]
                        [--verify-tor] [--resume]
```

### Examples

```bash
# Crawl a single site
deepwebharvester --url http://<56-char-hash>.onion/

# Use a config file with multiple seeds
deepwebharvester --config config.yaml

# Verify Tor routing before crawling, limit scope
deepwebharvester --url http://<hash>.onion/ --verify-tor --depth 1 --pages 5

# Resume a previous session
deepwebharvester --config config.yaml --resume

# JSON output only, custom directory, debug logging
deepwebharvester --config config.yaml \
  --no-csv --no-sqlite --output /tmp/intel --log-level DEBUG

# Multiple seed URLs
deepwebharvester \
  --url http://<hash1>.onion/ \
  --url http://<hash2>.onion/ \
  --workers 2

# Launch the graphical interface
deepwebharvester-gui
```

---

## Output Formats

All output files are written to the configured `output_dir` (default: `results/`).

### JSON

```json
[
  {
    "url": "http://<hash>.onion/page",
    "site": "http://<hash>.onion",
    "title": "Page Title",
    "depth": 0,
    "crawl_time_s": 4.21,
    "links_found": 12,
    "content_hash": "sha256hex...",
    "text": "Visible body text..."
  }
]
```

### CSV

Columns: `URL, Site, Title, Depth, CrawlTime(s), LinksFound, ContentHash, Text`

### SQLite

```sql
-- List all pages from a specific site
SELECT url, title, depth, crawled_at
FROM crawl_results
WHERE site = 'http://<hash>.onion'
ORDER BY crawled_at DESC;

-- Count unique sites
SELECT site, COUNT(*) AS pages
FROM crawl_results
GROUP BY site;
```

The SQLite database also serves as the source of truth for `--resume` mode. Any URL already present in `crawl_results` is skipped on subsequent runs.

---

## Docker Deployment

### Using docker-compose (recommended)

```bash
export TOR_CONTROL_PASSWORD=YourStrongPassword123

docker compose up --build
```

Results appear in `./results/`. The compose file starts a Tor proxy sidecar and waits for it to pass a health check before launching the harvester.

### Standalone container

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

### Setup

```bash
pip install -e ".[dev]"
```

### Running tests

```bash
pytest                             # full suite with coverage
pytest tests/test_extractor.py     # single module
pytest -k "dedup"                  # match by name pattern
pytest -v --no-cov                 # verbose, no coverage overhead
```

### Code quality tools

```bash
black deepwebharvester tests       # format
isort deepwebharvester tests       # sort imports
flake8 deepwebharvester tests      # lint
mypy deepwebharvester              # type check
```

### Conventions

| Tool | Config |
|---|---|
| Formatter | black, line length 100 |
| Import order | isort, profile = black |
| Type checker | mypy strict mode |
| Test runner | pytest |
| Coverage target | >= 80% (`fail_under = 80`) |

---

## Security Model

| Concern | Control |
|---|---|
| Credential exposure | Tor password via environment variable only; never in config files or code |
| DNS leaks | `socks5h` scheme resolves DNS through Tor |
| Traffic correlation | Configurable crawl delay and periodic circuit renewal |
| Duplicate processing | Content hashing deduplicates across sessions |
| Privilege escalation | Docker image runs as an unprivileged `harvester` user |
| Dependency vulnerabilities | CI runs `pip-audit` on every push |

---

## Use Cases

**Threat intelligence monitoring** — Systematically index dark web forums, marketplaces, and paste sites for indicators of compromise, leaked credentials, or advance notice of planned attacks.

**Data breach detection** — Identify when proprietary data, customer records, or authentication material appears on hidden services. Alert security teams for rapid response.

**Law enforcement support** — Provide investigators with a reproducible, auditable method to collect and preserve evidence from hidden services.

**Brand and IP protection** — Detect counterfeit goods, pirated software, and fraudulent services impersonating legitimate organisations.

**Competitive intelligence and research** — Study dark web ecosystem structure, service uptime patterns, and underground market dynamics for academic or commercial research.

**Proactive defence** — Build continuously updated threat intelligence databases to enrich SIEM platforms, feed anomaly detection models, and improve security posture.

---

## Troubleshooting

### Tor is not running

```bash
sudo systemctl status tor

# If the status shows "active (exited)" rather than "active (running)":
sudo systemctl restart tor

# Confirm the SOCKS port is listening
ss -aln | grep 9050
```

### Verify Tor connectivity

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Expected: {"IsTor":true, "IP":"..."}
```

### Circuit renewal fails

Confirm that `ControlPort 9051` and a `HashedControlPassword` are set in `/etc/tor/torrc`, and that the plain-text value in `TOR_CONTROL_PASSWORD` matches the hash generated by `tor --hash-password`.

```bash
journalctl -xeu tor
```

### GUI does not start

Ensure `python3-tk` is installed on your system:

```bash
sudo apt install python3-tk
python3 -c "import tkinter; print(tkinter.TkVersion)"
```

### .onion sites are slow

Hidden services are inherently slower than the clearweb. The default 7-second `crawl_delay` is intentional and reduces detection risk. For exploratory runs, reduce `max_pages` rather than `crawl_delay`.

---

## Disclaimer

This software is intended exclusively for legitimate cybersecurity research, OSINT intelligence gathering, and authorised investigations. Access to computer systems or networks without explicit permission from the owner is illegal in most jurisdictions. The authors accept no responsibility for any unlawful use of this software. Users must obtain proper authorisation before targeting any system or service and must comply with all applicable national and international laws and regulations.

---

**Author:** Tech Enthusiast
**Contact:** [LinkedIn](http://linkedin.com/in/tech-enthusiast-669279263)
**License:** [MIT](LICENSE)
