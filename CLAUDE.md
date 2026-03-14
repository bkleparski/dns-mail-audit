# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
pip3 install -r requirements.txt
```

Requires Python 3.10+.

## Running the auditor

```bash
# Single domain
python3 mail_dns_audit.py -d example.com

# Multiple domains
python3 mail_dns_audit.py -d example.com firma.pl

# From file
python3 mail_dns_audit.py -f domains.txt

# All output formats to a directory (auto-named files)
python3 mail_dns_audit.py -f domains.txt -o ./raporty

# Specific output files
python3 mail_dns_audit.py -f domains.txt --html raport.html --csv raport.csv --json raport.json

# Custom DKIM selector(s)
python3 mail_dns_audit.py -d firma.pl --dkim-selector selector1 --dkim-selector selector2

# No color (for logs/CI)
python3 mail_dns_audit.py -f domains.txt --no-color
```

## Architecture

Single-file tool (`mail_dns_audit.py`). Data flows: DNS queries → per-check dicts → `audit_domain()` aggregation → output formatters.

**Check functions** (`check_mx`, `check_spf`, `check_dmarc`, `check_dkim`, `check_mta_sts`, `check_tls_rpt`, `check_bimi`) each return a dict with keys: `status`, `note`, `raw`, and a type-specific record field. Status values: `OK`, `WARN`, `MISSING`, `ERROR`, `NOT_FOUND`.

**`check_spoofability(spf, dmarc)`** derives an overall spoofing risk (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) from the SPF and DMARC check results.

**`audit_domain()`** calls all checks, then sets `overall` (`OK`/`WARN`/`HIGH`/`CRITICAL`) based on the presence of `MISSING`/`ERROR`/`WARN` statuses in MX, SPF, DMARC and the spoofability risk.

**Output formatters**: `print_result()` / `print_summary()` for terminal; `generate_html()`, `generate_csv()`, `generate_json()` write to files. JSON output strips `raw` fields before writing.

**`domains.txt`**: one domain per line; lines starting with `#` are ignored.
