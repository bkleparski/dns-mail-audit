#!/usr/bin/env python3
"""
mail_dns_audit.py — Email DNS Security Auditor
Sprawdza MX, SPF, DKIM, DMARC, MTA-STS, BIMI, TLS-RPT dla listy domen.
Generuje raporty: terminal (kolorowy), HTML, JSON, CSV.

Użycie:
  python mail_dns_audit.py -d example.com
  python mail_dns_audit.py -d example.com another.pl
  python mail_dns_audit.py -f domains.txt
  python mail_dns_audit.py -f domains.txt --html raport.html --csv raport.csv --json raport.json
  python mail_dns_audit.py -d example.com --dkim-selector google
"""

import argparse
import csv
import json
import socket
import sys
import os
from datetime import datetime
from pathlib import Path

# ── zależności zewnętrzne ──────────────────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[ERROR] Brak modułu 'dnspython'. Zainstaluj: pip install dnspython")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    print("[WARN]  Brak modułu 'colorama'. Zainstaluj: pip install colorama")
    HAS_COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""

# ── stałe ─────────────────────────────────────────────────────────────────────
VERSION = "1.2.0"
DEFAULT_DKIM_SELECTORS = [
    "default", "google", "mail", "selector1", "selector2",
    "k1", "dkim", "email", "key1", "s1", "s2", "mx",
    "smtp", "protonmail", "mailjet", "sendgrid", "amazonses",
]

# ── helpers ───────────────────────────────────────────────────────────────────

def _resolve(qname: str, rtype: str) -> list[str]:
    """Zwraca listę tekstowych wyników lub [] jeśli brak rekordu."""
    try:
        answers = dns.resolver.resolve(qname, rtype, lifetime=8)
        if rtype == "TXT":
            return [b"".join(rd.strings).decode(errors="replace") for rd in answers]
        elif rtype == "MX":
            return [f"{rd.preference} {rd.exchange.to_text()}" for rd in answers]
        else:
            return [rd.to_text() for rd in answers]
    except (dns.exception.DNSException, Exception):
        return []


def check_mx(domain: str) -> dict:
    records = _resolve(domain, "MX")
    hosts = []
    for r in records:
        parts = r.split(None, 1)
        if len(parts) == 2:
            hosts.append({"priority": parts[0], "host": parts[1].rstrip(".")})
    status = "OK" if hosts else "MISSING"
    note = "" if hosts else "Brak rekordu MX — domena nie odbiera poczty."
    return {"status": status, "records": hosts, "note": note, "raw": records}


def check_spf(domain: str) -> dict:
    txts = _resolve(domain, "TXT")
    spf = [t for t in txts if t.startswith("v=spf1")]
    if not spf:
        return {"status": "MISSING", "record": None,
                "note": "Brak rekordu SPF. Zalecane: dodaj rekord TXT z 'v=spf1 ... -all'", "raw": []}
    if len(spf) > 1:
        return {"status": "ERROR", "record": spf,
                "note": "Wiele rekordów SPF — niedozwolone (RFC 7208). Usuń duplikaty.", "raw": spf}

    rec = spf[0]
    notes = []
    if "~all" in rec:
        notes.append("SoftFail (~all): wiadomości z nieautoryzowanych serwerów są tagowane, nie odrzucane.")
    elif "?all" in rec:
        notes.append("Neutral (?all): brak ochrony — rozważ zmianę na -all lub ~all.")
    elif "+all" in rec:
        notes.append("NIEBEZPIECZNE: +all zezwala KAŻDEMU na wysyłanie w imieniu domeny!")
    elif "-all" in rec:
        notes.append("HardFail (-all): poprawna konfiguracja.")

    includes = rec.count("include:")
    if includes > 8:
        notes.append(f"UWAGA: {includes} mechanizmów include — ryzyko przekroczenia limitu 10 lookup-ów DNS (RFC 7208).")

    status = "WARN" if any("NIEBEZPIECZNE" in n or "UWAGA" in n or "SoftFail" in n or "Neutral" in n for n in notes) else "OK"
    return {"status": status, "record": rec, "note": " | ".join(notes) or "Poprawny rekord SPF.", "raw": spf}


def check_dmarc(domain: str) -> dict:
    txts = _resolve(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in txts if t.startswith("v=DMARC1")]
    if not dmarc:
        return {"status": "MISSING", "record": None,
                "note": "Brak rekordu DMARC. Domena podatna na spoofing.", "raw": []}

    rec = dmarc[0]
    notes = []
    policy = "none"
    for part in rec.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part[2:].strip().lower()
    if policy == "none":
        notes.append("Polityka p=none: monitorowanie tylko, brak ochrony. Docelowo ustaw p=quarantine lub p=reject.")
    elif policy == "quarantine":
        notes.append("Polityka p=quarantine: podejrzane maile trafiają do spamu — dobry poziom.")
    elif policy == "reject":
        notes.append("Polityka p=reject: najsilniejsza ochrona — maile niespełniające DMARC są odrzucane.")

    if "rua=" not in rec:
        notes.append("Brak rua= — nie otrzymujesz raportów agregowanych DMARC.")
    if "ruf=" not in rec:
        notes.append("Brak ruf= — brak raportów forensic (opcjonalne, ale przydatne).")

    status_map = {"none": "WARN", "quarantine": "OK", "reject": "OK"}
    status = status_map.get(policy, "WARN")
    return {"status": status, "record": rec, "policy": policy,
            "note": " | ".join(notes) or "Poprawny rekord DMARC.", "raw": dmarc}


def check_dkim(domain: str, selectors: list[str]) -> dict:
    found = []
    for sel in selectors:
        qname = f"{sel}._domainkey.{domain}"
        txts = _resolve(qname, "TXT")
        dkim = [t for t in txts if "v=DKIM1" in t or "k=rsa" in t or "k=ed25519" in t or "p=" in t]
        if dkim:
            found.append({"selector": sel, "record": dkim[0]})

    if not found:
        return {"status": "NOT_FOUND", "records": [],
                "note": f"Nie znaleziono DKIM dla sprawdzanych selektorów: {', '.join(selectors[:8])}... "
                        "Podaj właściwy selektor przez --dkim-selector."}
    notes = []
    for f in found:
        if "p=" in f["record"]:
            p_start = f["record"].find("p=") + 2
            p_val = f["record"][p_start:].split(";")[0].strip()
            if not p_val:
                notes.append(f"Selektor '{f['selector']}': klucz publiczny pusty — DKIM nieaktywny (revoked).")
    status = "WARN" if notes else "OK"
    return {"status": status, "records": found,
            "note": " | ".join(notes) or f"Znaleziono DKIM ({len(found)} selektor/ów).", "raw": []}


def check_mta_sts(domain: str) -> dict:
    txts = _resolve(f"_mta-sts.{domain}", "TXT")
    sts = [t for t in txts if t.startswith("v=STSv1")]
    if not sts:
        return {"status": "MISSING", "record": None,
                "note": "Brak MTA-STS. Opcjonalne, ale zalecane — chroni przed downgrade TLS."}
    return {"status": "OK", "record": sts[0],
            "note": "MTA-STS skonfigurowane.", "raw": sts}


def check_tls_rpt(domain: str) -> dict:
    txts = _resolve(f"_smtp._tls.{domain}", "TXT")
    rpt = [t for t in txts if t.startswith("v=TLSRPTv1")]
    if not rpt:
        return {"status": "MISSING", "record": None,
                "note": "Brak TLS-RPT. Opcjonalne — raporty o problemach z szyfrowaniem SMTP."}
    return {"status": "OK", "record": rpt[0],
            "note": "TLS-RPT skonfigurowane.", "raw": rpt}


def check_bimi(domain: str) -> dict:
    txts = _resolve(f"default._bimi.{domain}", "TXT")
    bimi = [t for t in txts if t.startswith("v=BIMI1")]
    if not bimi:
        return {"status": "MISSING", "record": None,
                "note": "Brak BIMI. Opcjonalne — logo przy wiadomości w skrzynce odbiorcy."}
    return {"status": "OK", "record": bimi[0],
            "note": "BIMI skonfigurowane.", "raw": bimi}


def check_spoofability(spf: dict, dmarc: dict) -> dict:
    """Uproszczona ocena podatności na spoofing (wzorowana na Spoofy)."""
    spf_ok   = spf["status"] == "OK" and spf.get("record") and "-all" in (spf.get("record") or "")
    spf_soft = spf["status"] in ("OK", "WARN") and "~all" in (spf.get("record") or "")
    dmarc_policy = dmarc.get("policy", "none") if dmarc["status"] != "MISSING" else "none"

    if spf["status"] == "MISSING" and dmarc["status"] == "MISSING":
        return {"spoofable": True, "risk": "CRITICAL",
                "note": "Brak SPF i DMARC — domena jest w pełni spoofowalna!"}
    if dmarc_policy == "none" and not spf_ok:
        return {"spoofable": True, "risk": "HIGH",
                "note": "DMARC p=none i słabe SPF — domena prawdopodobnie spoofowalna."}
    if dmarc_policy == "none":
        return {"spoofable": True, "risk": "MEDIUM",
                "note": "DMARC p=none — monitorowanie bez ochrony. Możliwy spoofing."}
    if dmarc_policy in ("quarantine", "reject") and (spf_ok or spf_soft):
        return {"spoofable": False, "risk": "LOW",
                "note": "Dobra ochrona przed spoofingiem."}
    return {"spoofable": True, "risk": "MEDIUM",
            "note": "Konfiguracja częściowa — możliwy spoofing w niektórych scenariuszach."}


def audit_domain(domain: str, dkim_selectors: list[str]) -> dict:
    domain = domain.strip().lower().rstrip(".")
    mx    = check_mx(domain)
    spf   = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim  = check_dkim(domain, dkim_selectors)
    mta   = check_mta_sts(domain)
    tlsrpt= check_tls_rpt(domain)
    bimi  = check_bimi(domain)
    spoof = check_spoofability(spf, dmarc)

    # ocena ogólna
    critical_checks = [mx, spf, dmarc]
    statuses = [c["status"] for c in critical_checks]
    if "MISSING" in statuses or spoof["risk"] == "CRITICAL":
        overall = "CRITICAL"
    elif "ERROR" in statuses or spoof["risk"] == "HIGH":
        overall = "HIGH"
    elif "WARN" in statuses or dkim["status"] == "NOT_FOUND" or spoof["risk"] == "MEDIUM":
        overall = "WARN"
    else:
        overall = "OK"

    return {
        "domain": domain,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "overall": overall,
        "spoofability": spoof,
        "checks": {
            "mx":      mx,
            "spf":     spf,
            "dmarc":   dmarc,
            "dkim":    dkim,
            "mta_sts": mta,
            "tls_rpt": tlsrpt,
            "bimi":    bimi,
        }
    }

# ── terminal output ───────────────────────────────────────────────────────────

STATUS_COLOR = {
    "OK":        Fore.GREEN,
    "WARN":      Fore.YELLOW,
    "MISSING":   Fore.RED,
    "ERROR":     Fore.RED,
    "NOT_FOUND": Fore.YELLOW,
    "CRITICAL":  Fore.RED,
    "HIGH":      Fore.RED,
    "MEDIUM":    Fore.YELLOW,
    "LOW":       Fore.GREEN,
}

STATUS_ICON = {
    "OK":        "✔",
    "WARN":      "⚠",
    "MISSING":   "✘",
    "ERROR":     "✘",
    "NOT_FOUND": "?",
    "CRITICAL":  "‼",
    "HIGH":      "!",
    "MEDIUM":    "~",
    "LOW":       "✔",
}

def _color(text: str, status: str) -> str:
    c = STATUS_COLOR.get(status, "")
    return f"{c}{text}{Style.RESET_ALL}"

def print_result(result: dict):
    domain   = result["domain"]
    overall  = result["overall"]
    spoof    = result["spoofability"]
    checks   = result["checks"]

    sep = "─" * 68
    print(f"\n{Style.BRIGHT}{Fore.CYAN}{sep}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}DOMENA:{Style.RESET_ALL} {Fore.WHITE}{domain}{Style.RESET_ALL}   "
          f"[{_color(overall, overall)}]   "
          f"Spoofing: {_color(spoof['risk'], spoof['risk'])}")
    print(f"{Style.BRIGHT}{Fore.CYAN}{sep}{Style.RESET_ALL}")

    rows = [
        ("MX",       checks["mx"]),
        ("SPF",      checks["spf"]),
        ("DMARC",    checks["dmarc"]),
        ("DKIM",     checks["dkim"]),
        ("MTA-STS",  checks["mta_sts"]),
        ("TLS-RPT",  checks["tls_rpt"]),
        ("BIMI",     checks["bimi"]),
    ]

    for name, chk in rows:
        st   = chk["status"]
        icon = STATUS_ICON.get(st, "?")
        col  = STATUS_COLOR.get(st, "")
        note = chk.get("note", "")
        print(f"  {col}{icon}{Style.RESET_ALL}  {Style.BRIGHT}{name:<9}{Style.RESET_ALL}  "
              f"{col}{st:<10}{Style.RESET_ALL}  {Style.DIM}{note}{Style.RESET_ALL}")

    # szczegóły MX
    if checks["mx"]["records"]:
        for r in checks["mx"]["records"]:
            print(f"             {Fore.WHITE}↳ [{r['priority']:>3}] {r['host']}{Style.RESET_ALL}")

    # szczegóły DKIM
    if checks["dkim"]["records"]:
        for r in checks["dkim"]["records"]:
            print(f"             {Fore.WHITE}↳ selector: {r['selector']}{Style.RESET_ALL}")

    print(f"  {Fore.MAGENTA}⚑ Spoofing: {spoof['note']}{Style.RESET_ALL}")
    print()


def print_summary(results: list[dict]):
    total = len(results)
    crit  = sum(1 for r in results if r["overall"] == "CRITICAL")
    high  = sum(1 for r in results if r["overall"] == "HIGH")
    warn  = sum(1 for r in results if r["overall"] == "WARN")
    ok    = sum(1 for r in results if r["overall"] == "OK")

    sep = "═" * 68
    print(f"\n{Style.BRIGHT}{Fore.CYAN}{sep}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}PODSUMOWANIE — {total} domen(y){Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{Fore.CYAN}{sep}{Style.RESET_ALL}")
    print(f"  {_color('CRITICAL', 'CRITICAL')}  {crit:>3} domen")
    print(f"  {_color('HIGH',     'HIGH')}      {high:>3} domen")
    print(f"  {_color('WARN',     'WARN')}      {warn:>3} domen")
    print(f"  {_color('OK',       'OK')}        {ok:>3} domen")
    print(f"{Style.BRIGHT}{Fore.CYAN}{sep}{Style.RESET_ALL}\n")

# ── HTML output ───────────────────────────────────────────────────────────────

HTML_STATUS_CLASS = {
    "OK": "ok", "WARN": "warn", "MISSING": "miss",
    "ERROR": "miss", "NOT_FOUND": "warn",
    "CRITICAL": "miss", "HIGH": "miss", "MEDIUM": "warn", "LOW": "ok",
}

def generate_html(results: list[dict], output_path: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows_html = ""

    for r in results:
        c = r["checks"]
        ov = r["overall"]
        sp = r["spoofability"]

        def badge(st):
            cls = HTML_STATUS_CLASS.get(st, "warn")
            icon = STATUS_ICON.get(st, "?")
            return f'<span class="badge {cls}">{icon} {st}</span>'

        def cell(chk):
            st = chk["status"]
            note = chk.get("note", "")
            return f'<td>{badge(st)}<div class="note">{note}</div></td>'

        dkim_sel = ", ".join(d["selector"] for d in c["dkim"].get("records", [])) or "—"
        mx_hosts = "<br>".join(
            f"[{x['priority']}] {x['host']}" for x in c["mx"].get("records", [])
        ) or "—"

        rows_html += f"""
        <tr>
          <td class="domain"><strong>{r['domain']}</strong><br>
            <small>{r['timestamp']}</small></td>
          <td>{badge(ov)}</td>
          <td>{badge(sp['risk'])}<div class="note">{sp['note']}</div></td>
          <td><div class="note">{mx_hosts}</div></td>
          {cell(c['spf'])}
          {cell(c['dmarc'])}
          <td>{badge(c['dkim']['status'])}<div class="note">Selektory: {dkim_sel}</div></td>
          {cell(c['mta_sts'])}
          {cell(c['tls_rpt'])}
          {cell(c['bimi'])}
        </tr>"""

    total = len(results)
    crit  = sum(1 for r in results if r["overall"] == "CRITICAL")
    high  = sum(1 for r in results if r["overall"] == "HIGH")
    warn  = sum(1 for r in results if r["overall"] == "WARN")
    ok    = sum(1 for r in results if r["overall"] == "OK")

    html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Email DNS Audit — {ts}</title>
<style>
  :root {{
    --bg: #0f1117; --bg2: #1a1d27; --bg3: #22263a;
    --ok: #22c55e; --warn: #f59e0b; --miss: #ef4444;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 1.6rem; margin-bottom: .3rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; }}
  .stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: var(--bg2); border-radius: 8px; padding: .7rem 1.2rem; text-align: center; min-width: 100px; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; }}
  .stat .lbl {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; }}
  .stat.c {{ border-top: 3px solid var(--miss); }} .stat.c .num {{ color: var(--miss); }}
  .stat.h {{ border-top: 3px solid #f97316; }} .stat.h .num {{ color: #f97316; }}
  .stat.w {{ border-top: 3px solid var(--warn); }} .stat.w .num {{ color: var(--warn); }}
  .stat.o {{ border-top: 3px solid var(--ok); }}  .stat.o .num {{ color: var(--ok); }}
  .wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
  th {{ background: var(--bg3); color: var(--accent); padding: .6rem .8rem;
        text-align: left; border-bottom: 2px solid #2d3452; white-space: nowrap; }}
  td {{ padding: .55rem .8rem; border-bottom: 1px solid #1e2235; vertical-align: top; }}
  tr:hover td {{ background: var(--bg2); }}
  .domain {{ min-width: 180px; }}
  .domain strong {{ color: var(--accent); }}
  .domain small {{ color: var(--muted); font-size: .75rem; }}
  .note {{ color: var(--muted); font-size: .75rem; margin-top: .25rem; line-height: 1.4; }}
  .badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 4px;
            font-size: .75rem; font-weight: 600; letter-spacing: .03em; }}
  .badge.ok   {{ background: rgba(34,197,94,.15);  color: var(--ok); }}
  .badge.warn {{ background: rgba(245,158,11,.15); color: var(--warn); }}
  .badge.miss {{ background: rgba(239,68,68,.15);  color: var(--miss); }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: .78rem; }}
</style>
</head>
<body>
<h1>📧 Email DNS Security Audit</h1>
<p class="meta">Wygenerowano: {ts} &nbsp;|&nbsp; mail_dns_audit.py v{VERSION} &nbsp;|&nbsp; Sprawdzono domen: {total}</p>

<div class="stats">
  <div class="stat c"><div class="num">{crit}</div><div class="lbl">Critical</div></div>
  <div class="stat h"><div class="num">{high}</div><div class="lbl">High</div></div>
  <div class="stat w"><div class="num">{warn}</div><div class="lbl">Warn</div></div>
  <div class="stat o"><div class="num">{ok}</div><div class="lbl">OK</div></div>
</div>

<div class="wrap">
<table>
<thead>
<tr>
  <th>Domena</th><th>Ocena</th><th>Spoofing</th><th>MX</th>
  <th>SPF</th><th>DMARC</th><th>DKIM</th>
  <th>MTA-STS</th><th>TLS-RPT</th><th>BIMI</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>

<footer>
  Legenda: <span class="badge ok">✔ OK</span>
  <span class="badge warn">⚠ WARN/MEDIUM</span>
  <span class="badge miss">✘ MISSING/CRITICAL</span>
  &nbsp;|&nbsp; Narzędzie: mail_dns_audit.py — open source, self-hosted
</footer>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"  {Fore.GREEN}✔{Style.RESET_ALL}  HTML zapisany: {output_path}")

# ── CSV output ────────────────────────────────────────────────────────────────

def generate_csv(results: list[dict], output_path: str):
    fieldnames = [
        "domain", "timestamp", "overall", "spoofing_risk", "spoofing_note",
        "mx_status", "mx_hosts",
        "spf_status", "spf_record", "spf_note",
        "dmarc_status", "dmarc_policy", "dmarc_record", "dmarc_note",
        "dkim_status", "dkim_selectors", "dkim_note",
        "mta_sts_status", "mta_sts_note",
        "tls_rpt_status", "tls_rpt_note",
        "bimi_status", "bimi_note",
    ]
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in results:
            c = r["checks"]
            mx_hosts = "; ".join(f"[{x['priority']}] {x['host']}" for x in c["mx"].get("records", []))
            dkim_sel  = ", ".join(d["selector"] for d in c["dkim"].get("records", []))
            w.writerow({
                "domain":         r["domain"],
                "timestamp":      r["timestamp"],
                "overall":        r["overall"],
                "spoofing_risk":  r["spoofability"]["risk"],
                "spoofing_note":  r["spoofability"]["note"],
                "mx_status":      c["mx"]["status"],
                "mx_hosts":       mx_hosts,
                "spf_status":     c["spf"]["status"],
                "spf_record":     c["spf"].get("record") or "",
                "spf_note":       c["spf"].get("note") or "",
                "dmarc_status":   c["dmarc"]["status"],
                "dmarc_policy":   c["dmarc"].get("policy") or "",
                "dmarc_record":   c["dmarc"].get("record") or "",
                "dmarc_note":     c["dmarc"].get("note") or "",
                "dkim_status":    c["dkim"]["status"],
                "dkim_selectors": dkim_sel,
                "dkim_note":      c["dkim"].get("note") or "",
                "mta_sts_status": c["mta_sts"]["status"],
                "mta_sts_note":   c["mta_sts"].get("note") or "",
                "tls_rpt_status": c["tls_rpt"]["status"],
                "tls_rpt_note":   c["tls_rpt"].get("note") or "",
                "bimi_status":    c["bimi"]["status"],
                "bimi_note":      c["bimi"].get("note") or "",
            })
    print(f"  {Fore.GREEN}✔{Style.RESET_ALL}  CSV zapisany:  {output_path}")


# ── JSON output ───────────────────────────────────────────────────────────────

def generate_json(results: list[dict], output_path: str):
    # usuń surowe rekordy (raw) z JSON — są zbędne
    clean = json.loads(json.dumps(results))
    for r in clean:
        for chk in r.get("checks", {}).values():
            chk.pop("raw", None)
    Path(output_path).write_text(
        json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"  {Fore.GREEN}✔{Style.RESET_ALL}  JSON zapisany: {output_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description=f"mail_dns_audit.py v{VERSION} — Email DNS Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Przykłady:
  python mail_dns_audit.py -d example.com
  python mail_dns_audit.py -d example.com other.pl -o raporty/
  python mail_dns_audit.py -f domains.txt --html raport.html --csv raport.csv
  python mail_dns_audit.py -f domains.txt --dkim-selector google --dkim-selector mail
        """
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("-d", "--domain",  nargs="+", metavar="DOMENA",
                     help="Jedna lub więcej domen do sprawdzenia")
    src.add_argument("-f", "--file",    metavar="PLIK",
                     help="Plik tekstowy z domenami (jedna na linię)")

    p.add_argument("--dkim-selector", dest="dkim_selectors", action="append",
                   metavar="SELEKTOR",
                   help="Selektor DKIM do sprawdzenia (można podać wielokrotnie). "
                        "Domyślnie używa wbudowanej listy ~20 popularnych selektorów.")

    out = p.add_argument_group("Wyjście (opcjonalne — domyślnie tylko terminal)")
    out.add_argument("--html",   metavar="PLIK",  help="Zapisz raport HTML")
    out.add_argument("--csv",    metavar="PLIK",  help="Zapisz raport CSV")
    out.add_argument("--json",   metavar="PLIK",  help="Zapisz raport JSON")
    out.add_argument("-o",       metavar="KATALOG",
                     help="Katalog wyjściowy — automatycznie tworzy "
                          "raport_{data}.html/.csv/.json")
    out.add_argument("--no-color", action="store_true",
                     help="Wyłącz kolory w terminalu")
    return p.parse_args()


def main():
    args = parse_args()

    if args.no_color:
        global HAS_COLOR
        HAS_COLOR = False

    # zbierz domeny
    domains: list[str] = []
    if args.domain:
        domains = [d.strip() for d in args.domain if d.strip()]
    elif args.file:
        try:
            lines = Path(args.file).read_text(encoding="utf-8").splitlines()
            domains = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] Plik nie istnieje: {args.file}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        print(f"{Fore.RED}[ERROR] Podaj domeny przez -d lub plik przez -f.{Style.RESET_ALL}")
        print("Użyj  python mail_dns_audit.py --help  aby zobaczyć pomoc.")
        sys.exit(1)

    if not domains:
        print(f"{Fore.RED}[ERROR] Brak domen do sprawdzenia.{Style.RESET_ALL}")
        sys.exit(1)

    selectors = args.dkim_selectors if args.dkim_selectors else DEFAULT_DKIM_SELECTORS

    # nagłówek
    print(f"\n{Style.BRIGHT}{Fore.CYAN}{'═'*68}")
    print(f"  mail_dns_audit.py v{VERSION}  —  Email DNS Security Auditor")
    print(f"{'═'*68}{Style.RESET_ALL}")
    print(f"  Domeny do sprawdzenia : {len(domains)}")
    print(f"  Selektory DKIM        : {', '.join(selectors[:6])}{'...' if len(selectors)>6 else ''}")
    print(f"  Czas startu           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # audit
    results = []
    for i, domain in enumerate(domains, 1):
        print(f"\n  [{i}/{len(domains)}] Sprawdzam: {Fore.WHITE}{domain}{Style.RESET_ALL} ...", end="", flush=True)
        result = audit_domain(domain, selectors)
        results.append(result)
        ov = result["overall"]
        col = STATUS_COLOR.get(ov, "")
        print(f" {col}{STATUS_ICON.get(ov,'?')} {ov}{Style.RESET_ALL}")
        print_result(result)

    print_summary(results)

    # zapisy
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.o:
        outdir = Path(args.o)
        outdir.mkdir(parents=True, exist_ok=True)
        generate_html(results, str(outdir / f"raport_{ts_file}.html"))
        generate_csv (results, str(outdir / f"raport_{ts_file}.csv"))
        generate_json(results, str(outdir / f"raport_{ts_file}.json"))
    else:
        if args.html:
            generate_html(results, args.html)
        if args.csv:
            generate_csv(results,  args.csv)
        if args.json:
            generate_json(results, args.json)

    print()


if __name__ == "__main__":
    main()
