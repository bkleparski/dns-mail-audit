# mail_dns_audit.py — Email DNS Security Auditor

Skrypt sprawdza konfigurację DNS związaną z pocztą dla jednej lub wielu domen.
Generuje raporty w terminalu (kolorowe), HTML, CSV i JSON.

## Co sprawdza

| Rekord   | Co jest weryfikowane                                          |
|----------|---------------------------------------------------------------|
| MX       | Obecność i priorytety serwerów pocztowych                    |
| SPF      | Obecność, polityka (-all/~all/+all), limit 10 lookupów       |
| DMARC    | Polityka (none/quarantine/reject), rua=, ruf=                |
| DKIM     | Automatyczne wyszukiwanie ~20 popularnych selektorów         |
| MTA-STS  | Ochrona przed downgrade TLS                                  |
| TLS-RPT  | Raportowanie problemów z szyfrowaniem SMTP                   |
| BIMI     | Logo przy wiadomościach                                       |
| Spoofing | Ocena podatności (CRITICAL / HIGH / MEDIUM / LOW)            |

---

## Instalacja

### Wymagania
- Python 3.10 lub nowszy
- pip

### macOS (Apple Silicon M1/M2/M3)

```bash
# Sprawdź wersję Pythona
python3 --version

# Zainstaluj zależności
pip3 install dnspython colorama

# Uruchom
python3 mail_dns_audit.py -d example.com
```

### Windows 11 (x64) — VS Code Terminal (PowerShell lub CMD)

```powershell
# Sprawdź wersję Pythona
python --version

# Zainstaluj zależności
pip install dnspython colorama

# Uruchom
python mail_dns_audit.py -d example.com
```

> **Tip VS Code:** Otwórz folder ze skryptem przez `File → Open Folder`,
> a terminal przez `` Ctrl+` `` (backtick).

---

## Użycie

### Sprawdź jedną domenę (terminal)
```bash
python mail_dns_audit.py -d example.com
```

### Sprawdź kilka domen naraz
```bash
python mail_dns_audit.py -d example.com firma.pl sklep.eu
```

### Sprawdź domeny z pliku
```bash
python mail_dns_audit.py -f domains.txt
```

Plik `domains.txt` — jedna domena na linię, linie z `#` są ignorowane:
```
# Klient A
klientA.pl
klientA.com

# Klient B
klientB.pl
```

### Generuj wszystkie raporty do folderu
```bash
python mail_dns_audit.py -f domains.txt -o ./raporty
```
Tworzy automatycznie: `raporty/raport_20250314_143022.html`, `.csv`, `.json`

### Generuj konkretne pliki
```bash
python mail_dns_audit.py -f domains.txt --html raport.html --csv raport.csv --json raport.json
```

### Podaj własny selektor DKIM
```bash
# Jeden selektor
python mail_dns_audit.py -d firma.pl --dkim-selector google

# Kilka selektorów
python mail_dns_audit.py -d firma.pl --dkim-selector selector1 --dkim-selector selector2
```

### Bez kolorów (np. do logów)
```bash
python mail_dns_audit.py -f domains.txt --no-color
```

---

## Przykład wyjścia terminala

```
════════════════════════════════════════════════════════════════════
  mail_dns_audit.py v1.2.0  —  Email DNS Security Auditor
════════════════════════════════════════════════════════════════════

  ────────────────────────────────────────────────────────────────
  DOMENA: google.com   [OK]   Spoofing: LOW
  ────────────────────────────────────────────────────────────────
  ✔  MX        OK          ...
  ✔  SPF       OK          HardFail (-all): poprawna konfiguracja.
  ✔  DMARC     OK          Polityka p=reject ...
  ✔  DKIM      OK          Znaleziono DKIM (1 selektor/ów).
  ⚠  MTA-STS   MISSING     Brak MTA-STS. Opcjonalne ...
  ...
```

---

## Opis poziomów ryzyka

| Poziom   | Znaczenie                                              |
|----------|--------------------------------------------------------|
| CRITICAL | Brak SPF i DMARC — domena w pełni spoofowalna          |
| HIGH     | DMARC p=none + słabe SPF                               |
| MEDIUM   | DMARC p=none lub częściowa konfiguracja                |
| LOW      | Dobra ochrona (quarantine/reject + SPF)                |
| OK       | Wszystkie krytyczne rekordy poprawnie skonfigurowane   |
| WARN     | Drobne problemy (SoftFail, brak rua=, itp.)            |
| MISSING  | Brak rekordu                                           |

---

## Wymagane zależności (requirements.txt)

```
dnspython>=2.4.0
colorama>=0.4.6
```

Instalacja jednym poleceniem:
```bash
pip install -r requirements.txt
```

---

## Wbudowane selektory DKIM

Skrypt automatycznie sprawdza ~20 popularnych selektorów:
`default`, `google`, `mail`, `selector1`, `selector2`, `k1`, `dkim`,
`email`, `key1`, `s1`, `s2`, `mx`, `smtp`, `protonmail`, `mailjet`,
`sendgrid`, `amazonses`, ...

Jeśli Twój klient używa innego selektora — podaj go przez `--dkim-selector`.

---

## Struktura pliku JSON

```json
[
  {
    "domain": "example.com",
    "timestamp": "2025-03-14T14:30:22",
    "overall": "WARN",
    "spoofability": {
      "spoofable": true,
      "risk": "MEDIUM",
      "note": "DMARC p=none ..."
    },
    "checks": {
      "mx":      { "status": "OK",      "records": [...], "note": "..." },
      "spf":     { "status": "OK",      "record":  "...", "note": "..." },
      "dmarc":   { "status": "WARN",    "record":  "...", "policy": "none", "note": "..." },
      "dkim":    { "status": "OK",      "records": [...], "note": "..." },
      "mta_sts": { "status": "MISSING", "record":  null,  "note": "..." },
      "tls_rpt": { "status": "MISSING", "record":  null,  "note": "..." },
      "bimi":    { "status": "MISSING", "record":  null,  "note": "..." }
    }
  }
]
```
