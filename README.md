# CyberSec Portal

Portale self-hosted per riunire i tuoi script di cyber security in una GUI web unica.

## Cosa fa

Questa base progetto converte i tuoi script locali in un piccolo portale web con:

- **Bulk AbuseIPDB**: incolli una lista di IP e ottieni risultati tabellari.
- **IR Investigation**: investigazione singola IP/dominio con AbuseIPDB, Shodan, AlienVault OTX, VirusTotal e WHOIS.
- **Catalogo tool**: lista di tool categorizzati con link rapidi per IP, URL e domini.
- **Deploy semplice**: `docker compose up -d`.

## Perché ti consiglio VM invece di LXC

Su Proxmox puoi farlo in entrambi i modi, ma per **Docker** e manutenzione semplice io ti consiglio una **VM Debian/Ubuntu**:

- meno attriti con nesting, AppArmor e privilegi;
- troubleshooting più facile;
- isolamento migliore;
- comportamento più prevedibile quando aggiungerai altri container o reverse proxy.

### Se vuoi comunque usare un LXC

Si può fare, ma è più delicato. In particolare Docker in LXC richiede configurazioni aggiuntive come **nesting** e, per container unprivileged, anche **keyctl** nelle opzioni del container Proxmox. Inoltre Proxmox segnala che il nested containerization dentro LXC ha avuto issue note, quindi non è la strada più lineare se vuoi una base stabile per il tuo portale. citeturn899587search2turn899587search7turn899587search0

## Struttura

```text
app/
  main.py
  config.py
  services/
    abuseipdb.py
    investigation.py
    catalog.py
  templates/
  static/
Dockerfile
docker-compose.yml
.env.example
```

## Setup rapido

1. Copia il progetto sulla VM.
2. Duplica `.env.example` in `.env`.
3. Inserisci le tue API key.
4. Avvia:

```bash
cp .env.example .env
nano .env
docker compose up -d --build
```

Poi apri:

```text
http://IP-DELLA-VM:8000
```

## Esempio `.env`

```env
APP_TITLE=CyberSec Portal
APP_HOST=0.0.0.0
APP_PORT=8000
APP_DEBUG=false

ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
SHODAN_API_KEY=...
ALIENVAULT_OTX_API_KEY=...
URLSCAN_API_KEY=...
```

## Hardening consigliato

Se lo esponi fuori dalla LAN, non pubblicarlo “nudo” su Internet.

Minimo consigliato:

- reverse proxy davanti;
- HTTPS;
- autenticazione (Authelia, OAuth2 Proxy, basic auth su reverse proxy, oppure VPN/Tailscale);
- fail2ban / rate limiting;
- backup di `.env` e compose;
- logging separato.

## Come aggiungere nuovi moduli

### Esempio: URLScan dedicato

1. crea `app/services/urlscan.py`;
2. aggiungi una route in `app/main.py`;
3. crea `templates/urlscan.html`;
4. aggiungi la voce al catalogo;
5. collega la chiave in `.env`.

## Come mappano i tuoi script originali

- `checkAbuseIP.py` esponeva già una funzione riutilizzabile `call_api(ips)` per una lista IP; qui è stata trasformata in un servizio web lato server. fileciteturn1file0
- `main.py` era una GUI Tkinter per il bulk AbuseIPDB; la stessa logica è stata portata su una pagina web con tabella e score colorato. fileciteturn1file2
- `ir_investigations.py` già univa AbuseIPDB, Shodan, OTX, WHOIS e VirusTotal; nel portale è diventato il modulo “IR Investigation”. fileciteturn1file1

## Nota importante sulle API key

Nel file `ir_investigations.py` che hai caricato ci sono chiavi hardcoded nel sorgente. Nel progetto nuovo le ho spostate in variabili d’ambiente. Ti consiglio di **revocare/ruotare** quelle chiavi e sostituirle con chiavi nuove. fileciteturn1file1
