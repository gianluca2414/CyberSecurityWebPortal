# CyberSec Portal

OnPremise portal to organize the most used cybersecurity tools in a single solution.

## What is

Web portal with:

- **Bulk AbuseIPDB**: you can paste a list of IPs and you obtain abuseIPDB score and result for all of them in a singe time
- **IR Investigation**: IP/domain OSINT intelligence and information retrieval to gather a first context and important information about a host or a server. With usage of AbuseIPDB, Shodan, AlienVault OTX, VirusTotal and WHOIS. All the information are grouped and displayed in a single page.
- **Tool list**: URL-redirect to most famous cybersecurity tools for extra information and support
- **Simple Deploy**: Adjust the deploy script with your username and machine name to deploy to a remote host; for docker, simple dockefile to bring up the project: `docker compose up -d`.
Use an .env file or set up variables to commuicate with external systems

## API Calls variable 
All tool do not need to pay to use them. Just register on the relative websites and get your personal API key.
Once you have the API key, you either use a .env file or you set env variable.

ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
SHODAN_API_KEY
ALIENVAULT_OTX_API_KEY
URLSCAN_API_KEY


## Infrastructure
You can deploy the tool wherever you want, just need Docker. I personally use a LXC container in a Proxmox environment. 
Low resource demanding (about 1 core and 500MiB RAM are enough on a LXC container)
No storage needed (for the moment).


## Code Structure

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

## Fast setup

1. Clone and copy the folder on your machine
2. Change `env.example` in `.env`.
3. Set up API keys
4. Start:

```bash
docker compose up --build -d
```

The web page can be accessed on:

```text
http://IP-DELLA-VM:8000
or 
http://localhost:8000
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

## Hardening suggestion

If Exposed, you should not directly expose this service.
Remember always to isolate your environment (container / VM / sandbox) AND isolate your network from the public internet (use a reverse proxy, use a firewall)

Some suggestions: 
- reverse proxy;
- HTTPS;
- fail2ban / rate limiting;

## How to add new modules

### Example: URLScan

1. create `app/services/urlscan.py`;
2. add a route in `app/main.py`;
3. create `templates/urlscan.html`;
4. add entry to catalogo;
5. create a new API key and set it up in .env