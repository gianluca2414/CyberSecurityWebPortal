from urllib.parse import quote_plus

TOOL_CATALOG = [
    {
        "category": "IP intelligence",
        "items": [
            {
                "name": "AbuseIPDB",
                "description": "Reputation score, reports, ISP, domain e hostnames.",
                "base_url": "https://www.abuseipdb.com/",
                "query_template": "https://www.abuseipdb.com/check/{query}",
            },
            {
                "name": "Shodan",
                "description": "Host lookup, porte aperte, org, ASN, fingerprint.",
                "base_url": "https://www.shodan.io/",
                "query_template": "https://www.shodan.io/host/{query}",
            },
            {
                "name": "IPinfo",
                "description": "Geolocalizzazione, ASN e dati di rete.",
                "base_url": "https://ipinfo.io/",
                "query_template": "https://ipinfo.io/{query}",
            },
            {
                "name": "VirusTotal",
                "description": "Ricerca globale IOC e reputation.",
                "base_url": "https://www.virustotal.com/",
                "query_template": "https://www.virustotal.com/gui/search/{query}",
            },
        ],
    },
    {
        "category": "URL intelligence",
        "items": [
            {
                "name": "urlscan.io",
                "description": "Scansioni, screenshot, redirect chain, requests e tecnologie.",
                "base_url": "https://urlscan.io/",
                "query_template": "https://urlscan.io/search/#domain:{query}",
            },
            {
                "name": "VirusTotal",
                "description": "Controllo URL e indicatori correlati.",
                "base_url": "https://www.virustotal.com/",
                "query_template": "https://www.virustotal.com/gui/search/{query}",
            },
            {
                "name": "WhereGoes",
                "description": "Follow dei redirect e della catena di navigazione.",
                "base_url": "https://wheregoes.com/",
                "query_template": None,
            },
        ],
    },
    {
        "category": "Domain intelligence",
        "items": [
            {
                "name": "WHOIS",
                "description": "Registrar, date, contatti e ownership pubblica.",
                "base_url": "https://who.is/",
                "query_template": "https://who.is/whois/{query}",
            },
            {
                "name": "AlienVault OTX",
                "description": "Pulses, tags, relazioni e minacce note.",
                "base_url": "https://otx.alienvault.com/",
                "query_template": "https://otx.alienvault.com/browse/global/pulses?q={query}",
            },
            {
                "name": "DNSChecker",
                "description": "DNS propagation e record lookup veloci.",
                "base_url": "https://dnschecker.org/",
                "query_template": None,
            },
        ],
    },
]


def build_catalog_links(query: str | None = None):
    normalized = (query or "").strip()
    result = []
    for category in TOOL_CATALOG:
        category_copy = {"category": category["category"], "items": []}
        for item in category["items"]:
            rendered = dict(item)
            if normalized and item.get("query_template"):
                rendered["href"] = item["query_template"].format(query=quote_plus(normalized))
            else:
                rendered["href"] = item["base_url"]
            category_copy["items"].append(rendered)
        result.append(category_copy)
    return result
