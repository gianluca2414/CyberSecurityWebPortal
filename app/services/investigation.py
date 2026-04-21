from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

import httpx
from shodan import Shodan


class InvestigationError(Exception):
    pass


def get_score_color(score: int) -> str:
    """Restituisce la classe CSS basata sullo score"""
    if score <= 5:
        return "score-very-low"
    elif score <= 10:
        return "score-low"
    elif score <= 40:
        return "score-mid"
    else:
        return "score-high"


async def investigate_target(target: str, config) -> dict[str, Any]:
    normalized = (target or "").strip()
    if not normalized:
        raise InvestigationError("Inserisci un IP o un dominio.")

    is_ip = _is_ip(normalized)
    resolved_ip = normalized if is_ip else await asyncio.to_thread(_resolve_dns, normalized)

    warnings: list[str] = []
    sections: dict[str, Any] = {}

    abuse = await _get_abuseipdb(resolved_ip, config.abuseipdb_api_key)
    if abuse.get("warning"):
        warnings.append(abuse["warning"])
    elif abuse.get("data"):
        sections["AbuseIPDB"] = abuse["data"]

    shodan = await _get_shodan(resolved_ip, config.shodan_api_key)
    if shodan.get("warning"):
        warnings.append(shodan["warning"])
    elif shodan.get("data"):
        sections["Shodan"] = shodan["data"]

    otx = await _get_otx(normalized, resolved_ip, is_ip, config.alienvault_otx_api_key)
    if otx.get("warning"):
        warnings.append(otx["warning"])
    elif otx.get("data"):
        sections["AlienVault OTX"] = otx["data"]

    vt = await _get_virustotal(normalized, is_ip, config.virustotal_api_key)
    if vt.get("warning"):
        warnings.append(vt["warning"])
    elif vt.get("data"):
        sections["VirusTotal"] = vt["data"]

    whois_data = await asyncio.to_thread(_get_whois, normalized)
    if whois_data.get("warning"):
        warnings.append(whois_data["warning"])
    elif whois_data.get("data"):
        sections["WHOIS"] = whois_data["data"]

    if not sections and not warnings:
        warnings.append("Nessun risultato disponibile per il target inserito.")

    return {
        "target": normalized,
        "resolved_ip": resolved_ip,
        "target_type": "IP" if is_ip else "Domain",
        "sections": sections,
        "warnings": warnings,
    }


def _is_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _resolve_dns(candidate: str) -> str | None:
    try:
        return socket.gethostbyname(candidate)
    except Exception:
        return None


async def _get_abuseipdb(ip: str | None, api_key: str) -> dict[str, Any]:
    if not ip:
        return {"warning": "Impossibile risolvere il dominio in IP per AbuseIPDB."}
    if not api_key:
        return {"warning": "AbuseIPDB non configurato: manca ABUSEIPDB_API_KEY."}

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
    if response.status_code != 200:
        return {"warning": f"AbuseIPDB ha risposto con HTTP {response.status_code}."}

    data = response.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    return {
        "data": {
            "ip": data.get("ipAddress", ip),
            "abuse_confidence_score": score,
            "score_color": get_score_color(score),
            "country_code": data.get("countryCode") or "N/D",
            "country_name": data.get("countryName") or "N/D",
            "usage_type": data.get("usageType") or "N/D",
            "isp": data.get("isp") or "N/D",
            "domain": data.get("domain") or "N/D",
            "is_whitelisted": data.get("isWhitelisted", False),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt") or "N/D",
            "hostnames": data.get("hostnames", []),
        }
    }


async def _get_shodan(ip: str | None, api_key: str) -> dict[str, Any]:
    if not ip:
        return {"warning": "Impossibile interrogare Shodan senza IP risolto."}
    if not api_key:
        return {"warning": "Shodan non configurato: manca SHODAN_API_KEY."}

    def _query() -> dict[str, Any]:
        api = Shodan(api_key)
        data = api.host(ip)
        return {
            "ip": ip,
            "org": data.get("org") or "N/D",
            "asn": data.get("asn") or "N/D",
            "os": data.get("os") or "N/D",
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": data.get("vulns", []),
        }

    try:
        return {"data": await asyncio.to_thread(_query)}
    except Exception as exc:
        return {"warning": f"Shodan non disponibile: {exc}"}


async def _get_otx(target: str, resolved_ip: str | None, is_ip: bool, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"warning": "AlienVault OTX non configurato: manca ALIENVAULT_OTX_API_KEY."}

    value = target if is_ip else target
    indicator_type = "IPv4" if is_ip else "domain"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{value}/general",
            headers={"X-OTX-API-KEY": api_key},
        )
    if response.status_code != 200:
        return {"warning": f"AlienVault OTX ha risposto con HTTP {response.status_code}."}

    data = response.json()
    pulses = data.get("pulse_info", {}).get("pulses", [])
    tags: list[str] = []
    for pulse in pulses:
        for tag in pulse.get("tags", []):
            if tag not in tags:
                tags.append(tag)

    return {
        "data": {
            "indicator": value,
            "indicator_type": indicator_type,
            "resolved_ip": resolved_ip,
            "pulse_count": len(pulses),
            "tags": tags[:20],
        }
    }


async def _get_virustotal(target: str, is_ip: bool, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {"warning": "VirusTotal non configurato: manca VIRUSTOTAL_API_KEY."}

    resource_type = "ip_addresses" if is_ip else "domains"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/{resource_type}/{target}",
            headers={"x-apikey": api_key},
        )
    if response.status_code != 200:
        return {"warning": f"VirusTotal ha risposto con HTTP {response.status_code}."}

    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"data": stats}


def _clean_date(value) -> str:
    if isinstance(value, list) and value:
        value = value[0]
    return value.strftime("%Y-%m-%d") if value else "N/D"


def _get_whois(target: str) -> dict[str, Any]:
    """Recupera informazioni WHOIS per un dominio con dati del registrant"""
    if _is_ip(target):
        return {
            "data": {
                "note": "WHOIS non applicabile per indirizzi IP",
                "status": "Non disponibile per IP"
            }
        }
    
    try:
        import whois
        
        data = whois.whois(target)
        
        if not data or not data.text:
            return {
                "data": {
                    "domain": target,
                    "status": "Nessun dato WHOIS trovato",
                    "note": "Il dominio potrebbe essere protetto da privacy o non esistere"
                }
            }
        
        # Estrai informazioni del registrant
        registrant_name = None
        registrant_organization = None
        registrant_email = None
        registrant_phone = None
        registrant_country = None
        registrant_address = None
        
        # Metodo 1: attributi diretti del registrant
        if hasattr(data, 'registrant'):
            registrant_name = data.registrant
        if hasattr(data, 'registrant_name'):
            registrant_name = data.registrant_name
        if hasattr(data, 'registrant_organization'):
            registrant_organization = data.registrant_organization
        if hasattr(data, 'registrant_email'):
            registrant_email = data.registrant_email
        if hasattr(data, 'registrant_phone'):
            registrant_phone = data.registrant_phone
        if hasattr(data, 'registrant_country'):
            registrant_country = data.registrant_country
        if hasattr(data, 'registrant_address'):
            registrant_address = data.registrant_address
        
        # Metodo 2: da email o contact
        if not registrant_email:
            if hasattr(data, 'emails') and data.emails:
                emails = data.emails
                if isinstance(emails, list) and emails:
                    registrant_email = emails[0] if emails else "N/D"
                else:
                    registrant_email = emails or "N/D"
            else:
                registrant_email = "N/D"
        
        # Metodo 3: da org come organizzazione
        if not registrant_organization and hasattr(data, 'org'):
            registrant_organization = data.org
        
        # Per name_servers
        name_servers = data.name_servers
        if isinstance(name_servers, list):
            name_servers_str = ", ".join(name_servers) if name_servers else "N/D"
        else:
            name_servers_str = name_servers or "N/D"
        
        result_data = {
            "domain_name": data.domain_name if isinstance(data.domain_name, str) else (", ".join(data.domain_name) if data.domain_name else "N/D"),
            "registrar": data.registrar or "N/D",
            "creation_date": _clean_date(data.creation_date),
            "updated_date": _clean_date(data.updated_date),
            "expiration_date": _clean_date(data.expiration_date),
            "name_servers": name_servers_str,
            "status": data.status or "N/D",
            # Registrant contact information
            "registrant_name": registrant_name or "N/D",
            "registrant_organization": registrant_organization or "N/D",
            "registrant_email": registrant_email,
            "registrant_phone": registrant_phone or "N/D",
            "registrant_country": registrant_country or "N/D",
            "registrant_address": registrant_address or "N/D",
        }
        
        return {"data": result_data}
        
    except ImportError:
        return {
            "data": {
                "status": "Modulo python-whois non installato",
                "note": "Installa con: pip install python-whois"
            }
        }
    except Exception as exc:
        error_msg = str(exc)
        
        if "Name or service not known" in error_msg:
            return {
                "data": {
                    "domain": target,
                    "status": "Errore di risoluzione DNS",
                    "note": f"Impossibile trovare il server WHOIS per '{target}'"
                }
            }
        elif "No whois server known" in error_msg:
            return {
                "data": {
                    "domain": target,
                    "status": "TLD non supportato",
                    "note": "La libreria python-whois non ha un server WHOIS configurato per questo dominio"
                }
            }
        else:
            return {
                "data": {
                    "domain": target,
                    "status": "Errore durante la query WHOIS",
                    "error": error_msg[:200]
                }
            }