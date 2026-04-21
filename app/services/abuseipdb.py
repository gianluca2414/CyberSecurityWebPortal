from __future__ import annotations

import ipaddress
from typing import Any
import httpx


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBError(Exception):
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


async def check_ips(ips: list[str], api_key: str) -> dict[str, Any]:
    if not api_key:
        raise AbuseIPDBError("ABUSEIPDB_API_KEY non configurata.")

    cleaned = []
    invalid = []
    for raw in ips:
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            cleaned.append(candidate)
        except ValueError:
            invalid.append(candidate)

    if not cleaned:
        raise AbuseIPDBError("Non hai inserito IP validi.")

    results: list[dict[str, Any]] = []
    headers = {"Accept": "application/json", "Key": api_key}

    async with httpx.AsyncClient(timeout=20) as client:
        for ip in cleaned:
            response = await client.get(
                ABUSEIPDB_URL,
                headers=headers,
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if response.status_code != 200:
                raise AbuseIPDBError(
                    f"Errore AbuseIPDB per {ip}: HTTP {response.status_code} - {response.text[:180]}"
                )
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            results.append(
                {
                    "ip": data.get("ipAddress", ip),
                    "abuse_score": score,
                    "score_color": get_score_color(score),
                    "country_code": data.get("countryCode") or "N/D",
                    "country_name": data.get("countryName") or "N/D",
                    "isp": data.get("isp") or "N/D",
                    "domain": data.get("domain") or "N/D",
                    "hostname": ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "N/D",
                    "tor": data.get("isTor", False),
                    "report_count": data.get("totalReports", 0),
                    "last_report": data.get("lastReportedAt") or "N/D",
                }
            )

    results.sort(key=lambda row: int(row["abuse_score"]), reverse=True)
    return {
        "submitted": cleaned,
        "invalid": invalid,
        "results": results,
    }