from __future__ import annotations

import asyncio
import ipaddress
import os
import re
from typing import Any

import httpx


class GeoTrackerService:
    """Enriches public SMTP relay IPs with cached ip-api geolocation data."""

    _cache: dict[str, dict[str, str]] = {}
    _IP_PATTERN = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")

    async def track_hops(self, received_headers: list[str]) -> list[dict[str, str]]:
        if not self._is_enabled():
            return []
        ips = self._extract_public_ips(received_headers)
        if not ips:
            return []

        timeout = httpx.Timeout(5.0, connect=2.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            hops = await asyncio.gather(*(self._lookup_ip(client, ip) for ip in ips))
            return [hop for hop in hops if hop is not None]

    def _extract_public_ips(self, received_headers: list[str]) -> list[str]:
        discovered: list[str] = []
        seen: set[str] = set()

        for header in received_headers:
            for candidate in self._IP_PATTERN.findall(header):
                try:
                    is_public = ipaddress.IPv4Address(candidate).is_global
                except ipaddress.AddressValueError:
                    is_public = False

                if is_public and candidate not in seen:
                    seen.add(candidate)
                    discovered.append(candidate)

        return discovered

    async def _lookup_ip(self, client: httpx.AsyncClient, ip: str) -> dict[str, str] | None:
        cached = self._cache.get(ip)
        if cached is not None:
            return cached.copy()

        try:
            response = await client.get(f"http://ip-api.com/json/{ip}")
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            if data.get("status") != "success":
                return None

            hop = {
                "ip": ip,
                "country": str(data.get("country") or "Unknown"),
                "city": str(data.get("city") or "Unknown"),
                "isp": str(data.get("isp") or "Unknown"),
                "asn": str(data.get("as") or "Unknown"),
            }
            self._cache[ip] = hop
            return hop.copy()
        except (httpx.HTTPError, ValueError, Exception):
            return None

    @staticmethod
    def _is_enabled() -> bool:
        """External IP enrichment can disclose message metadata, so require opt-in."""

        return os.getenv("MAILTRACE_ENABLE_GEO_OSINT", "false").lower() in {"1", "true", "yes"}
