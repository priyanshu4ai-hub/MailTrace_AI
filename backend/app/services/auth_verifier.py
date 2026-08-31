from __future__ import annotations

import re


class AuthVerifier:
    """Reads SPF, DKIM, and DMARC outcomes from Authentication-Results."""

    _RESULT_PATTERN = r"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b"

    def verify(self, authentication_results: str) -> dict[str, str]:
        return {
            "spf": self._extract_status(authentication_results, "spf"),
            "dkim": self._extract_status(authentication_results, "dkim"),
            "dmarc": self._extract_status(authentication_results, "dmarc"),
        }

    def _extract_status(self, header_value: str, mechanism: str) -> str:
        pattern = self._RESULT_PATTERN.format(mechanism=re.escape(mechanism))
        match = re.search(pattern, header_value or "", flags=re.IGNORECASE)
        return match.group(1).lower() if match else "none"
