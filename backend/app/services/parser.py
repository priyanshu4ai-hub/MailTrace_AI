from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
import re
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from fastapi import UploadFile


class InvalidEmailError(ValueError):
    """Raised when uploaded bytes do not resemble an RFC 5322 message."""


class EMLParser:
    """Extracts a compact, display-safe investigation record from an email upload."""

    async def parse_upload(self, file: UploadFile) -> dict[str, Any]:
        raw_email = await file.read()
        message = BytesParser(policy=policy.default).parsebytes(raw_email)
        if not any(message.get(header) for header in ("From", "To", "Subject", "Date", "Message-ID")):
            raise InvalidEmailError("The file does not contain recognizable email headers.")

        urls, link_mismatches = self._extract_html_link_data(message)
        return {
            "from": str(message.get("From", "")),
            "to": str(message.get("To", "")),
            "reply_to": str(message.get("Reply-To", "")),
            "subject": str(message.get("Subject", "")),
            "date": str(message.get("Date", "")),
            "message_id": str(message.get("Message-ID", "")),
            "body": self._extract_body(message),
            "urls": urls,
            "link_mismatches": link_mismatches,
            "received_headers": [str(header) for header in message.get_all("Received", [])],
            "authentication_results": str(message.get("Authentication-Results", "")),
        }

    def _extract_body(self, message: Message) -> str:
        plain_parts: list[Message] = []
        html_parts: list[Message] = []

        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()
            if content_type == "text/plain":
                plain_parts.append(part)
            elif content_type == "text/html":
                html_parts.append(part)

        if plain_parts:
            return "\n".join(self._decode_part(part) for part in plain_parts).strip()

        if html_parts:
            html = "\n".join(self._decode_part(part) for part in html_parts)
            return BeautifulSoup(html, "html.parser").get_text(" ", strip=True)

        return ""

    def _extract_html_link_data(self, message: Message) -> tuple[list[str], list[str]]:
        """Keep href targets and detect visible URLs that point somewhere else."""

        links: list[str] = []
        mismatches: list[str] = []
        seen: set[str] = set()
        for part in message.walk():
            if part.get_content_type() != "text/html" or part.get_content_disposition() == "attachment":
                continue
            soup = BeautifulSoup(self._decode_part(part), "html.parser")
            for anchor in soup.find_all("a", href=True):
                href = str(anchor.get("href") or "").strip()
                if href and href not in seen:
                    seen.add(href)
                    links.append(href)
                visible_host = self._visible_link_host(anchor.get_text(" ", strip=True))
                target_host = self._url_host(href)
                if visible_host and target_host and self._registrable_domain(visible_host) != self._registrable_domain(target_host):
                    mismatches.append(f"{visible_host} -> {target_host}")
        return links, list(dict.fromkeys(mismatches))

    @staticmethod
    def _visible_link_host(text: str) -> str:
        match = re.search(r"(?i)\b(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,63})\b", text)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _url_host(value: str) -> str:
        try:
            candidate = value if "://" in value else f"https://{value}"
            return (urlsplit(candidate).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""

    @staticmethod
    def _registrable_domain(host: str) -> str:
        labels = [label for label in host.split(".") if label]
        return ".".join(labels[-2:]) if len(labels) >= 2 else host

    @staticmethod
    def _decode_part(part: Message) -> str:
        payload = part.get_payload(decode=True)
        if payload is None:
            content = part.get_content()
            return content if isinstance(content, str) else ""

        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")
