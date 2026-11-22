"""Web crawler for VAPT discovery phase.

Discovers endpoints, forms, parameters, and attack surface.
"""
from __future__ import annotations

import re
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from http_client import HttpClient, Response
from scope import Scope


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    parameters: list[str]
    forms: list[dict[str, Any]]
    status_code: int
    content_type: str


@dataclass
class CrawlResult:
    endpoints: list[DiscoveredEndpoint]
    technologies: list[str]
    robots_txt: str | None
    sitemap_urls: list[str]
    errors: list[str]


class Crawler:
    """Web application crawler for attack surface discovery."""

    def __init__(
        self,
        client: HttpClient,
        max_depth: int = 3,
        max_pages: int = 100,
        rate_limit_per_second: float = 3.0,
    ) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.rate_limit_per_second = rate_limit_per_second
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()
        self._endpoints: list[DiscoveredEndpoint] = []
        self._technologies: set[str] = set()

    def crawl(self, start_url: str) -> CrawlResult:
        """Crawl the target application starting from start_url."""
        self._queue.append((start_url, 0))
        errors: list[str] = []

        while self._queue and len(self._visited) < self.max_pages:
            url, depth = self._queue.popleft()

            if url in self._visited or depth > self.max_depth:
                continue

            self._visited.add(url)

            try:
                resp = self.client.get(url)
                self._process_response(url, resp)

                if depth < self.max_depth:
                    self._extract_links(url, resp.text)

            except Exception as e:
                errors.append(f"Failed to crawl {url}: {e}")

        return CrawlResult(
            endpoints=self._endpoints,
            technologies=sorted(self._technologies),
            robots_txt=None,
            sitemap_urls=[],
            errors=errors,
        )

    def _process_response(self, url: str, resp: Response) -> None:
        """Process HTTP response to extract endpoints and technologies."""
        # Detect technologies from headers
        self._detect_technologies(resp.headers)

        # Parse HTML for forms and links
        forms = self._extract_forms(resp.text)
        parameters = self._extract_parameters(url)

        endpoint = DiscoveredEndpoint(
            url=url,
            method="GET",
            parameters=parameters,
            forms=forms,
            status_code=resp.status,
            content_type=resp.headers.get("Content-Type", ""),
        )
        self._endpoints.append(endpoint)

        # Also check for POST endpoints from forms
        for form in forms:
            if form.get("method", "").upper() == "POST":
                action = form.get("action", "")
                if action:
                    form_url = urljoin(url, action)
                    post_endpoint = DiscoveredEndpoint(
                        url=form_url,
                        method="POST",
                        parameters=[inp.get("name", "") for inp in form.get("inputs", []) if inp.get("name")],
                        forms=[form],
                        status_code=0,
                        content_type="",
                    )
                    self._endpoints.append(post_endpoint)

    def _detect_technologies(self, headers: dict[str, str]) -> None:
        """Detect technologies from response headers."""
        server = headers.get("Server", "").lower()
        powered_by = headers.get("X-Powered-By", "").lower()
        generator = headers.get("X-Generator", "").lower()

        tech_signatures = {
            "nginx": ["nginx"],
            "apache": ["apache"],
            "iis": ["iis", "microsoft-iis"],
            "express": ["express"],
            "php": ["php"],
            "asp.net": ["asp.net", "aspnet"],
            "django": ["django"],
            "rails": ["rails", "ruby on rails"],
            "spring": ["spring"],
            "tomcat": ["tomcat"],
            "jetty": ["jetty"],
            "cloudflare": ["cloudflare"],
            "aws": ["aws", "amazon"],
        }

        all_headers = f"{server} {powered_by} {generator}".lower()
        for tech, signatures in tech_signatures.items():
            if any(sig in all_headers for sig in signatures):
                self._technologies.add(tech)

    def _extract_forms(self, html: str) -> list[dict[str, Any]]:
        """Extract HTML forms from page content."""
        forms = []
        # Simple regex-based form extraction
        form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
        input_pattern = re.compile(r"<input[^>]*>", re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_inner = form_match.group(1)

            # Extract form attributes
            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)

            action = action_match.group(1) if action_match else ""
            method = method_match.group(1) if method_match else "GET"

            # Extract inputs
            inputs = []
            for input_match in input_pattern.finditer(form_inner):
                input_html = input_match.group(0)
                name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_html, re.IGNORECASE)

                inputs.append({
                    "name": name_match.group(1) if name_match else "",
                    "type": type_match.group(1) if type_match else "text",
                    "value": value_match.group(1) if value_match else "",
                })

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _extract_parameters(self, url: str) -> list[str]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())

    def _extract_links(self, base_url: str, html: str) -> None:
        """Extract links from HTML and add to crawl queue."""
        # Simple link extraction
        link_pattern = re.compile(r'href\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

        for match in link_pattern.finditer(html):
            href = match.group(1)
            # Skip anchors, javascript, mailto, etc.
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue

            full_url = urljoin(base_url, href)

            # Only follow links within the same scope
            if self.client.scope.contains(full_url):
                if full_url not in self._visited:
                    self._queue.append((full_url, len(self._visited)))


def crawl_target(client: HttpClient, start_url: str, max_depth: int = 3, max_pages: int = 100) -> CrawlResult:
    """Convenience function to crawl a target."""
    crawler = Crawler(client, max_depth=max_depth, max_pages=max_pages)
    return crawler.crawl(start_url)