"""
STIX 2.1 threat intelligence export.

Converts DeepWebHarvester crawl results + IOCs into standardised STIX 2.1
bundles ready for sharing with SIEMs, threat-intel platforms (MISP, OpenCTI,
ThreatConnect) or direct TAXII 2.1 push.

Produces the following STIX Domain Objects (SDOs) per page:
  - Indicator     (IOC-based: IPs, domains, URLs, BTC/XMR wallets, CVEs)
  - ThreatActor   (synthesised from classification category when High/Critical)
  - ObservedData  (raw page metadata)
  - Report        (wraps a full crawl-job bundle)

Requirements::

    pip install stix2
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import stix2  # type: ignore[import]
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False
    logger.debug("stix2 library not installed — STIX export disabled.")

from .crawler import CrawlResult
from .intelligence import PageIntelligence


_IDENTITY = None


def _get_identity():
    """Singleton STIX Identity representing DeepWebHarvester."""
    global _IDENTITY
    if _IDENTITY is None and STIX_AVAILABLE:
        _IDENTITY = stix2.Identity(
            name="DeepWebHarvester",
            identity_class="system",
            description="Automated OSINT dark web crawler and threat-intelligence platform",
        )
    return _IDENTITY


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _uuid_from_url(url: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, url))


class STIXExporter:
    """
    Convert crawl results and intelligence data into STIX 2.1 bundles.

    Usage::

        exporter = STIXExporter()
        bundle  = exporter.build_bundle(results, intel_list, job_id="abc")
        json_str = exporter.to_json(bundle)
        exporter.save(bundle, path="intel.stix.json")
    """

    def __init__(self) -> None:
        if not STIX_AVAILABLE:
            raise ImportError(
                "stix2 is required for STIX export. Run: pip install stix2"
            )
        self._identity = _get_identity()

    # ── SDO builders ──────────────────────────────────────────────────────────

    def _ip_indicator(self, ip: str, page_url: str) -> Any:
        return stix2.Indicator(
            id=f"indicator--{_uuid_from_url('ip:' + ip)}",
            created_by_ref=self._identity.id,
            name=f"Suspicious IP: {ip}",
            description=f"IPv4 address extracted from dark web page {page_url}",
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            indicator_types=["malicious-activity", "anonymization"],
            valid_from=_now(),
        )

    def _domain_indicator(self, domain: str, page_url: str) -> Any:
        return stix2.Indicator(
            id=f"indicator--{_uuid_from_url('domain:' + domain)}",
            created_by_ref=self._identity.id,
            name=f"Dark-web associated domain: {domain}",
            description=f"Domain referenced from dark web page {page_url}",
            pattern=f"[domain-name:value = '{domain}']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            valid_from=_now(),
        )

    def _url_indicator(self, url: str) -> Any:
        return stix2.Indicator(
            id=f"indicator--{_uuid_from_url('url:' + url)}",
            created_by_ref=self._identity.id,
            name=f"Dark web URL: {url[:80]}",
            description="URL extracted from .onion hidden service",
            pattern=f"[url:value = '{url}']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            valid_from=_now(),
        )

    def _btc_indicator(self, address: str, page_url: str) -> Any:
        return stix2.Indicator(
            id=f"indicator--{_uuid_from_url('btc:' + address)}",
            created_by_ref=self._identity.id,
            name=f"Bitcoin address: {address}",
            description=f"BTC wallet address found on {page_url}",
            pattern=f"[cryptocurrency-wallet:value = '{address}']",
            pattern_type="stix",
            indicator_types=["malicious-activity", "financial-crime"],
            valid_from=_now(),
        )

    def _xmr_indicator(self, address: str, page_url: str) -> Any:
        return stix2.Indicator(
            id=f"indicator--{_uuid_from_url('xmr:' + address)}",
            created_by_ref=self._identity.id,
            name=f"Monero address: {address}",
            description=f"XMR wallet address found on {page_url}",
            pattern=f"[cryptocurrency-wallet:value = '{address}']",
            pattern_type="stix",
            indicator_types=["malicious-activity", "financial-crime"],
            valid_from=_now(),
        )

    def _cve_vulnerability(self, cve: str, page_url: str) -> Any:
        return stix2.Vulnerability(
            id=f"vulnerability--{_uuid_from_url(cve)}",
            created_by_ref=self._identity.id,
            name=cve,
            description=f"CVE reference found on dark web page {page_url}",
        )

    def _observed_data(self, result: CrawlResult) -> Any:
        return stix2.ObservedData(
            created_by_ref=self._identity.id,
            first_observed=_now(),
            last_observed=_now(),
            number_observed=1,
            object_refs=[],   # populated in bundle
            custom_properties={
                "x_dwh_url": result.url,
                "x_dwh_title": result.title,
                "x_dwh_depth": result.depth,
                "x_dwh_site": result.site,
                "x_dwh_crawl_time": result.crawl_time,
                "x_dwh_content_hash": result.content_hash,
            },
        )

    # ── Bundle builder ────────────────────────────────────────────────────────

    def build_bundle(
        self,
        results: List[CrawlResult],
        intel_list: List[PageIntelligence],
        job_id: str = "",
        min_risk_label: str = "Low",
    ) -> Any:
        """
        Build a STIX 2.1 Bundle from a list of crawl results + intelligence.

        Args:
            results:        CrawlResult objects from the crawler.
            intel_list:     Corresponding PageIntelligence objects.
            job_id:         Optional job identifier for the Report SDO.
            min_risk_label: Only include IOCs from pages at or above this risk
                            level (Low | Medium | High | Critical).

        Returns:
            A ``stix2.Bundle`` object.
        """
        risk_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        min_rank = risk_order.get(min_risk_label, 0)
        objects: List[Any] = [self._identity]
        ref_ids: List[str] = [self._identity.id]

        for result, intel in zip(results, intel_list):
            rank = risk_order.get(intel.threat.risk_label, 0)
            if rank < min_rank:
                continue

            iocs = intel.iocs

            for ip in iocs.ipv4:
                obj = self._ip_indicator(ip, result.url)
                objects.append(obj)
                ref_ids.append(obj.id)

            for domain in iocs.domains:
                obj = self._domain_indicator(domain, result.url)
                objects.append(obj)
                ref_ids.append(obj.id)

            for url in iocs.urls[:10]:  # cap to 10 per page
                obj = self._url_indicator(url)
                objects.append(obj)
                ref_ids.append(obj.id)

            for btc in iocs.btc_addresses:
                obj = self._btc_indicator(btc, result.url)
                objects.append(obj)
                ref_ids.append(obj.id)

            for xmr in iocs.xmr_addresses:
                obj = self._xmr_indicator(xmr, result.url)
                objects.append(obj)
                ref_ids.append(obj.id)

            for cve in iocs.cves:
                obj = self._cve_vulnerability(cve, result.url)
                objects.append(obj)
                ref_ids.append(obj.id)

        # Wrap in a Report SDO
        if len(ref_ids) > 1:
            report = stix2.Report(
                created_by_ref=self._identity.id,
                name=f"DeepWebHarvester Intel Report — job {job_id or 'N/A'}",
                description=(
                    f"Automated OSINT intelligence report from {len(results)} "
                    "dark web pages. Generated by DeepWebHarvester v2."
                ),
                published=_now(),
                report_types=["threat-actor", "malware", "indicator"],
                object_refs=ref_ids,
            )
            objects.append(report)

        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        logger.info(
            "STIX bundle built: %d objects from %d pages",
            len(objects), len(results),
        )
        return bundle

    # ── Serialisation ─────────────────────────────────────────────────────────

    @staticmethod
    def to_json(bundle: Any, indent: int = 2) -> str:
        """Serialise a STIX bundle to a JSON string."""
        return bundle.serialize(pretty=(indent > 0))

    @staticmethod
    def save(bundle: Any, path: str) -> None:
        """Write a STIX bundle to a JSON file."""
        from pathlib import Path
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(STIXExporter.to_json(bundle), encoding="utf-8")
        logger.info("STIX bundle saved to %s", path)
