"""NVD (National Vulnerability Database) Integration - Fetch CVE/CVSS data from NVD API."""

import httpx
import json
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class CVERecord:
    """CVE record from NVD."""
    cve_id: str
    description: str
    cvss_v3_score: Optional[float]
    cvss_v3_vector: Optional[str]
    cvss_v2_score: Optional[float]
    published_date: str
    last_modified_date: str
    references: List[str]
    affected_products: List[str]


class NVDClient:
    """Client for National Vulnerability Database (NVD) API."""

    # NVD API endpoints
    NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY_HEADER = "X-API-Key"

    def __init__(self, api_key: Optional[str] = None, timeout: float = 30.0):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (optional, but recommended for higher rate limits)
            timeout: HTTP request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.http_client = httpx.Client(timeout=timeout)
        self._cache: Dict[str, CVERecord] = {}

    def search_cve(self, keyword: str, max_results: int = 10) -> List[CVERecord]:
        """
        Search CVE records by keyword.

        Args:
            keyword: Search keyword (e.g., "IAM", "privilege escalation")
            max_results: Maximum results to return

        Returns:
            List of CVE records matching keyword
        """
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": min(max_results, 200),
            }

            headers = {}
            if self.api_key:
                headers[self.NVD_API_KEY_HEADER] = self.api_key

            response = self.http_client.get(
                self.NVD_API_BASE_URL,
                params=params,
                headers=headers,
            )
            response.raise_for_status()

            data = response.json()
            cves = []

            for vulnerability in data.get("vulnerabilities", []):
                cve_data = vulnerability.get("cve", {})
                cve_record = self._parse_cve_data(cve_data)
                if cve_record:
                    cves.append(cve_record)
                    self._cache[cve_record.cve_id] = cve_record

            logger.info(f"Found {len(cves)} CVEs matching '{keyword}'")
            return cves

        except httpx.RequestError as e:
            logger.error(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error searching CVE: {e}")
            return []

    def get_cve_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """
        Get CVE record by ID.

        Args:
            cve_id: CVE ID (e.g., "CVE-2024-12345")

        Returns:
            CVE record or None if not found
        """
        # Check cache first
        if cve_id in self._cache:
            return self._cache[cve_id]

        try:
            params = {"cveId": cve_id}
            headers = {}
            if self.api_key:
                headers[self.NVD_API_KEY_HEADER] = self.api_key

            response = self.http_client.get(
                self.NVD_API_BASE_URL,
                params=params,
                headers=headers,
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if vulnerabilities:
                cve_data = vulnerabilities[0].get("cve", {})
                cve_record = self._parse_cve_data(cve_data)
                if cve_record:
                    self._cache[cve_id] = cve_record
                    return cve_record

            logger.warning(f"CVE not found: {cve_id}")
            return None

        except httpx.RequestError as e:
            logger.error(f"NVD API request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None

    def get_recent_cves(self, days: int = 7) -> List[CVERecord]:
        """
        Get recent CVE records published in last N days.

        Args:
            days: Number of days to look back

        Returns:
            List of recent CVE records
        """
        try:
            # NVD API uses specific date format
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)

            # Format for NVD API: YYYY-MM-DDTHH:MM:SS.000Z
            start_str = start_date.isoformat() + "Z"
            end_str = end_date.isoformat() + "Z"

            params = {
                "pubStartDate": start_str,
                "pubEndDate": end_str,
                "resultsPerPage": 100,
            }

            headers = {}
            if self.api_key:
                headers[self.NVD_API_KEY_HEADER] = self.api_key

            response = self.http_client.get(
                self.NVD_API_BASE_URL,
                params=params,
                headers=headers,
            )
            response.raise_for_status()

            data = response.json()
            cves = []

            for vulnerability in data.get("vulnerabilities", []):
                cve_data = vulnerability.get("cve", {})
                cve_record = self._parse_cve_data(cve_data)
                if cve_record:
                    cves.append(cve_record)

            logger.info(f"Found {len(cves)} recent CVEs from last {days} days")
            return cves

        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {e}")
            return []

    def _parse_cve_data(self, cve_data: Dict[str, Any]) -> Optional[CVERecord]:
        """Parse CVE data from NVD API response."""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Extract description
            description = ""
            descriptions = cve_data.get("descriptions", [])
            for desc_entry in descriptions:
                if desc_entry.get("lang") == "en":
                    description = desc_entry.get("value", "")
                    break

            # Extract CVSS scores
            cvss_v3_score = None
            cvss_v3_vector = None
            cvss_v2_score = None

            metrics = cve_data.get("metrics", {})

            # CVSS v3.1
            for metric in metrics.get("cvssMetricV31", []):
                if metric.get("cvssData"):
                    cvss_v3_score = float(metric["cvssData"].get("baseScore", 0))
                    cvss_v3_vector = metric["cvssData"].get("vectorString", "")
                    break

            # CVSS v3.0 (fallback)
            if not cvss_v3_score:
                for metric in metrics.get("cvssMetricV30", []):
                    if metric.get("cvssData"):
                        cvss_v3_score = float(metric["cvssData"].get("baseScore", 0))
                        cvss_v3_vector = metric["cvssData"].get("vectorString", "")
                        break

            # CVSS v2.0 (legacy)
            for metric in metrics.get("cvssMetricV2", []):
                if metric.get("cvssData"):
                    cvss_v2_score = float(metric["cvssData"].get("baseScore", 0))
                    break

            # Extract dates
            published_date = cve_data.get("published", "")
            last_modified = cve_data.get("lastModified", "")

            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            # Extract affected products
            affected_products = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            affected_products.append(cpe)

            return CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_vector=cvss_v3_vector,
                cvss_v2_score=cvss_v2_score,
                published_date=published_date,
                last_modified_date=last_modified,
                references=references,
                affected_products=affected_products,
            )

        except Exception as e:
            logger.error(f"Error parsing CVE data: {e}")
            return None

    def close(self):
        """Close HTTP client connection."""
        self.http_client.close()


class VulnerabilityDatabase:
    """Local database of vulnerabilities mapped to attack paths."""

    def __init__(self):
        """Initialize vulnerability database."""
        self.vulnerabilities: Dict[str, List[CVERecord]] = {}
        self.path_to_vulns: Dict[str, List[str]] = {}  # path_id -> CVE IDs

    def register_vulnerability(self, path_id: str, cve_record: CVERecord) -> None:
        """Register a vulnerability for an attack path."""
        if cve_record.cve_id not in self.vulnerabilities:
            self.vulnerabilities[cve_record.cve_id] = []
        self.vulnerabilities[cve_record.cve_id].append(cve_record)

        if path_id not in self.path_to_vulns:
            self.path_to_vulns[path_id] = []
        if cve_record.cve_id not in self.path_to_vulns[path_id]:
            self.path_to_vulns[path_id].append(cve_record.cve_id)

    def get_vulnerabilities_for_path(self, path_id: str) -> List[CVERecord]:
        """Get vulnerabilities associated with a path."""
        cve_ids = self.path_to_vulns.get(path_id, [])
        vulns = []
        for cve_id in cve_ids:
            vulns.extend(self.vulnerabilities.get(cve_id, []))
        return vulns

    def get_max_severity_for_path(self, path_id: str) -> Optional[Tuple[str, float]]:
        """Get max CVSS score and severity for a path."""
        vulns = self.get_vulnerabilities_for_path(path_id)
        if not vulns:
            return None

        max_score = 0.0
        max_severity = "None"

        for vuln in vulns:
            if vuln.cvss_v3_score and vuln.cvss_v3_score > max_score:
                max_score = vuln.cvss_v3_score
                if max_score < 4.0:
                    max_severity = "Low"
                elif max_score < 7.0:
                    max_severity = "Medium"
                elif max_score < 9.0:
                    max_severity = "High"
                else:
                    max_severity = "Critical"

        return (max_severity, max_score)
