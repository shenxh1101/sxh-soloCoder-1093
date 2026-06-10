from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .image_parser import InstalledPackage
from .utils import cpe_match_package, cvss_score_to_severity
from .vuln_db import VulnerabilityDatabase, VulnerabilityEntry


@dataclass
class MatchResult:
    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v2_score: float
    severity: str
    package_name: str
    package_version: str
    layer_order: int
    package_manager: str
    distro: str
    references: List[str] = field(default_factory=list)
    fixed_version: str = ""
    published_date: str = ""
    cpe_matched: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v2_score": self.cvss_v2_score,
            "severity": self.severity,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "layer_order": self.layer_order,
            "package_manager": self.package_manager,
            "distro": self.distro,
            "references": self.references,
            "fixed_version": self.fixed_version,
            "published_date": self.published_date,
            "cpe_matched": self.cpe_matched,
        }


class VulnerabilityMatcher:
    def __init__(self, vuln_db: VulnerabilityDatabase):
        self.vuln_db = vuln_db
        self.ignored_cves: Set[str] = set()

    def set_ignored_cves(self, cve_ids: List[str]) -> None:
        self.ignored_cves = set(cve_ids)

    def match_package(self, package: InstalledPackage, distro: str = "") -> List[MatchResult]:
        results: List[MatchResult] = []

        vendor_map = {
            "debian": ["debian", "canonical"],
            "rhel": ["redhat", "fedoraproject", "centos"],
            "alpine": ["alpinelinux"],
        }

        vendor_candidates = vendor_map.get(distro, [distro] if distro else [""])

        search_terms = [package.name]
        if package.source_name and package.source_name != package.name:
            search_terms.append(package.source_name)

        for search_term in search_terms:
            for vendor in vendor_candidates:
                entries = self.vuln_db.query_by_product(search_term, vendor if vendor else None)
                for entry in entries:
                    if entry.cve_id in self.ignored_cves:
                        continue

                    matched_cpe = ""
                    for cpe in entry.cpe_matches:
                        parts = cpe.split(":")
                        if len(parts) >= 6:
                            cpe_vendor = parts[3].lower()
                            cpe_product = parts[4].lower()
                            cpe_version = parts[5]

                            vendor_match = (
                                not vendor
                                or cpe_vendor == vendor.lower()
                                or cpe_vendor in vendor.lower()
                                or vendor.lower() in cpe_vendor
                                or cpe_vendor == "*"
                            )

                            product_match = (
                                cpe_product == search_term.lower()
                                or search_term.lower() in cpe_product
                                or cpe_product in search_term.lower()
                                or cpe_product == "*"
                            )

                            if vendor_match and product_match:
                                matched_cpe = cpe

                                if cpe_version != "*" and cpe_version != "-":
                                    if not cpe_match_package(cpe, vendor, search_term, package.version):
                                        continue

                                result = MatchResult(
                                    cve_id=entry.cve_id,
                                    description=entry.description,
                                    cvss_v3_score=entry.cvss_v3_score,
                                    cvss_v2_score=entry.cvss_v2_score,
                                    severity=entry.severity,
                                    package_name=package.name,
                                    package_version=package.version,
                                    layer_order=package.layer_order,
                                    package_manager=package.package_manager,
                                    distro=distro,
                                    references=entry.references,
                                    fixed_version=entry.fixed_versions.get(package.name, ""),
                                    published_date=entry.published_date,
                                    cpe_matched=matched_cpe,
                                )
                                results.append(result)
                                break

        return self._deduplicate_results(results)

    def match_packages(self, packages: List[InstalledPackage], distro: str = "") -> List[MatchResult]:
        all_results: List[MatchResult] = []

        for package in packages:
            results = self.match_package(package, distro)
            all_results.extend(results)

        return self._deduplicate_results(all_results)

    def _deduplicate_results(self, results: List[MatchResult]) -> List[MatchResult]:
        seen = set()
        deduped = []
        for r in results:
            key = (r.cve_id, r.package_name, r.package_version)
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        return deduped

    def get_summary(self, results: List[MatchResult]) -> dict:
        total = len(results)
        critical = sum(1 for r in results if r.severity == "CRITICAL")
        high = sum(1 for r in results if r.severity == "HIGH")
        medium = sum(1 for r in results if r.severity == "MEDIUM")
        low = sum(1 for r in results if r.severity == "LOW")
        unknown = sum(1 for r in results if r.severity == "UNKNOWN")

        unique_packages = len(set(r.package_name for r in results))
        unique_cves = len(set(r.cve_id for r in results))

        layer_distribution: Dict[int, int] = {}
        for r in results:
            layer_distribution[r.layer_order] = layer_distribution.get(r.layer_order, 0) + 1

        return {
            "total_vulnerabilities": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "unknown": unknown,
            "unique_affected_packages": unique_packages,
            "unique_cves": unique_cves,
            "layer_distribution": layer_distribution,
        }