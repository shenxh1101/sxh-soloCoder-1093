from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .image_parser import InstalledPackage
from .utils import cvss_score_to_severity
from .vuln_db import VulnerabilityDatabase, VulnerabilityEntry, FixVersionDatabase


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
    version_range_detail: str = ""

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
            "version_range_detail": self.version_range_detail,
        }


class VulnerabilityMatcher:
    def __init__(self, vuln_db: VulnerabilityDatabase):
        self.vuln_db = vuln_db
        self.ignored_cves: Set[str] = set()
        self.fix_db: FixVersionDatabase = vuln_db.fix_db

    def set_ignored_cves(self, cve_ids: List[str]) -> None:
        self.ignored_cves = set(cve_ids)

    def _version_in_affected_range(self, version: str, version_range, cpe_version: str) -> bool:
        from packaging import version as pkg_version

        if version_range and not version_range.is_unrestricted():
            return version_range.contains_version(version)

        if cpe_version == "*" or cpe_version == "-":
            return True

        try:
            installed = pkg_version.parse(version)
            cpe_ver = pkg_version.parse(cpe_version)
            return installed == cpe_ver
        except pkg_version.InvalidVersion:
            return version == cpe_version

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

                    best_detail = None
                    for detail in entry.cpe_match_details:
                        if not detail.vulnerable:
                            continue

                        dv = detail.vendor.lower()
                        dp = detail.product.lower()
                        sv = vendor.lower() if vendor else ""
                        sp = search_term.lower()

                        vendor_ok = (
                            not vendor
                            or dv == "*"
                            or dv == sv
                            or sv in dv
                            or dv in sv
                        )

                        product_ok = (
                            dp == "*"
                            or dp == sp
                            or sp in dp
                            or dp in sp
                        )

                        if not vendor_ok or not product_ok:
                            continue

                        if not self._version_in_affected_range(
                            package.version,
                            detail.version_range,
                            detail.cpe_version_fragment
                        ):
                            continue

                        best_detail = detail
                        break

                    if best_detail is None:
                        continue

                    ver_range_str = ""
                    vr = best_detail.version_range
                    if not vr.is_unrestricted():
                        parts = []
                        if vr.start_including:
                            parts.append(f">={vr.start_including}")
                        if vr.start_excluding:
                            parts.append(f">{vr.start_excluding}")
                        if vr.end_including:
                            parts.append(f"<={vr.end_including}")
                        if vr.end_excluding:
                            parts.append(f"<{vr.end_excluding}")
                        ver_range_str = ", ".join(parts)
                    elif best_detail.cpe_version_fragment not in ("*", "-"):
                        ver_range_str = f"=={best_detail.cpe_version_fragment}"
                    else:
                        ver_range_str = "all versions"

                    fix_ver = self._resolve_fix_version(
                        entry, package.name, package.version, distro
                    )

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
                        fixed_version=fix_ver,
                        published_date=entry.published_date,
                        cpe_matched=best_detail.criteria,
                        version_range_detail=ver_range_str,
                    )
                    results.append(result)

        return self._deduplicate_results(results)

    def _resolve_fix_version(self, entry: VulnerabilityEntry, package_name: str,
                              installed_version: str, distro: str) -> str:
        if package_name in entry.fixed_versions:
            return entry.fixed_versions[package_name]

        if "*" in entry.fixed_versions:
            return entry.fixed_versions["*"]

        fix_ver = self.fix_db.get_fix_version(package_name, installed_version, distro)
        if fix_ver:
            return fix_ver

        return ""

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

        with_fix = sum(1 for r in results if r.fixed_version)

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
            "fix_available": with_fix,
            "layer_distribution": layer_distribution,
        }