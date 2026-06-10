from typing import List, Optional

from .matcher import MatchResult
from .utils import cvss_score_to_severity


class VulnerabilityFilter:
    SEVERITY_ORDER = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "UNKNOWN": 1,
    }

    def __init__(self, results: List[MatchResult]):
        self.results = results

    def by_severity(self, severity: str) -> List[MatchResult]:
        severity_upper = severity.upper()
        if severity_upper in self.SEVERITY_ORDER:
            threshold = self.SEVERITY_ORDER[severity_upper]
            return [r for r in self.results if self.SEVERITY_ORDER.get(r.severity, 0) >= threshold]
        return [r for r in self.results if r.severity.upper() == severity_upper]

    def by_min_cvss(self, min_score: float) -> List[MatchResult]:
        return [r for r in self.results if r.cvss_v3_score >= min_score or (r.cvss_v3_score == 0 and r.cvss_v2_score >= min_score)]

    def by_max_cvss(self, max_score: float) -> List[MatchResult]:
        return [r for r in self.results if r.cvss_v3_score <= max_score or (r.cvss_v3_score == 0 and r.cvss_v2_score <= max_score)]

    def by_package(self, package_name: str) -> List[MatchResult]:
        return [r for r in self.results if package_name.lower() in r.package_name.lower()]

    def by_layer(self, layer_order: int) -> List[MatchResult]:
        return [r for r in self.results if r.layer_order == layer_order]

    def by_cve(self, cve_id: str) -> List[MatchResult]:
        return [r for r in self.results if cve_id.upper() in r.cve_id.upper()]

    def apply(self, min_severity: Optional[str] = None, min_cvss: Optional[float] = None,
              max_cvss: Optional[float] = None, package_filter: Optional[str] = None,
              layer_filter: Optional[int] = None, cve_filter: Optional[str] = None) -> List[MatchResult]:
        filtered = self.results

        if min_severity:
            filtered = self.by_severity(min_severity)
            self.results = filtered

        if min_cvss is not None:
            filtered = self.by_min_cvss(min_cvss)
            self.results = filtered

        if max_cvss is not None:
            filtered = self.by_max_cvss(max_cvss)
            self.results = filtered

        if package_filter:
            filtered = self.by_package(package_filter)
            self.results = filtered

        if layer_filter is not None:
            filtered = self.by_layer(layer_filter)
            self.results = filtered

        if cve_filter:
            filtered = self.by_cve(cve_filter)
            self.results = filtered

        return filtered

    def sort_by_severity(self, results: Optional[List[MatchResult]] = None) -> List[MatchResult]:
        target = results or self.results
        return sorted(target, key=lambda r: (-r.cvss_v3_score, -r.cvss_v2_score, r.cve_id))

    def sort_by_cvss(self, results: Optional[List[MatchResult]] = None) -> List[MatchResult]:
        target = results or self.results
        return sorted(target, key=lambda r: (-r.cvss_v3_score, -r.cvss_v2_score))

    def sort_by_package(self, results: Optional[List[MatchResult]] = None) -> List[MatchResult]:
        target = results or self.results
        return sorted(target, key=lambda r: (r.package_name, r.cve_id))

    def sort_by_layer(self, results: Optional[List[MatchResult]] = None) -> List[MatchResult]:
        target = results or self.results
        return sorted(target, key=lambda r: (r.layer_order, r.package_name))