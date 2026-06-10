import gzip
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from .config import ScannerConfig


@dataclass
class VulnerabilityEntry:
    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v2_score: float
    severity: str
    published_date: str
    last_modified_date: str
    cpe_matches: List[str] = field(default_factory=list)
    affected_vendors: Set[str] = field(default_factory=set)
    affected_products: Set[str] = field(default_factory=set)
    references: List[str] = field(default_factory=list)
    fixed_versions: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_v3_score": self.cvss_v3_score,
            "cvss_v2_score": self.cvss_v2_score,
            "severity": self.severity,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "cpe_matches": self.cpe_matches,
            "affected_vendors": list(self.affected_vendors),
            "affected_products": list(self.affected_products),
            "references": self.references,
            "fixed_versions": self.fixed_versions,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VulnerabilityEntry":
        return cls(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            cvss_v3_score=data.get("cvss_v3_score", 0.0),
            cvss_v2_score=data.get("cvss_v2_score", 0.0),
            severity=data.get("severity", "UNKNOWN"),
            published_date=data.get("published_date", ""),
            last_modified_date=data.get("last_modified_date", ""),
            cpe_matches=data.get("cpe_matches", []),
            affected_vendors=set(data.get("affected_vendors", [])),
            affected_products=set(data.get("affected_products", [])),
            references=data.get("references", []),
            fixed_versions=data.get("fixed_versions", {}),
        )


class VulnerabilityDatabase:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.db_dir = config.db_dir
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self._entries: Dict[str, VulnerabilityEntry] = {}
        self._product_index: Dict[str, Set[str]] = {}
        self._vendor_product_index: Dict[Tuple[str, str], Set[str]] = {}
        self._last_updated: Optional[datetime] = None
        self._loaded_years: Set[int] = set()

    def load(self) -> None:
        metadata_path = self.db_dir / "metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                self._last_updated = datetime.fromisoformat(meta.get("last_updated", "")) if meta.get("last_updated") else None
                self._loaded_years = set(meta.get("loaded_years", []))
            except (json.JSONDecodeError, KeyError, ValueError):
                pass

        index_path = self.db_dir / "vulnerability_index.json"
        if index_path.exists():
            try:
                with open(index_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for entry_data in data:
                    entry = VulnerabilityEntry.from_dict(entry_data)
                    self._entries[entry.cve_id] = entry
                    self._index_entry(entry)
            except (json.JSONDecodeError, KeyError):
                pass

    def update(self, force: bool = False, years: Optional[List[int]] = None) -> bool:
        current_year = datetime.now().year
        if years is None:
            years = list(range(self.config.nvd_start_year, current_year + 1))

        updated = False

        modified_path = self.db_dir / "nvdcve-2.0-modified.json"
        modified_meta_path = self.db_dir / "nvdcve-2.0-modified.meta"

        if self._should_update_modified(modified_meta_path, force):
            try:
                if not self.config.offline_mode:
                    self._download_feed(self.config.nvd_modified_url, modified_path)
                    updated = True
            except Exception:
                pass

        for year in years:
            filename = f"nvdcve-2.0-{year}.json"
            file_path = self.db_dir / filename
            meta_path = self.db_dir / f"{filename}.meta"

            if not self._should_update(meta_path, year, force):
                continue

            if self.config.offline_mode:
                continue

            url = self.config.nvd_feed_url.format(year=year)
            try:
                self._download_feed(url, file_path)
                self._update_metadata(meta_path)
                updated = True
            except Exception:
                pass

        if updated:
            self._rebuild_index()

        return updated

    def _should_update(self, meta_path: Path, year: int, force: bool) -> bool:
        if force:
            return True
        if not meta_path.exists():
            return True
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            last_update = datetime.fromisoformat(meta.get("last_updated", ""))
            return datetime.now() - last_update > timedelta(days=7)
        except (json.JSONDecodeError, KeyError, ValueError):
            return True

    def _should_update_modified(self, meta_path: Path, force: bool) -> bool:
        if force:
            return True
        if not meta_path.exists():
            return True
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            last_update = datetime.fromisoformat(meta.get("last_updated", ""))
            return datetime.now() - last_update > timedelta(hours=2)
        except (json.JSONDecodeError, KeyError, ValueError):
            return True

    def _download_feed(self, url: str, output_path: Path) -> None:
        response = requests.get(url, stream=True, timeout=120)
        response.raise_for_status()

        if url.endswith(".gz"):
            decompressed = gzip.decompress(response.content)
            with open(output_path, "wb") as f:
                f.write(decompressed)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(response.text)

    def _update_metadata(self, meta_path: Path) -> None:
        meta = {
            "last_updated": datetime.now().isoformat(),
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)

    def _rebuild_index(self) -> None:
        self._entries.clear()
        self._product_index.clear()
        self._vendor_product_index.clear()

        all_files = list(self.db_dir.glob("nvdcve-2.0-*.json"))
        all_files = [f for f in all_files if not f.name.endswith(".meta")]

        for file_path in all_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._parse_nvd_feed(data)
            except (json.JSONDecodeError, KeyError, IOError):
                continue

        self._save_index()
        self._save_metadata()

    def _parse_nvd_feed(self, data: dict) -> None:
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln_item in vulnerabilities:
            cve_data = vuln_item.get("cve", {})
            if not cve_data:
                continue

            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            published = cve_data.get("published", "")
            modified = cve_data.get("lastModified", "")

            cvss_v3, cvss_v2, severity = self._extract_cvss(cve_data)

            cpe_matches: List[str] = []
            affected_vendors: Set[str] = set()
            affected_products: Set[str] = set()

            configurations = cve_data.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_match_list = node.get("cpeMatch", [])
                    for cpe_match in cpe_match_list:
                        criteria = cpe_match.get("criteria", "")
                        if criteria:
                            cpe_matches.append(criteria)
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                affected_vendors.add(parts[3])
                                affected_products.add(parts[4])

            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            entry = VulnerabilityEntry(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3,
                cvss_v2_score=cvss_v2,
                severity=severity,
                published_date=published,
                last_modified_date=modified,
                cpe_matches=cpe_matches,
                affected_vendors=affected_vendors,
                affected_products=affected_products,
                references=references,
            )

            self._entries[cve_id] = entry
            self._index_entry(entry)

    def _extract_cvss(self, cve_data: dict) -> Tuple[float, float, str]:
        from .utils import cvss_score_to_severity

        metrics = cve_data.get("metrics", {})
        cvss_v3 = 0.0
        cvss_v2 = 0.0
        severity = "UNKNOWN"

        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_v3 = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", cvss_score_to_severity(cvss_v3))
        else:
            cvss_v30 = metrics.get("cvssMetricV30", [])
            if cvss_v30:
                cvss_data = cvss_v30[0].get("cvssData", {})
                cvss_v3 = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", cvss_score_to_severity(cvss_v3))

        cvss_v2_list = metrics.get("cvssMetricV2", [])
        if cvss_v2_list:
            v2_data = cvss_v2_list[0].get("cvssData", {})
            cvss_v2 = v2_data.get("baseScore", 0.0)
            if severity == "UNKNOWN" and cvss_v2 > 0:
                severity = cvss_score_to_severity(cvss_v2)

        return cvss_v3, cvss_v2, severity

    def _index_entry(self, entry: VulnerabilityEntry) -> None:
        for product in entry.affected_products:
            product_lower = product.lower()
            if product_lower not in self._product_index:
                self._product_index[product_lower] = set()
            self._product_index[product_lower].add(entry.cve_id)

            for vendor in entry.affected_vendors:
                key = (vendor.lower(), product_lower)
                if key not in self._vendor_product_index:
                    self._vendor_product_index[key] = set()
                self._vendor_product_index[key].add(entry.cve_id)

    def _save_index(self) -> None:
        index_path = self.db_dir / "vulnerability_index.json"
        data = [entry.to_dict() for entry in self._entries.values()]
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

    def _save_metadata(self) -> None:
        metadata_path = self.db_dir / "metadata.json"
        meta = {
            "last_updated": datetime.now().isoformat(),
            "loaded_years": list(self._loaded_years),
            "total_entries": len(self._entries),
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(meta, f)

    def get_entry(self, cve_id: str) -> Optional[VulnerabilityEntry]:
        return self._entries.get(cve_id)

    def query_by_product(self, product: str, vendor: Optional[str] = None) -> List[VulnerabilityEntry]:
        results: List[VulnerabilityEntry] = []

        if vendor:
            key = (vendor.lower(), product.lower())
            cve_ids = self._vendor_product_index.get(key, set())
            for cve_id in cve_ids:
                entry = self._entries.get(cve_id)
                if entry:
                    results.append(entry)
        else:
            cve_ids = self._product_index.get(product.lower(), set())
            for cve_id in cve_ids:
                entry = self._entries.get(cve_id)
                if entry:
                    results.append(entry)

        return results

    def query_by_package(self, package_name: str, package_version: str, distro: str = "") -> List[VulnerabilityEntry]:
        from .utils import cpe_match_package

        results: List[VulnerabilityEntry] = []
        seen: Set[str] = set()

        vendor_map = {
            "debian": ["debian", "canonical"],
            "rhel": ["redhat", "fedoraproject", "centos"],
            "alpine": ["alpinelinux"],
        }

        candidates = vendor_map.get(distro, [""])
        if distro:
            candidates = [distro] + candidates

        for candidate_vendor in candidates:
            key = (candidate_vendor, package_name.lower())
            if key in self._vendor_product_index:
                for cve_id in self._vendor_product_index[key]:
                    if cve_id not in seen:
                        seen.add(cve_id)
                        entry = self._entries.get(cve_id)
                        if entry:
                            results.append(entry)

        if not results:
            cve_ids = self._product_index.get(package_name.lower(), set())
            for cve_id in cve_ids:
                if cve_id not in seen:
                    seen.add(cve_id)
                    entry = self._entries.get(cve_id)
                    if entry:
                        for cpe in entry.cpe_matches:
                            if cpe_match_package(cpe, "", package_name, package_version):
                                results.append(entry)
                                break

        return results

    def get_statistics(self) -> dict:
        return {
            "total_entries": len(self._entries),
            "last_updated": self._last_updated.isoformat() if self._last_updated else "never",
            "indexed_products": len(self._product_index),
        }

    def search_cve(self, keyword: str) -> List[VulnerabilityEntry]:
        results = []
        keyword_lower = keyword.lower()
        for entry in self._entries.values():
            if keyword_lower in entry.cve_id.lower():
                results.append(entry)
            elif keyword_lower in entry.description.lower():
                results.append(entry)
        return results