import gzip
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from .config import ScannerConfig
from .utils import version_lt, version_le, version_gt, version_ge, version_eq


@dataclass
class VersionRange:
    start_including: Optional[str] = None
    start_excluding: Optional[str] = None
    end_including: Optional[str] = None
    end_excluding: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "startIncluding": self.start_including,
            "startExcluding": self.start_excluding,
            "endIncluding": self.end_including,
            "endExcluding": self.end_excluding,
        }

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "VersionRange":
        if not data:
            return cls()
        return cls(
            start_including=data.get("startIncluding"),
            start_excluding=data.get("startExcluding"),
            end_including=data.get("endIncluding"),
            end_excluding=data.get("endExcluding"),
        )

    def contains_version(self, version: str) -> bool:
        if self.start_including and version_lt(version, self.start_including):
            return False
        if self.start_excluding and version_le(version, self.start_excluding):
            return False
        if self.end_including and version_gt(version, self.end_including):
            return False
        if self.end_excluding and version_ge(version, self.end_excluding):
            return False
        return True

    def is_unrestricted(self) -> bool:
        return not any([
            self.start_including, self.start_excluding,
            self.end_including, self.end_excluding,
        ])


@dataclass
class CPEMatchDetail:
    criteria: str
    vulnerable: bool = True
    version_range: VersionRange = field(default_factory=VersionRange)
    vendor: str = ""
    product: str = ""
    cpe_version_fragment: str = "*"

    def to_dict(self) -> dict:
        return {
            "criteria": self.criteria,
            "vulnerable": self.vulnerable,
            "versionRange": self.version_range.to_dict(),
            "vendor": self.vendor,
            "product": self.product,
            "cpeVersionFragment": self.cpe_version_fragment,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CPEMatchDetail":
        return cls(
            criteria=data.get("criteria", ""),
            vulnerable=data.get("vulnerable", True),
            version_range=VersionRange.from_dict(data.get("versionRange")),
            vendor=data.get("vendor", ""),
            product=data.get("product", ""),
            cpe_version_fragment=data.get("cpeVersionFragment", "*"),
        )


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
    cpe_match_details: List[CPEMatchDetail] = field(default_factory=list)
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
            "cpe_match_details": [d.to_dict() for d in self.cpe_match_details],
            "affected_vendors": list(self.affected_vendors),
            "affected_products": list(self.affected_products),
            "references": self.references,
            "fixed_versions": self.fixed_versions,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VulnerabilityEntry":
        details_data = data.get("cpe_match_details", [])
        details = [CPEMatchDetail.from_dict(d) for d in details_data]
        return cls(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            cvss_v3_score=data.get("cvss_v3_score", 0.0),
            cvss_v2_score=data.get("cvss_v2_score", 0.0),
            severity=data.get("severity", "UNKNOWN"),
            published_date=data.get("published_date", ""),
            last_modified_date=data.get("last_modified_date", ""),
            cpe_matches=data.get("cpe_matches", []),
            cpe_match_details=details,
            affected_vendors=set(data.get("affected_vendors", [])),
            affected_products=set(data.get("affected_products", [])),
            references=data.get("references", []),
            fixed_versions=data.get("fixed_versions", {}),
        )

    def get_relevant_ranges(self, vendor: str, product: str) -> List[CPEMatchDetail]:
        relevant = []
        for detail in self.cpe_match_details:
            if not detail.vulnerable:
                continue
            dv = detail.vendor.lower()
            dp = detail.product.lower()
            sv = vendor.lower()
            sp = product.lower()
            vendor_ok = dv == "*" or dv == sv or sv in dv or dv in sv
            product_ok = dp == "*" or dp == sp or sp in dp or dp in sp
            if vendor_ok and product_ok:
                relevant.append(detail)
        return relevant


class FixVersionDatabase:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._fix_data: Dict[str, Dict[str, str]] = {}

    def load(self) -> None:
        if self.db_path.exists():
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self._fix_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._fix_data = {}

    def save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(self._fix_data, f, indent=2, ensure_ascii=False)

    def get_fix_version(self, product: str, installed_version: str, distro: str = "") -> Optional[str]:
        candidates = [product]
        if distro:
            candidates.insert(0, f"{distro}:{product}")
        for key in candidates:
            if key in self._fix_data:
                versions = self._fix_data[key]
                for affected_range, fix_version in sorted(versions.items(), key=lambda x: len(x[0]), reverse=True):
                    if self._version_in_range(installed_version, affected_range):
                        return fix_version
        return None

    def set_fix_version(self, product: str, affected_range: str, fix_version: str) -> None:
        if product not in self._fix_data:
            self._fix_data[product] = {}
        self._fix_data[product][affected_range] = fix_version
        self.save()

    @staticmethod
    def _version_in_range(version: str, range_spec: str) -> bool:
        range_spec = range_spec.strip()
        if range_spec.startswith(">=") and "<" in range_spec:
            parts = range_spec.split("<")
            lower = parts[0][2:].strip()
            upper = parts[1].strip()
            return version_ge(version, lower) and version_lt(version, upper)
        if "<" in range_spec:
            parts = range_spec.split("<")
            if len(parts) == 2 and parts[1].strip():
                return version_lt(version, parts[1].strip())
        if range_spec.startswith("<="):
            return version_le(version, range_spec[2:].strip())
        if range_spec.startswith(">="):
            return version_ge(version, range_spec[2:].strip())
        return version_eq(version, range_spec)

    def extract_from_cve_description(self, cve_id: str, description: str) -> Dict[str, str]:
        extracted: Dict[str, str] = {}
        STOP_WORDS = {"the", "a", "an", "of", "in", "on", "at", "to", "for", "is", "was", "and", "or", "not"}

        patterns = [
            (r'fixed\s+in\s+version\s+(\d[\w.+\-~]*?)\s+of\s+([a-z][\w.\-]+)', 2, 1),
            (r'([a-z][\w.\-]+?)\s+was\s+fixed\s+in\s+version\s+(\d[\w.+\-~]*)', 1, 2),
            (r'update\s+to\s+version\s+(\d[\w.+\-~]*)\s+(?:fixes|addresses|resolves)', 1, 1),
            (r'(?:update|upgrade)\s+([a-z][\w.\-]+)\s+(?:package\s+)?(?:to\s+)?(?:version\s+)?(\d[\d.:\-~+a-z]*?\.el\d)', 1, 2),
            (r'(?:update|upgrade)\s+([a-z][\w.\-]+)\s+(?:package\s+)?(?:to\s+)?(?:version\s+)?(\d[\d.:\-~+a-z]*?\+deb\d+u\d+)', 1, 2),
            (r'([a-z][\w.\-]+)-(\d[\d.:\-~+a-z]*?\.el\d\b)', 1, 2),
            (r'([a-z][\w.\-]+)-(\d[\d.:\-~+a-z]*?\+deb\d+u\d+\b)', 1, 2),
            (r'([a-z][\w.\-]+)-(\d[\d.:\-~+a-z]*?\-r\d+\b)', 1, 2),
            (r'DSA-\d+[\-\d]*\s+([a-z][\w.\-]+)\s+(\d[\d.:\-~+a-z]*)', 1, 2),
            (r'DLA-\d+[\-\d]*\s+([a-z][\w.\-]+)\s+(\d[\d.:\-~+a-z]*)', 1, 2),
            (r'(RH[SEBA]{2,3}-\d{4}:\d+)', 0, 1),
        ]

        desc_lower = description.lower()

        for pattern, pkg_group, ver_group in patterns:
            for match in re.findall(pattern, desc_lower, re.IGNORECASE):
                pkg_name = ""
                fix_ver = ""

                if pkg_group == 0:
                    fix_ver = match if isinstance(match, str) else match[0]
                elif pkg_group == ver_group:
                    fix_ver = match if isinstance(match, str) else match[0]
                    pkg_name = "*"
                else:
                    if isinstance(match, tuple) and len(match) == 2:
                        pkg_name = match[pkg_group - 1]
                        fix_ver = match[ver_group - 1]
                    elif isinstance(match, str):
                        fix_ver = match

                fix_ver = fix_ver.strip()
                if pkg_name:
                    pkg_name = pkg_name.strip().rstrip(".,;:!?)]}")
                    if not re.match(r'^[a-z]', pkg_name):
                        continue
                    if pkg_name in STOP_WORDS:
                        continue

                if not fix_ver or not re.search(r'\d', fix_ver):
                    continue

                if re.match(r'^RH[SEBA]{2,3}-\d{4}:\d+$', fix_ver, re.IGNORECASE):
                    fix_ver = fix_ver.upper()

                if pkg_name and re.search(r'^\d+$', pkg_name) and len(pkg_name) < 20:
                    continue

                if pkg_name and pkg_name != "*":
                    extracted[pkg_name] = fix_ver
                elif fix_ver:
                    existing = extracted.get("*", "")
                    if len(fix_ver) > len(existing) or not existing:
                        extracted["*"] = fix_ver

        return extracted


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
        self.fix_db = FixVersionDatabase(config.db_dir / "fix_versions.json")
        self.fix_db.load()

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
        meta = {"last_updated": datetime.now().isoformat()}
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
            cpe_match_details: List[CPEMatchDetail] = []
            affected_vendors: Set[str] = set()
            affected_products: Set[str] = set()

            configurations = cve_data.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_match_list = node.get("cpeMatch", [])
                    for cpe_match in cpe_match_list:
                        criteria = cpe_match.get("criteria", "")
                        if not criteria:
                            continue
                        vulnerable = cpe_match.get("vulnerable", True)
                        cpe_matches.append(criteria)
                        parts = criteria.split(":")
                        vendor_part = parts[3] if len(parts) > 3 else ""
                        product_part = parts[4] if len(parts) > 4 else ""
                        version_part = parts[5] if len(parts) > 5 else "*"
                        if vendor_part and vendor_part != "*":
                            affected_vendors.add(vendor_part)
                        if product_part and product_part != "*":
                            affected_products.add(product_part)
                        version_range = VersionRange(
                            start_including=cpe_match.get("versionStartIncluding"),
                            start_excluding=cpe_match.get("versionStartExcluding"),
                            end_including=cpe_match.get("versionEndIncluding"),
                            end_excluding=cpe_match.get("versionEndExcluding"),
                        )
                        detail = CPEMatchDetail(
                            criteria=criteria,
                            vulnerable=vulnerable,
                            version_range=version_range,
                            vendor=vendor_part,
                            product=product_part,
                            cpe_version_fragment=version_part,
                        )
                        cpe_match_details.append(detail)

            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            fix_versions = self.fix_db.extract_from_cve_description(cve_id, description)

            for ref_url in references:
                if "security-tracker.debian.org" in ref_url:
                    from urllib.parse import unquote
                    decoded = unquote(ref_url)
                    pkg_match = re.search(r'/tracker/([a-zA-Z0-9._\-+]+)', decoded)
                    if pkg_match:
                        pkg_name = pkg_match.group(1)
                        ver_match = re.search(r'version[=\-](\d[\d.:\-~+a-zA-Z]*)', decoded, re.IGNORECASE)
                        if ver_match and pkg_name not in fix_versions:
                            fix_versions[pkg_name] = ver_match.group(1)
                if "access.redhat.com/errata" in ref_url:
                    decoded = ref_url
                    try:
                        from urllib.parse import unquote
                        decoded = unquote(ref_url)
                    except Exception:
                        pass
                    rhsa_match = re.search(r'(RH[SEBA]{2,3}-\d{4}:\d+)', decoded)
                    if rhsa_match:
                        advisory = rhsa_match.group(1)
                        if "*" not in fix_versions:
                            fix_versions["*"] = advisory

            cleaned_fix: Dict[str, str] = {}
            for pkg, ver in fix_versions.items():
                if not ver or not re.search(r'\d', ver):
                    continue
                if pkg != "*" and re.match(r'^[\d.]+$', pkg) and len(pkg) < 20:
                    continue
                cleaned_fix[pkg] = ver
                if pkg != "*":
                    existing = self.fix_db._fix_data.get(pkg, {})
                    if ver not in existing.values():
                        existing["<=" + ver] = ver
                        self.fix_db._fix_data[pkg] = existing

            entry = VulnerabilityEntry(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3,
                cvss_v2_score=cvss_v2,
                severity=severity,
                published_date=published,
                last_modified_date=modified,
                cpe_matches=cpe_matches,
                cpe_match_details=cpe_match_details,
                affected_vendors=affected_vendors,
                affected_products=affected_products,
                references=references,
                fixed_versions=cleaned_fix,
            )
            self._entries[cve_id] = entry
            self._index_entry(entry)

        self.fix_db.save()

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