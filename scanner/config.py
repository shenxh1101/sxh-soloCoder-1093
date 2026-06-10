import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ScannerConfig:
    db_dir: Path = Path.home() / ".container_scanner" / "vuln_db"
    ignore_file: Path = Path.home() / ".container_scanner" / "ignore_list.json"
    nvd_feed_url: str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
    nvd_modified_url: str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
    nvd_start_year: int = 2002
    offline_mode: bool = False
    temp_dir: Optional[Path] = None
    mirror_url: Optional[str] = None
    _ignore_list: Dict[str, List[str]] = field(default_factory=dict)

    def load_ignore_list(self) -> Dict[str, List[str]]:
        if self.ignore_file.exists():
            try:
                with open(self.ignore_file, "r", encoding="utf-8") as f:
                    self._ignore_list = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._ignore_list = {}
        return self._ignore_list

    def save_ignore_list(self) -> None:
        self.ignore_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ignore_file, "w", encoding="utf-8") as f:
            json.dump(self._ignore_list, f, indent=2, ensure_ascii=False)

    def ignore_cve(self, cve_id: str, reason: str = "") -> None:
        self._ignore_list[cve_id] = {
            "reason": reason,
            "ignored_at": ""
        }
        self.save_ignore_list()

    def unignore_cve(self, cve_id: str) -> None:
        if cve_id in self._ignore_list:
            del self._ignore_list[cve_id]
            self.save_ignore_list()

    def is_ignored(self, cve_id: str) -> bool:
        return cve_id in self._ignore_list

    def get_ignored_cves(self) -> List[str]:
        return list(self._ignore_list.keys())