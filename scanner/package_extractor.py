import gzip
import io
import json
import re
import sqlite3
import struct
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .image_parser import InstalledPackage


class PackageExtractor:
    APT_STATUS_PATHS = [
        "var/lib/dpkg/status",
        "./var/lib/dpkg/status",
    ]

    APK_DB_PATHS = [
        "lib/apk/db/installed",
        "./lib/apk/db/installed",
    ]

    RPM_DB_PATHS = [
        "var/lib/rpm/rpmdb.sqlite",
        "./var/lib/rpm/rpmdb.sqlite",
    ]

    RPM_DB_DIRS = [
        "var/lib/rpm/",
        "./var/lib/rpm/",
    ]

    OS_RELEASE_PATHS = [
        "etc/os-release",
        "./etc/os-release",
        "usr/lib/os-release",
        "./usr/lib/os-release",
    ]

    def __init__(self, temp_dir: Optional[Path] = None):
        self.temp_dir = temp_dir
        self._distro_info: Optional[Dict[str, str]] = None

    def extract_from_layer(self, layer_tar_path: Path, layer_order: int) -> List[InstalledPackage]:
        if not layer_tar_path.exists():
            return []

        packages = []
        try:
            with tarfile.open(layer_tar_path, "r:*") as tar:
                apt_packages = self._extract_apt(tar, layer_order)
                apk_packages = self._extract_apk(tar, layer_order)
                rpm_packages = self._extract_rpm(tar, layer_order)

                packages.extend(apt_packages)
                packages.extend(apk_packages)
                packages.extend(rpm_packages)

                if not self._distro_info:
                    self._detect_os_release(tar)
        except (tarfile.TarError, EOFError, OSError):
            pass

        return packages

    def extract_from_image(self, layer_paths: Dict[int, Path]) -> List[InstalledPackage]:
        all_packages: List[InstalledPackage] = []
        seen = set()

        for order in sorted(layer_paths.keys()):
            packages = self.extract_from_layer(layer_paths[order], order)
            for pkg in packages:
                key = (pkg.name, pkg.version, pkg.package_manager)
                if key not in seen:
                    seen.add(key)
                    all_packages.append(pkg)

        return all_packages

    def _detect_os_release(self, tar: tarfile.TarFile) -> None:
        for path in self.OS_RELEASE_PATHS:
            try:
                member = tar.getmember(path)
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="replace")
                    info = {}
                    for line in content.splitlines():
                        if "=" in line and not line.startswith("#"):
                            key, _, value = line.partition("=")
                            info[key.strip()] = value.strip().strip('"')
                    self._distro_info = info
                    return
            except (KeyError, UnicodeDecodeError):
                continue

    def get_distro_id(self) -> str:
        if self._distro_info:
            return self._distro_info.get("ID", "")
        return ""

    def get_distro_version(self) -> str:
        if self._distro_info:
            return self._distro_info.get("VERSION_ID", "")
        return ""

    def _extract_apt(self, tar: tarfile.TarFile, layer_order: int) -> List[InstalledPackage]:
        packages = []
        for path in self.APT_STATUS_PATHS:
            try:
                member = tar.getmember(path)
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="replace")
                    packages = self._parse_dpkg_status(content, layer_order)
                    if packages:
                        return packages
            except (KeyError, UnicodeDecodeError):
                continue
        return packages

    def _parse_dpkg_status(self, content: str, layer_order: int) -> List[InstalledPackage]:
        packages = []
        entries = content.split("\n\n")

        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue

            pkg_info: Dict[str, str] = {}
            for line in entry.splitlines():
                if ":" in line:
                    key, _, value = line.partition(":")
                    pkg_info[key.strip()] = value.strip()

            status = pkg_info.get("Status", "")
            if "deinstall" in status:
                continue

            pkg_name = pkg_info.get("Package", "")
            if not pkg_name:
                continue

            version = pkg_info.get("Version", "")
            architecture = pkg_info.get("Architecture", "")
            source = pkg_info.get("Source", pkg_name)

            source_name = source
            if " " in source:
                source_name = source.split(" ", 1)[0]

            packages.append(InstalledPackage(
                name=pkg_name,
                version=version,
                architecture=architecture,
                package_manager="apt",
                layer_order=layer_order,
                source_name=source_name,
                distro="debian",
            ))

        return packages

    def _extract_apk(self, tar: tarfile.TarFile, layer_order: int) -> List[InstalledPackage]:
        packages = []
        for path in self.APK_DB_PATHS:
            try:
                member = tar.getmember(path)
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="replace")
                    packages = self._parse_apk_installed(content, layer_order)
                    if packages:
                        return packages
            except (KeyError, UnicodeDecodeError):
                continue

        return packages

    def _parse_apk_installed(self, content: str, layer_order: int) -> List[InstalledPackage]:
        packages = []
        lines = content.splitlines()
        current_pkg: Dict[str, str] = {}

        for line in lines:
            line = line.strip()
            if not line:
                if current_pkg and "P" in current_pkg:
                    version = current_pkg.get("V", "")
                    architecture = current_pkg.get("A", "")
                    origin = current_pkg.get("o", current_pkg["P"])

                    packages.append(InstalledPackage(
                        name=current_pkg["P"],
                        version=version,
                        architecture=architecture,
                        package_manager="apk",
                        layer_order=layer_order,
                        source_name=origin,
                        distro="alpine",
                    ))
                current_pkg = {}
            elif ":" in line:
                key, _, value = line.partition(":")
                current_pkg[key.strip()] = value.strip()

        if current_pkg and "P" in current_pkg:
            version = current_pkg.get("V", "")
            architecture = current_pkg.get("A", "")
            origin = current_pkg.get("o", current_pkg["P"])
            packages.append(InstalledPackage(
                name=current_pkg["P"],
                version=version,
                architecture=architecture,
                package_manager="apk",
                layer_order=layer_order,
                source_name=origin,
                distro="alpine",
            ))

        return packages

    def _extract_rpm(self, tar: tarfile.TarFile, layer_order: int) -> List[InstalledPackage]:
        for path in self.RPM_DB_PATHS:
            try:
                member = tar.getmember(path)
                f = tar.extractfile(member)
                if f:
                    content = f.read()
                    return self._parse_rpmdb_sqlite(content, layer_order)
            except (KeyError, tarfile.TarError):
                continue

        return self._extract_rpm_berkeley(tar, layer_order)

    def _parse_rpmdb_sqlite(self, content: bytes, layer_order: int) -> List[InstalledPackage]:
        import tempfile

        packages = []
        tmp_path = None

        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".sqlite")
            with os.fdopen(fd, "wb") as fh:
                fh.write(content)

            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            table_query = "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%Name%' OR name LIKE '%Packages%'"
            cursor.execute(table_query)
            tables = [row[0] for row in cursor.fetchall()]

            if "Packages" in tables:
                query = "SELECT name, version, release, arch FROM Packages"
                cursor.execute(query)
                for row in cursor.fetchall():
                    name, version, release, arch = row[0], row[1] if len(row) > 1 else "", row[2] if len(row) > 2 else "", row[3] if len(row) > 3 else ""
                    packages.append(InstalledPackage(
                        name=name,
                        version=version or "",
                        release=release or "",
                        architecture=arch or "",
                        package_manager="rpm",
                        layer_order=layer_order,
                        source_name=name,
                        distro="rhel",
                    ))
            elif "Name" in tables:
                query = "SELECT name, version, release, arch FROM Name"
                cursor.execute(query)
                for row in cursor.fetchall():
                    name, version, release, arch = row[0], row[1] if len(row) > 1 else "", row[2] if len(row) > 2 else "", row[3] if len(row) > 3 else ""
                    packages.append(InstalledPackage(
                        name=name,
                        version=version or "",
                        release=release or "",
                        architecture=arch or "",
                        package_manager="rpm",
                        layer_order=layer_order,
                        source_name=name,
                        distro="rhel",
                    ))

            conn.close()
        except Exception:
            packages = []
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return packages

    def _extract_rpm_berkeley(self, tar: tarfile.TarFile, layer_order: int) -> List[InstalledPackage]:
        packages = []
        rpm_dir_candidates = ["var/lib/rpm", "./var/lib/rpm"]

        for rpm_dir in rpm_dir_candidates:
            try:
                members = [m for m in tar.getmembers() if m.name.startswith(rpm_dir) and m.isfile()]
                if not members:
                    continue

                name_entries: Dict[str, List[str]] = {}

                for member in members:
                    basename = member.name.rsplit("/", 1)[-1]
                    if not re.match(r'^[a-zA-Z]', basename):
                        continue

                break
            except tarfile.TarError:
                continue

        return packages

    def get_package_summary(self, packages: List[InstalledPackage]) -> Dict[str, object]:
        managers = {}
        for pkg in packages:
            pm = pkg.package_manager
            if pm not in managers:
                managers[pm] = 0
            managers[pm] += 1

        return {
            "total_packages": len(packages),
            "package_managers": managers,
            "distro": self.get_distro_id(),
            "distro_version": self.get_distro_version(),
        }


def _has_berkeleydb() -> bool:
    try:
        import bsddb3
        return True
    except ImportError:
        pass
    try:
        import berkeleydb
        return True
    except ImportError:
        pass
    return False