import gzip
import io
import json
import os
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

    RPM_DB_SQLITE_PATHS = [
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

    CENTOS_RELEASE_PATHS = [
        "etc/centos-release",
        "./etc/centos-release",
        "etc/redhat-release",
        "./etc/redhat-release",
        "etc/system-release",
        "./etc/system-release",
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
                    if not self._distro_info:
                        self._detect_centos_release(tar)
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

    def _detect_centos_release(self, tar: tarfile.TarFile) -> None:
        for path in self.CENTOS_RELEASE_PATHS:
            try:
                member = tar.getmember(path)
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode("utf-8", errors="replace").strip()
                    distro_id = ""
                    if "CentOS" in content:
                        distro_id = "centos"
                    elif any(x in content for x in ("Red Hat", "RHEL", "rhel")):
                        distro_id = "rhel"
                    elif "Fedora" in content:
                        distro_id = "fedora"
                    elif "Rocky" in content:
                        distro_id = "rocky"
                    elif "AlmaLinux" in content:
                        distro_id = "almalinux"

                    version_match = re.search(r'(\d+\.?\d*)', content)
                    version_id = version_match.group(1) if version_match else ""

                    self._distro_info = {"ID": distro_id, "VERSION_ID": version_id}
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
        for path in self.RPM_DB_SQLITE_PATHS:
            try:
                member = tar.getmember(path)
                f = tar.extractfile(member)
                if f:
                    content = f.read()
                    pkgs = self._parse_rpmdb_sqlite(content, layer_order)
                    if pkgs:
                        return pkgs
            except (KeyError, tarfile.TarError):
                continue

        pkgs = self._extract_rpm_berkeley(tar, layer_order)
        if pkgs:
            return pkgs

        return []

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

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            target_table = None
            for tbl in tables:
                tbl_lower = tbl.lower()
                if tbl_lower == "packages":
                    target_table = tbl
                    break

            if target_table is None:
                for tbl in tables:
                    tbl_lower = tbl.lower()
                    if "package" in tbl_lower or "rpm" in tbl_lower:
                        target_table = tbl
                        break

            if target_table is None:
                conn.close()
                return packages

            columns = self._get_table_columns(cursor, target_table)

            name_col = None
            version_col = None
            release_col = None
            arch_col = None
            epoch_col = None

            for col in columns:
                cl = col.lower()
                if cl == "name" or cl == "pkgname":
                    name_col = col
                elif cl == "version" or cl == "pkgversion":
                    version_col = col
                elif cl == "release" or cl == "pkgrelease":
                    release_col = col
                elif cl == "arch" or cl == "architecture" or cl == "pkgarch":
                    arch_col = col
                elif cl == "epoch" or cl == "pkgepoch":
                    epoch_col = col

            if name_col is None:
                conn.close()
                return packages

            select_cols = [name_col]
            col_map = {name_col: "name"}
            if version_col:
                select_cols.append(version_col)
                col_map[version_col] = "version"
            if release_col:
                select_cols.append(release_col)
                col_map[release_col] = "release"
            if arch_col:
                select_cols.append(arch_col)
                col_map[arch_col] = "arch"
            if epoch_col:
                select_cols.append(epoch_col)
                col_map[epoch_col] = "epoch"

            query = f"SELECT {', '.join(select_cols)} FROM [{target_table}]"
            cursor.execute(query)

            for row in cursor.fetchall():
                values = {}
                for i, col in enumerate(select_cols):
                    key = col_map[col]
                    values[key] = str(row[i]) if row[i] is not None else ""

                name = values.get("name", "")
                if not name:
                    continue

                version = values.get("version", "")
                release = values.get("release", "")
                arch = values.get("arch", "")
                epoch = values.get("epoch", "")

                full_version = version
                if release:
                    full_version = f"{version}-{release}"

                packages.append(InstalledPackage(
                    name=name,
                    version=full_version,
                    release=release,
                    architecture=arch,
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

    def _get_table_columns(self, cursor, table_name: str) -> List[str]:
        try:
            cursor.execute(f"PRAGMA table_info('{table_name}')")
            return [row[1] for row in cursor.fetchall()]
        except Exception:
            return []

    def _extract_rpm_berkeley(self, tar: tarfile.TarFile, layer_order: int) -> List[InstalledPackage]:
        packages = []
        rpm_dir_candidates = ["var/lib/rpm", "./var/lib/rpm"]

        for rpm_dir in rpm_dir_candidates:
            try:
                names_content = None
                for suffix in ["/Name", "/Packages"]:
                    try:
                        member = tar.getmember(rpm_dir + suffix)
                        f = tar.extractfile(member)
                        if f:
                            content = f.read()
                            if suffix == "/Name":
                                names_content = content
                            elif suffix == "/Packages":
                                packages = self._parse_rpm_packages_raw(content, layer_order)
                                if packages:
                                    return packages
                    except (KeyError, tarfile.TarError):
                        continue
            except tarfile.TarError:
                continue

        return packages

    def _parse_rpm_packages_raw(self, content: bytes, layer_order: int) -> List[InstalledPackage]:
        packages = []
        seen = set()

        try:
            entries = re.split(rb'(?:\x00\x00\x00\x08)', content)

            for entry in entries:
                name = _extract_rpm_binary_field(entry, b'Name') or _extract_rpm_binary_field(entry, b'NAME')
                if not name:
                    continue

                if not name.isprintable() or len(name) > 200:
                    continue

                version = _extract_rpm_binary_field(entry, b'Version') or _extract_rpm_binary_field(entry, b'VERSION')
                release = _extract_rpm_binary_field(entry, b'Release') or _extract_rpm_binary_field(entry, b'RELEASE')
                arch = _extract_rpm_binary_field(entry, b'Arch') or _extract_rpm_binary_field(entry, b'ARCH')

                full_version = (version or "")
                if release:
                    full_version = f"{version}-{release}"

                key = (name, full_version)
                if key in seen:
                    continue
                seen.add(key)

                packages.append(InstalledPackage(
                    name=name,
                    version=full_version,
                    release=release or "",
                    architecture=arch or "",
                    package_manager="rpm",
                    layer_order=layer_order,
                    source_name=name,
                    distro="rhel",
                ))
        except Exception:
            pass

        return packages

    def get_package_summary(self, packages: List[InstalledPackage]) -> Dict[str, object]:
        managers = {}
        for pkg in packages:
            pm = pkg.package_manager
            if pm not in managers:
                managers[pm] = 0
            managers[pm] += 1
        rpm_count = sum(1 for p in packages if p.package_manager == "rpm")
        return {
            "total_packages": len(packages),
            "package_managers": managers,
            "distro": self.get_distro_id(),
            "distro_version": self.get_distro_version(),
        }


def _extract_rpm_binary_field(data: bytes, field_name: bytes) -> Optional[str]:
    prefix = field_name + b'\x00'
    idx = data.find(prefix)
    if idx == -1:
        return None

    start = idx + len(prefix)
    while start < len(data) and data[start:start+1] == b'\x00':
        start += 1

    end = data.find(b'\x00', start)
    if end == -1:
        end = len(data)

    value = data[start:end]
    try:
        decoded = value.decode("utf-8", errors="replace").strip("\x00")
        if decoded and len(decoded) > 0:
            return decoded
    except Exception:
        pass

    return None