import hashlib
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Optional, Tuple


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_file_in_tar(tar: tarfile.TarFile, filename: str) -> Optional[bytes]:
    try:
        member = tar.getmember(filename)
        f = tar.extractfile(member)
        if f:
            return f.read()
    except KeyError:
        pass
    return None


def find_files_in_tar(tar: tarfile.TarFile, pattern: str) -> list:
    results = []
    regex = re.compile(pattern)
    for member in tar.getmembers():
        if member.isfile() and regex.search(member.name):
            f = tar.extractfile(member)
            if f:
                results.append((member.name, f.read()))
    return results


def normalize_distribution(name: str) -> str:
    name = name.lower()
    if name in ("debian", "ubuntu"):
        return "debian"
    if name in ("centos", "rhel", "fedora", "rocky", "almalinux", "oraclelinux"):
        return "rhel"
    if name in ("alpine",):
        return "alpine"
    return name


def split_package_version(version_str: str) -> Tuple[str, str]:
    epoch = "0"
    if ":" in version_str:
        epoch, version_str = version_str.split(":", 1)

    release = ""
    if "-" in version_str:
        parts = version_str.rsplit("-", 1)
        if len(parts) == 2 and re.match(r"^[\d]+", parts[1]):
            version_str, release = parts

    return f"{epoch}:{version_str}-{release}" if release else f"{epoch}:{version_str}"


def cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def cpe_match_package(cpe_uri: str, vendor: str, product: str, version: str) -> bool:
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return False

    cpe_vendor = parts[3].lower()
    cpe_product = parts[4].lower()
    cpe_version = parts[5] if len(parts) > 5 else "*"

    vendor_match = cpe_vendor == "*" or cpe_vendor == vendor.lower() or vendor.lower() in cpe_vendor or cpe_vendor in vendor.lower()
    product_match = cpe_product == "*" or cpe_product == product.lower() or product.lower() in cpe_product or cpe_product in product.lower()

    if not vendor_match or not product_match:
        return False

    if cpe_version == "*" or cpe_version == "-":
        return True

    return version_match(version, cpe_version)


def version_match(actual_version: str, affected_version: str) -> bool:
    from packaging import version as pkg_version

    try:
        actual = pkg_version.parse(actual_version)
    except pkg_version.InvalidVersion:
        return actual_version == affected_version

    affected_version = affected_version.strip()

    if affected_version.startswith("<="):
        target = pkg_version.parse(affected_version[2:].strip())
        return actual <= target
    elif affected_version.startswith(">="):
        target = pkg_version.parse(affected_version[2:].strip())
        return actual >= target
    elif affected_version.startswith("<"):
        target = pkg_version.parse(affected_version[1:].strip())
        return actual < target
    elif affected_version.startswith(">"):
        target = pkg_version.parse(affected_version[1:].strip())
        return actual > target

    try:
        target = pkg_version.parse(affected_version)
        return actual == target
    except pkg_version.InvalidVersion:
        return actual_version == affected_version


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w\-_\.]", "_", name)