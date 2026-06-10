import hashlib
import re

from typing import List, Tuple, Union


def _split_debian_tilde(v: str) -> List[str]:
    if '~' not in v:
        return [v]
    return v.split('~')


def _segment_version(v: str) -> List[Union[int, str]]:
    segments: List[Union[int, str]] = []
    for seg in re.split(r'[.\-_:+]', v):
        if not seg:
            continue
        for part in re.findall(r'(\d+|\D+)', seg):
            if part.isdigit():
                segments.append(int(part))
            else:
                segments.append(part)
    return segments


def _version_compare_segments(a: str, b: str) -> int:
    if a == b:
        return 0

    ca = _segment_version(a)
    cb = _segment_version(b)

    for i in range(min(len(ca), len(cb))):
        va, vb = ca[i], cb[i]
        if type(va) is not type(vb):
            return -1 if isinstance(va, int) else 1
        if va < vb:
            return -1
        if va > vb:
            return 1

    if len(ca) < len(cb):
        return -1
    if len(ca) > len(cb):
        return 1
    return 0


def version_compare(a: str, b: str) -> int:
    if a == b:
        return 0

    a_epoch, a_rest = _split_epoch(a)
    b_epoch, b_rest = _split_epoch(b)

    try:
        ae = int(a_epoch)
        be = int(b_epoch)
    except (ValueError, TypeError):
        ae = 0
        be = 0

    if ae != be:
        return -1 if ae < be else 1

    a_parts = _split_debian_tilde(a_rest)
    b_parts = _split_debian_tilde(b_rest)

    a_has_tilde = len(a_parts) > 1
    b_has_tilde = len(b_parts) > 1

    base_cmp = _version_compare_segments(a_parts[0], b_parts[0])
    if base_cmp != 0:
        return base_cmp

    if a_has_tilde and not b_has_tilde:
        return -1
    if not a_has_tilde and b_has_tilde:
        return 1

    for i in range(1, min(len(a_parts), len(b_parts))):
        seg_cmp = _version_compare_segments(a_parts[i], b_parts[i])
        if seg_cmp != 0:
            return seg_cmp

    if len(a_parts) < len(b_parts):
        return -1
    if len(a_parts) > len(b_parts):
        return 1

    return 0


def _split_epoch(v: str) -> Tuple[str, str]:
    if ":" in v and re.match(r'^\d+:', v):
        parts = v.split(":", 1)
        return parts[0], parts[1]
    return "0", v


def version_lt(a: str, b: str) -> bool:
    return version_compare(a, b) < 0


def version_le(a: str, b: str) -> bool:
    return version_compare(a, b) <= 0


def version_gt(a: str, b: str) -> bool:
    return version_compare(a, b) > 0


def version_ge(a: str, b: str) -> bool:
    return version_compare(a, b) >= 0


def version_eq(a: str, b: str) -> bool:
    return version_compare(a, b) == 0


def sha256_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w\-_\.]", "_", name)