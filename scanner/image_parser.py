import json
import os
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class Layer:
    layer_id: str
    diff_id: str
    tar_path: Path
    order: int
    size: int = 0
    packages: List["InstalledPackage"] = field(default_factory=list)


@dataclass
class ImageInfo:
    name: str
    tag: str
    architecture: str
    os_type: str
    layers: List[Layer] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    distro: str = ""
    distro_version: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.name}:{self.tag}"


@dataclass
class InstalledPackage:
    name: str
    version: str
    release: str = ""
    architecture: str = ""
    package_manager: str = ""
    layer_order: int = 0
    source_name: str = ""
    distro: str = ""

    @property
    def full_version(self) -> str:
        if self.release:
            return f"{self.version}-{self.release}"
        return self.version


class ImageParser:
    def __init__(self, image_path: str, temp_dir: Optional[Path] = None):
        self.image_path = Path(image_path)
        self.temp_dir = temp_dir or Path(tempfile.mkdtemp(prefix="scanner_"))
        self.image_info: Optional[ImageInfo] = None

    def parse(self) -> ImageInfo:
        if not self.image_path.exists():
            raise FileNotFoundError(f"Image file not found: {self.image_path}")

        if not tarfile.is_tarfile(self.image_path):
            raise ValueError(f"Not a valid tar file: {self.image_path}")

        with tarfile.open(self.image_path, "r") as tar:
            manifest_data = self._read_manifest(tar)
            if not manifest_data:
                raise ValueError("No manifest.json found in image tar")

            manifest = json.loads(manifest_data)
            if not manifest:
                raise ValueError("Empty manifest.json")

            config_data, config_path = self._read_config(tar, manifest[0])
            if not config_data:
                raise ValueError("Could not read image config")

            config = json.loads(config_data)

            image_info = self._build_image_info(manifest[0], config, tar)
            self.image_info = image_info
            return image_info

    def _read_manifest(self, tar: tarfile.TarFile) -> Optional[bytes]:
        try:
            member = tar.getmember("manifest.json")
            f = tar.extractfile(member)
            if f:
                return f.read()
        except KeyError:
            pass
        return None

    def _read_config(self, tar: tarfile.TarFile, manifest_entry: dict) -> Tuple[Optional[bytes], str]:
        config_path = manifest_entry.get("Config", "")
        try:
            member = tar.getmember(config_path)
            f = tar.extractfile(member)
            if f:
                return f.read(), config_path
        except KeyError:
            pass
        return None, config_path

    def _build_image_info(self, manifest_entry: dict, config: dict, tar: tarfile.TarFile) -> ImageInfo:
        config_image = config.get("config", {})
        labels = config_image.get("Labels", {}) or {}
        env_list = config_image.get("Env", []) or []

        env_dict = {}
        for env_var in env_list:
            if "=" in env_var:
                k, v = env_var.split("=", 1)
                env_dict[k] = v

        name = labels.get("org.opencontainers.image.ref.name", "")
        version = labels.get("org.opencontainers.image.version", "")

        if not name:
            name = labels.get("name", "")
        if not name:
            name = self.image_path.stem

        tag = version or "latest"

        architecture = config.get("architecture", "unknown")
        os_type = config.get("os", "linux")

        repo_tags = manifest_entry.get("RepoTags", [])
        if repo_tags and repo_tags[0]:
            full_tag = repo_tags[0]
            if ":" in full_tag:
                name, tag = full_tag.rsplit(":", 1)

        distro, distro_version = self._detect_distro(config, labels, env_dict)

        rootfs = config.get("rootfs", {})
        diff_ids = rootfs.get("diff_ids", [])

        layers = manifest_entry.get("Layers", [])

        image_info = ImageInfo(
            name=name,
            tag=tag,
            architecture=architecture,
            os_type=os_type,
            config=config,
            distro=distro,
            distro_version=distro_version,
        )

        for idx, (layer_file, diff_id) in enumerate(zip(layers, diff_ids)):
            layer_tar_path = self._extract_layer(tar, layer_file, idx)
            layer = Layer(
                layer_id=layer_file,
                diff_id=diff_id,
                tar_path=layer_tar_path,
                order=idx,
                size=layer_tar_path.stat().st_size if layer_tar_path.exists() else 0,
            )
            image_info.layers.append(layer)

        return image_info

    def _detect_distro(self, config: dict, labels: dict, env_dict: dict) -> Tuple[str, str]:
        distro = ""
        distro_version = ""

        variant = env_dict.get("ID", "")
        version_id = env_dict.get("VERSION_ID", "")

        if variant:
            distro = variant.lower().strip('"')
            distro_version = version_id.lower().strip('"') if version_id else ""

        if not distro:
            variant_labels = [
                "org.opencontainers.image.vendor",
                "org.label-schema.vendor",
                "distribution_id",
                "com.docker.compose.image",
            ]
            for label_key in variant_labels:
                if label_key in labels and labels[label_key]:
                    val = labels[label_key].lower()
                    for candidate in ("debian", "ubuntu", "alpine", "centos", "rhel", "fedora"):
                        if candidate in val:
                            distro = candidate
                            break
                if distro:
                    break

        return distro, distro_version

    def _extract_layer(self, tar: tarfile.TarFile, layer_file: str, index: int) -> Path:
        extract_dir = self.temp_dir / f"layer_{index}"
        extract_dir.mkdir(parents=True, exist_ok=True)

        extracted_path = extract_dir / "layer.tar"

        try:
            member = tar.getmember(layer_file)
            member.name = os.path.basename(layer_file)
            tar.extract(member, path=str(extract_dir))
        except (KeyError, OSError):
            pass

        if not extracted_path.exists():
            alt_paths = [
                extract_dir / os.path.basename(layer_file),
                extract_dir / layer_file.replace("/", "_"),
            ]
            for alt in alt_paths:
                if alt.exists():
                    return alt

        return extracted_path

    def cleanup(self) -> None:
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(str(self.temp_dir), ignore_errors=True)