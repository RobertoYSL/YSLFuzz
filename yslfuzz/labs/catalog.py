"""Lab pack catalog discovery."""

from pathlib import Path

from yslfuzz.labs.loader import LabManifestLoader
from yslfuzz.models.lab import LabManifest


class LabCatalogError(ValueError):
    """Raised when discovered lab catalog entries are inconsistent."""


class LabCatalog:
    """Discover and validate local lab pack manifests."""

    @classmethod
    def discover(cls, root_path: str | Path | None = None) -> list[LabManifest]:
        """Return lab manifests below a root path sorted by lab_id."""
        root = Path(root_path) if root_path is not None else cls.default_root()
        manifests = LabManifestLoader().load_directory(root)
        ordered = sorted(manifests, key=lambda manifest: (manifest.lab_id, manifest.lab_version))
        cls.validate_consistency(ordered)
        return ordered

    @classmethod
    def validate_consistency(cls, manifests: list[LabManifest]) -> None:
        """Require stable catalog identity fields."""
        seen: set[str] = set()
        for manifest in manifests:
            if manifest.lab_id in seen:
                raise LabCatalogError(f"Duplicate lab_id in catalog: {manifest.lab_id}")
            seen.add(manifest.lab_id)

    @classmethod
    def default_root(cls) -> Path:
        """Return the repository-relative default lab catalog root."""
        return Path.cwd() / "examples" / "labs"
