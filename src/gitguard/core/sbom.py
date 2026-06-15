from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from gitguard.core.auditor import DependencyAuditor


class SBOMGenerator:
    """Generates Software Bill of Materials (SBOM) in CycloneDX format."""

    def __init__(self, project_path: str | Path) -> None:
        self.project_path = Path(project_path).resolve()

    def generate_cyclonedx(self) -> str:
        auditor = DependencyAuditor()
        audit_result = auditor.audit_project(self.project_path)

        components: list[dict[str, Any]] = []
        for dep in audit_result.dependencies:
            component: dict[str, Any] = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "scope": "required" if dep.is_direct else "optional",
            }

            purl = self._get_purl(dep)
            if purl:
                component["purl"] = purl

            if dep.is_vulnerable:
                component["properties"] = [
                    {
                        "name": "gitguard:vulnerable",
                        "value": "true"
                    }
                ]

            components.append(component)

        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "gitguard",
                        "name": "gitguard",
                        "version": "0.1.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self.project_path.name,
                }
            },
            "components": components
        }

        return json.dumps(bom, indent=2)

    def generate_spdx(self) -> str:
        auditor = DependencyAuditor()
        audit_result = auditor.audit_project(self.project_path)

        packages: list[dict[str, Any]] = []
        for _i, dep in enumerate(audit_result.dependencies, start=1):
            package: dict[str, Any] = {
                "SPDXID": f"SPDXRef-Package-{dep.name}",
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }

            if dep.is_vulnerable:
                package["externalRefs"] = [
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": f"cpe:2.3:a:{dep.name}:{dep.name}:{dep.version}:*:*:*:*:*:*:*"
                    }
                ]

            packages.append(package)

        document: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.project_path.name,
            "documentNamespace": f"https://github.com/gitguard/{self.project_path.name}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": ["Tool: gitguard-0.1.0"],
                "licenseListVersion": "3.19"
            },
            "packages": packages
        }

        return json.dumps(document, indent=2)

    def save_sbom(self, output_path: str | Path, format: str = "cyclonedx") -> Path:
        path = Path(output_path)

        if format == "cyclonedx":
            content = self.generate_cyclonedx()
            suffix = ".json"
        elif format == "spdx":
            content = self.generate_spdx()
            suffix = ".json"
        else:
            raise ValueError(f"Unknown format: {format}")

        if not path.suffix:
            path = path.with_suffix(suffix)

        path.write_text(content)
        return path

    def _get_purl(self, dep: Any) -> str | None:
        ecosystem_map = {
            "pypi": "pkg:pypi",
            "npm": "pkg:npm",
            "cargo": "pkg:cargo",
            "go": "pkg:golang",
        }

        prefix = ecosystem_map.get(dep.ecosystem)
        if not prefix:
            return None

        name = dep.name.lower().replace("_", "-")
        return f"{prefix}/{name}@{dep.version}"
