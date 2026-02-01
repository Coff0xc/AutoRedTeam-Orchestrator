#!/usr/bin/env python3
"""
SBOM (Software Bill of Materials) 生成器
支持: CycloneDX, SPDX, Simple格式
覆盖: Python (requirements.txt, Pipfile, pyproject.toml)
      Node.js (package.json, package-lock.json)
      Go (go.mod)
作者: AutoRedTeam
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SBOMFormat(Enum):
    """SBOM格式"""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    SIMPLE = "simple"


class PackageEcosystem(Enum):
    """包生态系统"""

    PYPI = "pypi"
    NPM = "npm"
    GO = "go"
    MAVEN = "maven"
    CARGO = "cargo"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """依赖信息"""

    name: str
    version: str
    ecosystem: PackageEcosystem
    license: str = ""
    purl: str = ""  # Package URL
    hashes: Dict[str, str] = field(default_factory=dict)
    direct: bool = True
    dev_dependency: bool = False
    file_path: str = ""


@dataclass
class SBOMDocument:
    """SBOM文档"""

    format: SBOMFormat
    project_name: str
    project_version: str
    dependencies: List[Dependency]
    created_at: str
    tool_name: str = "AutoRedTeam-SBOM"
    tool_version: str = "1.0.0"
    serial_number: str = ""


class SBOMGenerator:
    """SBOM生成器"""

    # 依赖文件模式
    DEPENDENCY_FILES = {
        PackageEcosystem.PYPI: [
            "requirements.txt",
            "requirements*.txt",
            "Pipfile",
            "Pipfile.lock",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
        ],
        PackageEcosystem.NPM: ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        PackageEcosystem.GO: ["go.mod", "go.sum"],
        PackageEcosystem.MAVEN: ["pom.xml"],
        PackageEcosystem.CARGO: ["Cargo.toml", "Cargo.lock"],
    }

    def __init__(self, project_path: str):
        """
        初始化SBOM生成器

        Args:
            project_path: 项目根目录路径
        """
        self.project_path = Path(project_path)
        self._dependencies: List[Dependency] = []
        self._detected_ecosystems: List[PackageEcosystem] = []

    def detect_ecosystems(self) -> List[PackageEcosystem]:
        """
        检测项目使用的包生态系统

        Returns:
            检测到的生态系统列表
        """
        ecosystems = []

        for ecosystem, files in self.DEPENDENCY_FILES.items():
            for file_pattern in files:
                if "*" in file_pattern:
                    matches = list(self.project_path.glob(file_pattern))
                else:
                    matches = [self.project_path / file_pattern]

                for match in matches:
                    if match.exists():
                        if ecosystem not in ecosystems:
                            ecosystems.append(ecosystem)
                        break

        self._detected_ecosystems = ecosystems
        return ecosystems

    def _generate_purl(self, name: str, version: str, ecosystem: PackageEcosystem) -> str:
        """
        生成Package URL

        格式: pkg:type/namespace/name@version
        """
        type_map = {
            PackageEcosystem.PYPI: "pypi",
            PackageEcosystem.NPM: "npm",
            PackageEcosystem.GO: "golang",
            PackageEcosystem.MAVEN: "maven",
            PackageEcosystem.CARGO: "cargo",
        }

        pkg_type = type_map.get(ecosystem, "generic")
        # 清理名称
        clean_name = name.lower().replace("_", "-")

        return f"pkg:{pkg_type}/{clean_name}@{version}"

    def parse_requirements_txt(self, file_path: Optional[Path] = None) -> List[Dependency]:
        """解析Python requirements.txt"""
        dependencies = []

        if file_path is None:
            file_path = self.project_path / "requirements.txt"

        if not file_path.exists():
            return dependencies

        try:
            content = file_path.read_text(encoding="utf-8")

            for line in content.splitlines():
                line = line.strip()

                # 跳过注释和空行
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # 解析包名和版本
                # 支持格式: package==1.0.0, package>=1.0.0, package~=1.0.0
                match = re.match(r"^([a-zA-Z0-9_-]+)\s*([><=~!]+)?\s*([0-9a-zA-Z._-]+)?", line)

                if match:
                    name = match.group(1)
                    version = match.group(3) or "unknown"

                    dep = Dependency(
                        name=name,
                        version=version,
                        ecosystem=PackageEcosystem.PYPI,
                        purl=self._generate_purl(name, version, PackageEcosystem.PYPI),
                        file_path=str(file_path),
                    )
                    dependencies.append(dep)

        except Exception as e:
            logger.error(f"解析requirements.txt失败: {e}")

        return dependencies

    def parse_package_json(self, file_path: Optional[Path] = None) -> List[Dependency]:
        """解析Node.js package.json"""
        dependencies = []

        if file_path is None:
            file_path = self.project_path / "package.json"

        if not file_path.exists():
            return dependencies

        try:
            content = json.loads(file_path.read_text(encoding="utf-8"))

            # 生产依赖
            for name, version in content.get("dependencies", {}).items():
                # 清理版本号 (移除 ^, ~, >= 等前缀)
                clean_version = re.sub(r"^[\^~>=<]+", "", version)

                dep = Dependency(
                    name=name,
                    version=clean_version,
                    ecosystem=PackageEcosystem.NPM,
                    purl=self._generate_purl(name, clean_version, PackageEcosystem.NPM),
                    direct=True,
                    dev_dependency=False,
                    file_path=str(file_path),
                )
                dependencies.append(dep)

            # 开发依赖
            for name, version in content.get("devDependencies", {}).items():
                clean_version = re.sub(r"^[\^~>=<]+", "", version)

                dep = Dependency(
                    name=name,
                    version=clean_version,
                    ecosystem=PackageEcosystem.NPM,
                    purl=self._generate_purl(name, clean_version, PackageEcosystem.NPM),
                    direct=True,
                    dev_dependency=True,
                    file_path=str(file_path),
                )
                dependencies.append(dep)

        except Exception as e:
            logger.error(f"解析package.json失败: {e}")

        return dependencies

    def parse_go_mod(self, file_path: Optional[Path] = None) -> List[Dependency]:
        """解析Go go.mod"""
        dependencies = []

        if file_path is None:
            file_path = self.project_path / "go.mod"

        if not file_path.exists():
            return dependencies

        try:
            content = file_path.read_text(encoding="utf-8")

            # 解析require块
            in_require = False
            for line in content.splitlines():
                line = line.strip()

                if line.startswith("require ("):
                    in_require = True
                    continue
                elif line == ")":
                    in_require = False
                    continue

                if in_require or line.startswith("require "):
                    # 移除 require 前缀
                    if line.startswith("require "):
                        line = line[8:]

                    # 解析: module/path v1.0.0
                    match = re.match(r"^([^\s]+)\s+(v[0-9.]+)", line)
                    if match:
                        name = match.group(1)
                        version = match.group(2)

                        dep = Dependency(
                            name=name,
                            version=version,
                            ecosystem=PackageEcosystem.GO,
                            purl=self._generate_purl(name, version, PackageEcosystem.GO),
                            file_path=str(file_path),
                        )
                        dependencies.append(dep)

        except Exception as e:
            logger.error(f"解析go.mod失败: {e}")

        return dependencies

    def parse_pyproject_toml(self, file_path: Optional[Path] = None) -> List[Dependency]:
        """解析Python pyproject.toml"""
        dependencies = []

        if file_path is None:
            file_path = self.project_path / "pyproject.toml"

        if not file_path.exists():
            return dependencies

        try:
            content = file_path.read_text(encoding="utf-8")

            # 简单的TOML解析 (dependencies部分)
            in_dependencies = False
            for line in content.splitlines():
                line = line.strip()

                if line == "[project.dependencies]" or line == "dependencies = [":
                    in_dependencies = True
                    continue
                elif line.startswith("[") and in_dependencies:
                    in_dependencies = False
                    continue

                if in_dependencies:
                    # 解析: "package>=1.0.0",
                    match = re.match(r'"([a-zA-Z0-9_-]+)\s*([><=~!]+)?\s*([0-9.]+)?"', line)
                    if match:
                        name = match.group(1)
                        version = match.group(3) or "unknown"

                        dep = Dependency(
                            name=name,
                            version=version,
                            ecosystem=PackageEcosystem.PYPI,
                            purl=self._generate_purl(name, version, PackageEcosystem.PYPI),
                            file_path=str(file_path),
                        )
                        dependencies.append(dep)

        except Exception as e:
            logger.error(f"解析pyproject.toml失败: {e}")

        return dependencies

    def scan_all(self) -> List[Dependency]:
        """
        扫描所有依赖文件

        Returns:
            所有发现的依赖列表
        """
        all_deps = []

        # 检测生态系统
        ecosystems = self.detect_ecosystems()

        # Python
        if PackageEcosystem.PYPI in ecosystems:
            # requirements.txt
            for req_file in self.project_path.glob("requirements*.txt"):
                all_deps.extend(self.parse_requirements_txt(req_file))

            # pyproject.toml
            all_deps.extend(self.parse_pyproject_toml())

        # Node.js
        if PackageEcosystem.NPM in ecosystems:
            all_deps.extend(self.parse_package_json())

        # Go
        if PackageEcosystem.GO in ecosystems:
            all_deps.extend(self.parse_go_mod())

        # 去重
        seen = set()
        unique_deps = []
        for dep in all_deps:
            key = (dep.name, dep.version, dep.ecosystem)
            if key not in seen:
                seen.add(key)
                unique_deps.append(dep)

        self._dependencies = unique_deps
        return unique_deps

    def _to_cyclonedx(self, deps: List[Dependency], project_name: str) -> Dict[str, Any]:
        """转换为CycloneDX格式"""
        components = []

        for dep in deps:
            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": dep.purl,
            }

            if dep.license:
                component["licenses"] = [{"license": {"id": dep.license}}]

            if dep.hashes:
                component["hashes"] = [
                    {"alg": alg, "content": value} for alg, value in dep.hashes.items()
                ]

            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [{"vendor": "AutoRedTeam", "name": "SBOM Generator", "version": "1.0.0"}],
                "component": {"type": "application", "name": project_name},
            },
            "components": components,
        }

    def _to_spdx(self, deps: List[Dependency], project_name: str) -> Dict[str, Any]:
        """转换为SPDX格式"""
        packages = []

        for i, dep in enumerate(deps):
            package = {
                "SPDXID": f"SPDXRef-Package-{i+1}",
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }

            if dep.purl:
                package["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dep.purl,
                    }
                ]

            packages.append(package)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": project_name,
            "documentNamespace": f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: AutoRedTeam-SBOM-1.0.0"],
            },
            "packages": packages,
        }

    def _to_simple(self, deps: List[Dependency]) -> Dict[str, Any]:
        """转换为简单格式"""
        return {
            "total": len(deps),
            "ecosystems": list(set(d.ecosystem.value for d in deps)),
            "dependencies": [
                {
                    "name": d.name,
                    "version": d.version,
                    "ecosystem": d.ecosystem.value,
                    "purl": d.purl,
                    "dev": d.dev_dependency,
                    "file": d.file_path,
                }
                for d in deps
            ],
        }

    def generate(
        self, format: SBOMFormat = SBOMFormat.CYCLONEDX, project_name: str = ""
    ) -> Dict[str, Any]:
        """
        生成SBOM

        Args:
            format: 输出格式
            project_name: 项目名称

        Returns:
            SBOM文档字典
        """
        if not self._dependencies:
            self.scan_all()

        if not project_name:
            project_name = self.project_path.name

        if format == SBOMFormat.CYCLONEDX:
            return self._to_cyclonedx(self._dependencies, project_name)
        elif format == SBOMFormat.SPDX:
            return self._to_spdx(self._dependencies, project_name)
        else:
            return self._to_simple(self._dependencies)

    def get_summary(self) -> Dict[str, Any]:
        """获取SBOM摘要"""
        if not self._dependencies:
            self.scan_all()

        ecosystem_counts = {}
        for dep in self._dependencies:
            eco = dep.ecosystem.value
            ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + 1

        dev_count = sum(1 for d in self._dependencies if d.dev_dependency)

        return {
            "total_dependencies": len(self._dependencies),
            "production_dependencies": len(self._dependencies) - dev_count,
            "dev_dependencies": dev_count,
            "ecosystems": ecosystem_counts,
            "detected_files": [str(f) for f in self._detected_ecosystems],
        }


# 便捷函数
def generate_sbom(project_path: str, format: str = "cyclonedx") -> Dict[str, Any]:
    """快速生成SBOM"""
    generator = SBOMGenerator(project_path)
    fmt = SBOMFormat(format.lower())
    return generator.generate(fmt)


if __name__ == "__main__":
    # 测试示例
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = "."

    generator = SBOMGenerator(path)

    # 检测生态系统
    ecosystems = generator.detect_ecosystems()
    logger.info(f"检测到的生态系统: {[e.value for e in ecosystems]}")

    # 生成SBOM
    sbom = generator.generate(SBOMFormat.SIMPLE)
    logger.info(f"依赖总数: {sbom['total']}")
