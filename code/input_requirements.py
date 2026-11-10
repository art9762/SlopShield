"""Parse registry requirements without silently dropping unaudited inputs."""

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name


def package_name(value: str) -> str:
    try:
        requirement = Requirement(value)
    except InvalidRequirement as exc:
        raise ValueError(f"Invalid PyPI requirement: {value!r}") from exc
    if requirement.url:
        raise ValueError("Direct URL requirements cannot be audited against PyPI")
    return canonicalize_name(requirement.name)


def parse_requirements_file(filepath: str) -> list[str]:
    path = Path(filepath)
    packages = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Cannot read requirements file {path}: {exc}") from exc
    for number, line in enumerate(lines, 1):
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            packages.append(package_name(line))
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from exc
    return packages
