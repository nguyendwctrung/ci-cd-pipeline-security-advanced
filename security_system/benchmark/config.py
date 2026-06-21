"""Load and validate benchmark repository metadata."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from security_system.benchmark.models import RepoSpec

try:  # pragma: no cover - exercised only when PyYAML is installed.
    import yaml
except ModuleNotFoundError:  # pragma: no cover - fallback is covered instead.
    yaml = None


def load_repos(path: Path) -> list[RepoSpec]:
    """Load benchmark repository specs from repos.yaml."""
    with path.open("r", encoding="utf-8") as handle:
        content = handle.read()
    data = _load_yaml(content)
    entries = data.get("repositories")
    if not isinstance(entries, list):
        raise ValueError("repos.yaml must contain a repositories list")
    repos = [RepoSpec.from_dict(entry) for entry in entries]
    names = [repo.name for repo in repos]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"Duplicate repository names: {', '.join(duplicates)}")
    return repos


def select_repos(repos: list[RepoSpec], name: str | None, run_all: bool) -> list[RepoSpec]:
    """Select repositories for a run or scoring command."""
    if run_all:
        return repos
    if not name:
        raise ValueError("Specify --repo <name> or --all")
    for repo in repos:
        if repo.name == name:
            return [repo]
    raise ValueError(f"Unknown benchmark repository: {name}")


def _load_yaml(content: str) -> dict[str, object]:
    content = dedent(content)
    if yaml is not None:
        return yaml.safe_load(content) or {}
    return _parse_simple_repos_yaml(content)


def _parse_simple_repos_yaml(content: str) -> dict[str, object]:
    """Parse the limited repos.yaml shape when PyYAML is unavailable."""
    repositories: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    in_repositories = False
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.strip() == "repositories:":
            in_repositories = True
            continue
        if not in_repositories:
            continue
        stripped = line.strip()
        if stripped.startswith("- "):
            if current is not None:
                repositories.append(current)
            current = {}
            stripped = stripped[2:].strip()
            if stripped:
                key, value = _split_yaml_pair(stripped)
                current[key] = _parse_yaml_value(value)
            continue
        if current is None:
            continue
        key, value = _split_yaml_pair(stripped)
        current[key] = _parse_yaml_value(value)
    if current is not None:
        repositories.append(current)
    return {"repositories": repositories}


def _split_yaml_pair(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise ValueError(f"Invalid repos.yaml line: {value}")
    key, raw = value.split(":", 1)
    return key.strip(), raw.strip()


def _parse_yaml_value(value: str) -> object:
    if value.startswith("[") and value.endswith("]"):
        body = value[1:-1].strip()
        if not body:
            return []
        return [item.strip().strip("'\"") for item in body.split(",")]
    return value.strip("'\"")
