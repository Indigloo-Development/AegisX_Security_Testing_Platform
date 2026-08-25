from __future__ import annotations
import json
from pathlib import Path
from typing import Any


def _node(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


def parse_package_lock(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], []
    deps: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    packages = data.get("packages") or {}
    # npm lockfile v2/v3. The root package is represented by an empty key.
    for package_path, meta in packages.items():
        if not package_path or not isinstance(meta, dict):
            continue
        if not package_path.startswith("node_modules/"):
            continue
        name = package_path[len("node_modules/"):].split("/node_modules/")[-1]
        if name.startswith("@") and "/" in name:
            # scoped package path is node_modules/@scope/pkg
            parts = package_path.split("/")
            if len(parts) >= 3:
                name = "/".join(parts[-2:])
        version = str(meta.get("version") or "unknown")
        deps.append({"name": name, "version": version, "ecosystem": "npm", "direct": False, "scope": "runtime", "manifest": str(path), "source": "package-lock"})
    # Prefer the lockfile's explicit nested dependency graph when available.
    root = packages.get("") or {}
    root_deps = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        root_deps.update(root.get(section) or {})
    for name, spec in root_deps.items():
        version = str((packages.get(f"node_modules/{name}") or {}).get("version") or spec if isinstance(spec, str) else "unknown")
        deps.append({"name": name, "version": version, "ecosystem": "npm", "direct": True, "scope": "runtime", "manifest": str(path), "source": "package-lock"})
        edges.append({"source": _node("npm", "root", "0"), "target": _node("npm", name, version), "relation": "depends-on", "direct": True})
    # Package lock may expose nested dependency metadata through legacy dependencies.
    legacy = data.get("dependencies") or {}
    def walk(parent_name: str, rows: dict[str, Any]) -> None:
        for name, meta in rows.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version") or "unknown")
            child = _node("npm", name, version)
            deps.append({"name": name, "version": version, "ecosystem": "npm", "direct": False, "scope": "runtime", "manifest": str(path), "source": "package-lock-legacy"})
            edges.append({"source": parent_name, "target": child, "relation": "depends-on", "direct": False})
            nested = meta.get("dependencies") or {}
            if isinstance(nested, dict):
                walk(child, nested)
    if legacy:
        walk(_node("npm", "root", "0"), legacy)
    return _dedupe_dependencies(deps), _dedupe_edges(edges)


def parse_cargo_lock(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return [], []
    deps: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for pkg in data.get("package", []) or []:
        name = str(pkg.get("name") or "")
        version = str(pkg.get("version") or "unknown")
        if not name:
            continue
        deps.append({"name": name, "version": version, "ecosystem": "Cargo", "direct": False, "scope": "runtime", "manifest": str(path), "source": "Cargo.lock"})
        for child in pkg.get("dependencies") or []:
            dep_name = str(child).split(" ", 1)[0]
            target = next((x for x in deps if x["name"] == dep_name), None)
            target_version = target["version"] if target else "unknown"
            edges.append({"source": _node("Cargo", name, version), "target": _node("Cargo", dep_name, target_version), "relation": "depends-on", "direct": False})
    return _dedupe_dependencies(deps), _dedupe_edges(edges)


def _dedupe_dependencies(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key=(row.get("ecosystem",""), row.get("name",""), row.get("version",""))
        existing=out.get(key)
        if existing is None or row.get("direct"):
            out[key]=row
        elif existing.get("direct"):
            continue
        else:
            out[key]=row
    return list(out.values())


def _dedupe_edges(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out={f"{r.get('source')}|{r.get('target')}|{r.get('relation')}":r for r in rows}
    return list(out.values())
