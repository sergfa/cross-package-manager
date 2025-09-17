#!/usr/bin/env python3
"""Cross-package-manager scanner for the Shai-Halud incident."""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple


class CSVFormatError(RuntimeError):
    """Raised when the affected-packages CSV cannot be parsed."""


def parse_affected_packages(csv_path: Path) -> Dict[str, Set[str]]:
    """Parse the affected packages CSV into a mapping of package -> versions."""

    if not csv_path.is_file():
        raise CSVFormatError(f"CSV file not found: {csv_path}")

    affected: Dict[str, Set[str]] = defaultdict(set)

    def _row_iter() -> Iterator[str]:
        with csv_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                yield raw_line

    reader = csv.DictReader(_row_iter())
    if reader.fieldnames is None:
        raise CSVFormatError("CSV is missing header row")

    field_map = {name.lower(): name for name in reader.fieldnames}
    pkg_key = field_map.get("package")
    ver_key = field_map.get("versions")
    if not pkg_key or not ver_key:
        raise CSVFormatError("CSV must contain 'Package' and 'Versions' headers")

    for row in reader:
        package = (row.get(pkg_key) or "").strip()
        version_field = (row.get(ver_key) or "").strip()
        extras = row.get(None)
        if isinstance(extras, list):
            extra_values = [value.strip() for value in extras if value and value.strip()]
            if extra_values:
                tail = ",".join(extra_values)
                version_field = f"{version_field},{tail}" if version_field else tail
        if not package or not version_field:
            continue
        normalized = version_field.replace(";", ",")
        versions = [part.strip() for part in normalized.split(",") if part.strip()]
        if not versions:
            continue
        affected[package].update(versions)

    if not affected:
        raise CSVFormatError("CSV did not contain any package/version entries")

    return affected


@dataclass
class Finding:
    package: str
    versions_found: List[str]
    versions_flagged: List[str]
    evidence_by_version: Dict[str, List[str]] = field(default_factory=dict)

    def evidence_string(self) -> str:
        parts: List[str] = []
        for version in self.versions_flagged:
            entries = self.evidence_by_version.get(version, [])
            if entries:
                parts.append("; ".join(entries))
        return " | ".join(parts)

    def to_json(self) -> Dict[str, object]:
        return {
            "package": self.package,
            "versions_found": self.versions_found,
            "versions_flagged": self.versions_flagged,
            "evidence": self.evidence_string(),
        }


class DependencyCollector:
    def __init__(self) -> None:
        self._versions: Dict[str, Set[str]] = defaultdict(set)
        self._evidence: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))

    def add(self, package: Optional[str], version: Optional[str], evidence: str) -> None:
        if not package or not version:
            return
        version = version.strip()
        if not version:
            return
        if version.startswith("file:") or version.startswith("link:"):
            return
        self._versions[package].add(version)
        self._evidence[package][version].add(evidence)

    @property
    def packages_scanned(self) -> int:
        return len(self._versions)

    def iter_packages(self) -> Iterator[Tuple[str, Set[str]]]:
        for package, versions in self._versions.items():
            yield package, versions

    def evidence_for(self, package: str, version: str) -> List[str]:
        return sorted(self._evidence.get(package, {}).get(version, []))


def _extract_name_from_npm_key(key: str, metadata: Dict[str, object]) -> Optional[str]:
    name = metadata.get("name") if isinstance(metadata, dict) else None
    if isinstance(name, str) and name:
        return name
    if not key:
        return None
    parts = key.split("node_modules/")
    candidate = parts[-1]
    if candidate:
        return candidate
    return None


def _parse_npm_packages_section(packages: Dict[str, object], collector: DependencyCollector, lockfile_name: str) -> None:
    for key, metadata in packages.items():
        if not isinstance(metadata, dict):
            continue
        version = metadata.get("version")
        name = _extract_name_from_npm_key(key, metadata)
        if not isinstance(version, str):
            continue
        if not name:
            continue
        evidence_key = key or "."
        evidence = f"{lockfile_name} -> packages['{evidence_key}'] -> version {version}"
        collector.add(name, version, evidence)


def _parse_npm_dependencies_tree(
    dependencies: Dict[str, object],
    collector: DependencyCollector,
    lockfile_name: str,
    path: Tuple[str, ...] = (),
) -> None:
    for dep_name, metadata in dependencies.items():
        if not isinstance(metadata, dict):
            continue
        version = metadata.get("version")
        if isinstance(version, str):
            breadcrumb = " -> ".join((*path, dep_name))
            evidence = f"{lockfile_name} -> dependencies[{breadcrumb}] -> version {version}"
            collector.add(dep_name, version, evidence)
        nested = metadata.get("dependencies")
        if isinstance(nested, dict):
            _parse_npm_dependencies_tree(nested, collector, lockfile_name, (*path, dep_name))


def parse_package_lock(lock_path: Path, collector: DependencyCollector) -> None:
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    lockfile_name = lock_path.name

    packages = data.get("packages")
    if isinstance(packages, dict):
        _parse_npm_packages_section(packages, collector, lockfile_name)
        return

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _parse_npm_dependencies_tree(dependencies, collector, lockfile_name)
        return

    raise RuntimeError(f"Unrecognised npm lockfile structure in {lock_path}")


def _split_yarn_header(header: str) -> List[str]:
    header = header.rstrip(":").strip()
    if not header:
        return []
    try:
        reader = csv.reader([header], skipinitialspace=True)
        parts = next(reader)
    except Exception:
        parts = header.split(",")
    return [part.strip().strip('"').strip("'") for part in parts if part.strip()]


def _package_name_from_spec(spec: str) -> Optional[str]:
    spec = spec.strip().strip('"').strip("'")
    if not spec:
        return None
    if spec.startswith("@"):  # scoped package
        at_index = spec.find("@", 1)
        if at_index == -1:
            return spec
        return spec[:at_index]
    at_index = spec.find("@")
    if at_index == -1:
        return spec
    return spec[:at_index]


def parse_yarn_lock(lock_path: Path, collector: DependencyCollector) -> None:
    lockfile_name = lock_path.name
    with lock_path.open("r", encoding="utf-8") as handle:
        current_specs: List[str] = []
        current_version: Optional[str] = None

        def flush_block() -> None:
            nonlocal current_specs, current_version
            if not current_specs or not current_version:
                current_specs = []
                current_version = None
                return
            seen_packages: Set[str] = set()
            for spec in current_specs:
                package = _package_name_from_spec(spec)
                if not package or package in seen_packages:
                    continue
                seen_packages.add(package)
                evidence = f"{lockfile_name} -> {spec} -> version {current_version}"
                collector.add(package, current_version, evidence)
            current_specs = []
            current_version = None

        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not line.strip():
                flush_block()
                continue
            if not line.startswith(" ") and line.endswith(":"):
                flush_block()
                current_specs = _split_yarn_header(line)
                current_version = None
                continue
            stripped = line.strip()
            if stripped.startswith("version "):
                value = stripped[len("version "):].strip()
                current_version = value.strip('"').strip("'")

        flush_block()


_pnpm_key_re = re.compile(r"^/?([^:@]+/)?[^:]+$")


def _parse_pnpm_key(entry: str) -> Tuple[Optional[str], Optional[str]]:
    entry = entry.strip().strip('"').strip("'")
    if not entry:
        return None, None
    if entry.startswith("/"):
        entry = entry[1:]
    if entry.startswith("."):
        # local path style keys
        return None, None
    if entry.startswith("node_modules"):
        entry = entry.split("node_modules/")[-1]
    if "(" in entry:
        entry = entry.split("(", 1)[0]
    if "@" not in entry:
        return None, None
    at_index = entry.rfind("@")
    name = entry[:at_index]
    version = entry[at_index + 1 :]
    if not name or not version:
        return None, None
    return name, version


def parse_pnpm_lock(lock_path: Path, collector: DependencyCollector) -> None:
    lockfile_name = lock_path.name
    with lock_path.open("r", encoding="utf-8") as handle:
        in_packages = False
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not in_packages:
                if line.strip() == "packages:":
                    in_packages = True
                continue
            if line and not line.startswith(" "):
                # end of packages section
                break
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip(" "))
            stripped = line.strip()
            if indent == 2 and stripped.endswith(":"):
                key = stripped[:-1].strip()
                package, version = _parse_pnpm_key(key)
                if not package or not version:
                    continue
                evidence = f"{lockfile_name} -> packages['{key}'] -> version {version}"
                collector.add(package, version, evidence)


# ---------------------------------------------------------------------------
# CLI fallbacks
# ---------------------------------------------------------------------------


def _run_command(args: Sequence[str], cwd: Path) -> str:
    completed = subprocess.run(
        args,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Command {' '.join(args)} failed with code {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.stdout


def _walk_npm_tree(tree: Dict[str, object], collector: DependencyCollector, lockfile_name: str, path: Tuple[str, ...] = ()) -> None:
    name = tree.get("name") if isinstance(tree, dict) else None
    version = tree.get("version") if isinstance(tree, dict) else None
    if isinstance(name, str) and isinstance(version, str):
        evidence = f"{lockfile_name} -> {'/'.join(path) or name} -> version {version}"
        collector.add(name, version, evidence)
    dependencies = tree.get("dependencies") if isinstance(tree, dict) else None
    if isinstance(dependencies, dict):
        for dep_name, metadata in dependencies.items():
            if not isinstance(metadata, dict):
                continue
            sub_path = (*path, dep_name)
            _walk_npm_tree(metadata, collector, lockfile_name, sub_path)


def collect_via_cli(
    project_dir: Path,
    detector: str,
    collector: DependencyCollector,
    max_depth: Optional[int],
) -> None:
    if detector == "cli:npm":
        cmd = ["npm", "ls", "--all", "--json"]
        if max_depth is not None:
            cmd.extend(["--depth", str(max_depth)])
        output = _run_command(cmd, project_dir)
        data = json.loads(output or "{}")
        _walk_npm_tree(data, collector, "npm ls")
        return
    if detector == "cli:pnpm":
        depth_value = str(max_depth) if max_depth is not None else "Infinity"
        cmd = ["pnpm", "list", "--depth", depth_value, "--json"]
        output = _run_command(cmd, project_dir)
        data = json.loads(output or "[]")
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if isinstance(name, str) and isinstance(version, str):
                evidence = "pnpm list -> root"
                collector.add(name, version, evidence)
            children = entry.get("dependencies")
            if isinstance(children, list):
                for child in children:
                    if not isinstance(child, dict):
                        continue
                    cname = child.get("name")
                    cver = child.get("version")
                    if isinstance(cname, str) and isinstance(cver, str):
                        evidence = f"pnpm list -> {cname}"
                        collector.add(cname, cver, evidence)
        return
    if detector == "cli:yarn":
        cmd = ["yarn", "list", "--pattern", ".", "--json"]
        if max_depth is not None:
            cmd.extend(["--depth", str(max_depth)])
        output = _run_command(cmd, project_dir)
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("type") != "tree":
                continue
            trees = payload.get("data", {}).get("trees", [])
            for node in trees:
                name = node.get("name") if isinstance(node, dict) else None
                if not isinstance(name, str):
                    continue
                if "@" not in name:
                    continue
                pkg, ver = name.rsplit("@", 1)
                evidence = f"yarn list -> {name}"
                collector.add(pkg, ver, evidence)
        return
    raise RuntimeError(f"Unsupported CLI detector {detector}")


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


def _verbose(message: str, enabled: bool) -> None:
    if enabled:
        print(message, file=sys.stderr)


def _available_lockfiles(project_dir: Path) -> List[Path]:
    candidates = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"]
    found = [project_dir / name for name in candidates if (project_dir / name).is_file()]
    return found


def collect_dependencies(
    project_dir: Path,
    verbose: bool = False,
    max_depth: Optional[int] = None,
) -> Tuple[str, DependencyCollector]:
    collector = DependencyCollector()
    lockfiles = _available_lockfiles(project_dir)
    priority = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"]
    lockfile_map = {lockfile.name: lockfile for lockfile in lockfiles}

    selected_lockfile: Optional[Path] = None
    for name in priority:
        if name in lockfile_map:
            selected_lockfile = lockfile_map[name]
            break

    if selected_lockfile:
        if len(lockfiles) > 1:
            _verbose(
                "Multiple lockfiles detected; prioritising %s" % selected_lockfile.name,
                verbose,
            )
        _verbose(f"Parsing {selected_lockfile.name}", verbose)
        try:
            if selected_lockfile.name == "pnpm-lock.yaml":
                parse_pnpm_lock(selected_lockfile, collector)
                return "lockfile:pnpm", collector
            if selected_lockfile.name == "package-lock.json":
                parse_package_lock(selected_lockfile, collector)
                return "lockfile:npm", collector
            if selected_lockfile.name == "yarn.lock":
                parse_yarn_lock(selected_lockfile, collector)
                return "lockfile:yarn", collector
        except Exception as exc:  # pragma: no cover - defensive
            _verbose(f"Failed to parse {selected_lockfile.name}: {exc}", verbose)
            collector = DependencyCollector()

    # CLI fallback
    _verbose("Falling back to CLI inspection", verbose)
    detector: Optional[str] = None
    if (project_dir / "package.json").is_file():
        detector = "cli:npm"
    elif (project_dir / "pnpm-lock.yaml").is_file() or (project_dir / "pnpm-workspace.yaml").is_file():
        detector = "cli:pnpm"
    elif (project_dir / "yarn.lock").is_file():
        detector = "cli:yarn"
    else:
        detector = "cli:npm"

    collect_via_cli(project_dir, detector, collector, max_depth)
    return detector, collector


def build_findings(
    collector: DependencyCollector,
    affected: Dict[str, Set[str]],
) -> List[Finding]:
    findings: List[Finding] = []
    for package, versions in collector.iter_packages():
        if package not in affected:
            continue
        versions_found = sorted(versions)
        flagged = sorted(v for v in versions if v in affected[package])
        if not flagged:
            continue
        evidence_map = {version: collector.evidence_for(package, version) for version in flagged}
        findings.append(
            Finding(
                package=package,
                versions_found=versions_found,
                versions_flagged=flagged,
                evidence_by_version=evidence_map,
            )
        )
    findings.sort(key=lambda f: f.package)
    return findings


def render_table(findings: List[Finding], detector: str) -> str:
    if not findings:
        return "No flagged packages found."
    rows: List[Tuple[str, str, str, str]] = []
    for finding in findings:
        for version in finding.versions_flagged:
            evidence_entries = finding.evidence_by_version.get(version, [])
            evidence = "; ".join(evidence_entries)
            rows.append((finding.package, version, detector, evidence))

    headers = ("Package", "Flagged Version", "Found Via", "Evidence")
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(value))

    def format_row(values: Sequence[str]) -> str:
        return " | ".join(value.ljust(widths[idx]) for idx, value in enumerate(values))

    lines = [format_row(headers), "-+-".join("-" * width for width in widths)]
    for row in rows:
        lines.append(format_row(row))
    return "\n".join(lines)


def summarise(findings: List[Finding]) -> Tuple[List[str], int]:
    flagged_pairs = [(finding.package, version) for finding in findings for version in finding.versions_flagged]
    if not flagged_pairs:
        return ["No flagged packages detected."], 0
    lines = [f"Found {len(flagged_pairs)} flagged package(s):"]
    for package, version in flagged_pairs:
        lines.append(f"- {package}@{version}")
    return lines, len(flagged_pairs)


def generate_report(
    project_dir: Path,
    detector: str,
    findings: List[Finding],
    collector: DependencyCollector,
) -> Dict[str, object]:
    timestamp = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    return {
        "project_dir": str(project_dir.resolve()),
        "detector": detector,
        "findings": [finding.to_json() for finding in findings],
        "summary": {
            "packages_scanned": collector.packages_scanned,
            "flagged_count": len(findings),
            "timestamp": timestamp,
        },
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan lockfiles for Shai-Halud incident packages")
    parser.add_argument("--csv", required=True, help="Path to CSV with affected packages")
    parser.add_argument("--dir", default=".", help="Project directory to scan")
    parser.add_argument("--format", choices=["json", "table"], default="table", help="Output format")
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument("--max-depth", type=int, help="Maximum depth for CLI fallback")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose diagnostics")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    project_dir = Path(args.dir).resolve()

    try:
        affected = parse_affected_packages(Path(args.csv))
    except Exception as exc:
        print(f"Error reading CSV: {exc}", file=sys.stderr)
        return 1

    try:
        detector, collector = collect_dependencies(project_dir, verbose=args.verbose, max_depth=args.max_depth)
    except Exception as exc:
        print(f"Error collecting dependencies: {exc}", file=sys.stderr)
        return 1

    findings = build_findings(collector, affected)
    report = generate_report(project_dir, detector, findings, collector)

    if args.format == "json":
        output_text = json.dumps(report, indent=2)
    else:
        output_text = render_table(findings, detector)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(output_text + "\n", encoding="utf-8")
        if args.verbose:
            print(f"Report written to {out_path}", file=sys.stderr)
    else:
        print(output_text)

    summary_lines, flagged_count = summarise(findings)
    for line in summary_lines:
        print(line)
    exit_code = 2 if flagged_count else 0
    print(f"Exit code: {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
