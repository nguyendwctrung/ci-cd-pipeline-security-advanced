"""Command line interface for the benchmark framework."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Sequence

from security_system.benchmark.config import load_repos, select_repos
from security_system.benchmark.ground_truth import seed_ground_truth_from_findings
from security_system.benchmark.models import BenchmarkPaths, RepoSpec
from security_system.benchmark.reporting import generate_summary
from security_system.benchmark.runner import BenchmarkRunner
from security_system.benchmark.scoring import score_repository, write_score


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="benchmark")
    parser.add_argument("--benchmark-root", type=Path, default=Path("benchmark"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--repo")
    run_parser.add_argument("--all", action="store_true")
    run_parser.add_argument("--force", action="store_true")
    run_parser.add_argument("--jobs", type=_positive_int, default=1)
    run_parser.add_argument("--fail-fast", action="store_true")
    run_parser.add_argument("--list", action="store_true")

    score_parser = subparsers.add_parser("score")
    score_parser.add_argument("--repo")
    score_parser.add_argument("--all", action="store_true")

    seed_parser = subparsers.add_parser("seed-ground-truth")
    seed_parser.add_argument("--repo")
    seed_parser.add_argument("--all", action="store_true")
    seed_parser.add_argument("--limit", type=int)
    seed_parser.add_argument("--write", action="store_true")

    subparsers.add_parser("status")
    subparsers.add_parser("report")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    paths = BenchmarkPaths.from_root(args.benchmark_root)
    repos = load_repos(paths.repos_yaml)

    if args.command == "run":
        if args.list:
            _print_repo_list(repos)
            return
        selected = select_repos(repos, args.repo, args.all)
        records = BenchmarkRunner(paths).run_many(
            selected,
            force=args.force,
            jobs=args.jobs,
            fail_fast=args.fail_fast,
        )
        for record in records:
            print(_format_run_record(record))
    elif args.command == "score":
        selected = select_repos(repos, args.repo, args.all)
        for repo in selected:
            if not repo.ground_truth:
                print(f"{repo.name}: SKIPPED no ground truth")
                continue
            findings_path = paths.normalized_dir / f"{repo.name}.findings.json"
            if not findings_path.exists():
                print(f"{repo.name}: SKIPPED no normalized findings")
                continue
            score = score_repository(findings_path, paths.ground_truth_dir / repo.ground_truth)
            write_score(paths.scored_dir / f"{repo.name}.score.json", score)
            print(f"{repo.name}: SCORED")
    elif args.command == "seed-ground-truth":
        selected = select_repos(repos, args.repo, args.all)
        for repo in selected:
            if not repo.ground_truth:
                print(f"{repo.name}: SKIPPED no ground truth")
                continue
            findings_path = paths.normalized_dir / f"{repo.name}.findings.json"
            if not findings_path.exists():
                print(f"{repo.name}: SKIPPED no normalized findings")
                continue
            result = seed_ground_truth_from_findings(
                repo,
                findings_path,
                paths.ground_truth_dir,
                write=args.write,
                limit=args.limit,
            )
            mode = "WROTE" if result.written else "DRY-RUN"
            print(
                f"{repo.name}: {mode} {result.added} candidate row(s), "
                f"{result.skipped_existing} duplicate(s), file={result.path}"
            )
    elif args.command == "report":
        path = generate_summary(paths, repos)
        print(path)
    elif args.command == "status":
        for line in _build_status_lines(paths, repos):
            print(line)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _print_repo_list(repos: list[RepoSpec]) -> None:
    for repo in repos:
        ground_truth = repo.ground_truth or "none"
        checks = ",".join(repo.enabled_checks)
        print(f"{repo.name}: language={repo.language} category={repo.category} ground_truth={ground_truth} checks={checks}")


def _format_run_record(record: dict[str, object]) -> str:
    parts = [f"{record.get('repo')}: {record.get('status')}"]
    if _has_value(record.get("duration_seconds")):
        parts.append(f"duration={record.get('duration_seconds')}s")
    if _has_value(record.get("finding_count")):
        parts.append(f"findings={record.get('finding_count')}")
    if record.get("stage"):
        parts.append(f"stage={record.get('stage')}")
    reason = record.get("error") or record.get("reason")
    if reason:
        parts.append(f"reason={reason}")
    return " ".join(parts)


def _build_status_lines(paths: BenchmarkPaths, repos: list[RepoSpec]) -> list[str]:
    lines = []
    totals = {"COMPLETED": 0, "ERROR": 0, "SKIPPED": 0, "NOT_RUN": 0, "SCORED": 0}
    for repo in repos:
        run = _load_json(paths.results_dir / "runs" / f"{repo.name}.json")
        status = str(run.get("status", "NOT_RUN"))
        totals[status] = totals.get(status, 0) + 1
        normalized_path = paths.normalized_dir / f"{repo.name}.findings.json"
        score_path = paths.scored_dir / f"{repo.name}.score.json"
        scored = score_path.exists()
        if scored:
            totals["SCORED"] += 1
        details = []
        if normalized_path.exists():
            details.append("normalized=yes")
        else:
            details.append("normalized=no")
        details.append(f"scored={'yes' if scored else 'no'}")
        if _has_value(run.get("duration_seconds")):
            details.append(f"duration={run.get('duration_seconds')}s")
        reason = run.get("error") or run.get("reason")
        if reason:
            details.append(f"reason={reason}")
        lines.append(f"{repo.name}: {status} {' '.join(details)}")
    lines.append(
        "TOTAL: "
        f"completed={totals.get('COMPLETED', 0)} "
        f"error={totals.get('ERROR', 0)} "
        f"skipped={totals.get('SKIPPED', 0)} "
        f"not_run={totals.get('NOT_RUN', 0)} "
        f"scored={totals.get('SCORED', 0)}"
    )
    return lines


def _load_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def _has_value(value: object) -> bool:
    return value is not None and value != ""


if __name__ == "__main__":
    main()
