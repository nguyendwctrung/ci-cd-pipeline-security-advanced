"""Command line interface for the benchmark framework."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from security_system.benchmark.config import load_repos, select_repos
from security_system.benchmark.ground_truth import seed_ground_truth_from_findings
from security_system.benchmark.models import BenchmarkPaths
from security_system.benchmark.reporting import generate_summary
from security_system.benchmark.runner import BenchmarkRunner
from security_system.benchmark.scoring import score_repository, write_score


def main() -> None:
    parser = argparse.ArgumentParser(prog="benchmark")
    parser.add_argument("--benchmark-root", type=Path, default=Path("benchmark"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--repo")
    run_parser.add_argument("--all", action="store_true")
    run_parser.add_argument("--force", action="store_true")

    score_parser = subparsers.add_parser("score")
    score_parser.add_argument("--repo")
    score_parser.add_argument("--all", action="store_true")

    seed_parser = subparsers.add_parser("seed-ground-truth")
    seed_parser.add_argument("--repo")
    seed_parser.add_argument("--all", action="store_true")
    seed_parser.add_argument("--limit", type=int)
    seed_parser.add_argument("--write", action="store_true")

    subparsers.add_parser("report")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    paths = BenchmarkPaths.from_root(args.benchmark_root)
    repos = load_repos(paths.repos_yaml)

    if args.command == "run":
        selected = select_repos(repos, args.repo, args.all)
        records = BenchmarkRunner(paths).run_many(selected, force=args.force)
        for record in records:
            print(f"{record['repo']}: {record['status']}")
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


if __name__ == "__main__":
    main()
