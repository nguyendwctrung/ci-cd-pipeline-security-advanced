from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

summary_path = Path("benchmark/results/summary.csv")
output_dir = Path("benchmark/results/charts")
output_dir.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(summary_path)

numeric_cols = [
    "duration_seconds",
    "finding_count",
    "strict_precision",
    "strict_recall",
    "strict_f1",
    "relaxed_f1",
    "category_f1",
]
for col in numeric_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# 1. Finding count by repo
findings = df.sort_values("finding_count", ascending=False)
plt.figure(figsize=(12, 6))
plt.bar(findings["repo"], findings["finding_count"])
plt.xticks(rotation=75, ha="right")
plt.ylabel("Findings")
plt.title("Finding Count by Repository")
plt.tight_layout()
plt.savefig(output_dir / "finding_by_repo.png", dpi=200)
plt.close()

# 2. Runtime by repo
runtimes = df.sort_values("duration_seconds", ascending=False)
plt.figure(figsize=(12, 6))
plt.bar(runtimes["repo"], runtimes["duration_seconds"])
plt.xticks(rotation=75, ha="right")
plt.ylabel("Seconds")
plt.title("Benchmark Runtime by Repository")
plt.tight_layout()
plt.savefig(output_dir / "runtime_by_repo.png", dpi=200)
plt.close()

# 3. Strict F1 by scored repo
scored = df[df["strict_f1"].notna()].sort_values("strict_f1", ascending=False)
plt.figure(figsize=(10, 5))
plt.bar(scored["repo"], scored["strict_f1"])
plt.xticks(rotation=60, ha="right")
plt.ylim(0, 1)
plt.ylabel("Strict F1 Score")
plt.title("Strict F1 by Scored Repository")
plt.tight_layout()
plt.savefig(output_dir / "strict_f1_by_repo.png", dpi=200)
plt.close()

# 4. Precision vs recall
plt.figure(figsize=(7, 6))
plt.scatter(scored["strict_recall"], scored["strict_precision"])
for _, row in scored.iterrows():
    plt.annotate(row["repo"], (row["strict_recall"], row["strict_precision"]), fontsize=8)
plt.xlim(0, 1.05)
plt.ylim(0, 1.05)
plt.xlabel("Strict Recall")
plt.ylabel("Strict Precision")
plt.title("Precision vs Recall")
plt.tight_layout()
plt.savefig(output_dir / "precision_vs_recall.png", dpi=200)
plt.close()

print(f"Charts written to {output_dir}")