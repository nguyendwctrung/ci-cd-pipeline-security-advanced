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
findings = df.sort_values("finding_count", ascending=True)
plt.figure(figsize=(12, max(6, len(findings) * 0.4)))
bars = plt.barh(findings["repo"], findings["finding_count"])
plt.xscale("symlog", linthresh=1)
plt.xlabel("Findings (symlog scale)")
plt.title("Finding Count by Repository")
plt.bar_label(bars, labels=[str(int(value)) if pd.notna(value) else "" for value in findings["finding_count"]], padding=3)
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

# 4. Precision and recall by scored repo
precision_recall = scored.sort_values("strict_f1", ascending=False)
x = list(range(len(precision_recall)))
repo_labels = precision_recall["repo"].astype(str).tolist()
width = 0.38
plt.figure(figsize=(12, 6))
plt.bar([position - width / 2 for position in x], precision_recall["strict_precision"], width, label="Precision")
plt.bar([position + width / 2 for position in x], precision_recall["strict_recall"], width, label="Recall")
plt.xticks(x, repo_labels, rotation=60, ha="right")
plt.ylim(0, 1.05)
plt.ylabel("Score")
plt.title("Strict Precision and Recall by Scored Repository")
plt.legend()
plt.tight_layout()
plt.savefig(output_dir / "precision_recall_by_repo.png", dpi=200)
plt.close()

print(f"Charts written to {output_dir}")
