import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load CSVs
df1 = pd.read_csv("metrics_adaptive.csv")
df2 = pd.read_csv("metrics_fixed_old.csv")

# Metrics to compare
metrics = [
    "cpu_percent",
    "table_occupancy",
    "rejected_flows",
    "memory_mb",
    "packet_in_count",
]

labels = ["adaptive", "fixed"]

for metric in metrics:
    avg_values = [
        df1[metric].mean(),
        df2[metric].mean(),
    ]

    plt.figure()
    plt.bar(labels, avg_values)
    plt.ylabel("Average value")
    plt.title(f"Average {metric}")

    plt.tight_layout()
    plt.savefig(f"{metric}_comparison.png")
    plt.close()
