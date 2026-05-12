import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ─────────────────────────────────────────────
#  DATA
# ─────────────────────────────────────────────
data = {
    "polska\n(12 nodes)": {
        "adaptive": {"avg_cpu_percent": 15.5, "avg_memory_mb": 40},
    },
    "germany\n(17 nodes)": {
        "adaptive": {"avg_cpu_percent": 30.9, "avg_memory_mb": 41},
    },
    "france\n(25 nodes)": {
        "adaptive": {"avg_cpu_percent": 63,   "avg_memory_mb": 42},
    },
}

# ─────────────────────────────────────────────
#  SETTINGS
# ─────────────────────────────────────────────
COLORS    = ["#3B82F6", "#10B981", "#F59E0B"]   # blue, green, amber per topology
BAR_WIDTH = 0.45
FIGSIZE   = (8, 5)

topologies   = list(data.keys())
x            = np.arange(len(topologies))
adaptive_cpu = [data[t]["adaptive"]["avg_cpu_percent"] for t in topologies]
adaptive_mem = [data[t]["adaptive"]["avg_memory_mb"]   for t in topologies]

def style_ax(ax, ylabel, title, values):
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=13, fontweight="bold", pad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(topologies, fontsize=11)
    ax.set_ylim(0, max(values) * 1.35)
    ax.grid(axis="y", linestyle="--", alpha=0.4, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

legend_patches = [
    mpatches.Patch(color=COLORS[i], label=topologies[i].replace("\n", " "))
    for i in range(len(topologies))
]

# ── Figure 1: CPU % ─────────────────────────
fig1, ax1 = plt.subplots(figsize=FIGSIZE)
bars1 = ax1.bar(x, adaptive_cpu, BAR_WIDTH, color=COLORS, alpha=0.9, zorder=3,
                edgecolor="white", linewidth=0.8)
style_ax(ax1, "Avg CPU Usage (%)", "CPU Utilization per Topology", adaptive_cpu)

for bar, val in zip(bars1, adaptive_cpu):
    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
             f"{val:.1f}%", ha="center", va="bottom",
             fontsize=10, fontweight="bold", color="#1e293b")

ax1.legend(handles=legend_patches, fontsize=9, framealpha=0.7)
fig1.suptitle("SDN Controller — Adaptive Timeout Mode", fontsize=11, color="#64748b", y=1.01)
fig1.tight_layout()
fig1.savefig("cpu_metrics.png", dpi=150, bbox_inches="tight")
print("Saved: cpu_metrics.png")

# ── Figure 2: Memory MB ─────────────────────
fig2, ax2 = plt.subplots(figsize=FIGSIZE)
bars2 = ax2.bar(x, adaptive_mem, BAR_WIDTH, color=COLORS, alpha=0.9, zorder=3,
                edgecolor="white", linewidth=0.8)
style_ax(ax2, "Avg Memory Usage (MB)", "Memory Utilization per Topology", adaptive_mem)

for bar, val in zip(bars2, adaptive_mem):
    ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
             f"{val:.1f} MB", ha="center", va="bottom",
             fontsize=10, fontweight="bold", color="#1e293b")

ax2.legend(handles=legend_patches, fontsize=9, framealpha=0.7)
fig2.suptitle("SDN Controller — Adaptive Timeout Mode", fontsize=11, color="#64748b", y=1.01)
fig2.tight_layout()
fig2.savefig("memory_metrics.png", dpi=150, bbox_inches="tight")
print("Saved: memory_metrics.png")

plt.show()
