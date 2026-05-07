#!/usr/bin/env python3
"""
Adaptive timeout parameter optimizer.
Runs your Docker+Mininet stack with different parameter sets,
reads summary.json, and finds the best combination.

Usage:
    python3 optimize_params.py                  # random search (default 30 trials)
    python3 optimize_params.py --trials 50
    python3 optimize_params.py --strategy grid  # grid search (slow but exhaustive)
    python3 optimize_params.py --strategy tpe   # TPE (Bayesian-like, recommended)
    python3 optimize_params.py --w-rejected 3 --w-cpu 1 --w-memory 1
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
from itertools import product
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
RESULTS_DIR   = "./results/adaptive"   # where summary.json lands (mode=adaptive)
TCAM_MAX      = 750                   # must match controller TCAM_MAX
RUN_SCRIPT    = "./run.sh"             # script that starts docker + mininet
ENV_FILE      = ".env"                 # docker-compose / shell env file

# Search space — (min, max, step)
SPACE = {
    "T_MIN":  (0.5, 5.0,  0.5),
    "T_MAX":  (5.0, 60.0, 5.0),
    "ALPHA":  (0.5, 10.0, 0.5),
    "BETA":   (0.5, 10.0, 0.5),
    "DELTA":  (5.0, 80.0, 5.0),
    "GAMMA":  (0.1, 5.0,  0.1),
    "ETA":    (1.0, 20.0, 1.0),
    "THETA":  (1.0, 30.0, 1.0),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def frange(start, stop, step):
    """Inclusive float range."""
    vals = []
    v = start
    while v <= stop + 1e-9:
        vals.append(round(v, 6))
        v += step
    return vals


def write_env(params: dict):
    """Write parameters to .env file (preserves other keys if present)."""
    existing = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    existing[k.strip()] = v.strip()

    existing.update({k: str(v) for k, v in params.items()})
    existing["MODE"] = "adaptive"   # always adaptive when tuning

    with open(ENV_FILE, "w") as f:
        for k, v in existing.items():
            f.write(f"{k}={v}\n")


def run_experiment() -> dict | None:
    """Run the stack and return the summary dict, or None on failure."""
    # Remove old results so we don't read stale data
    summary_path = Path(f"{RESULTS_DIR}/{TCAM_MAX}/summary.json")
    if summary_path.exists():
        summary_path.unlink()

    print(f"    Running {RUN_SCRIPT} ...", flush=True)
    result = subprocess.run(
        ["bash", RUN_SCRIPT],
        capture_output=False,
        timeout=300,   # hard cap 5 minutes per trial
    )

    if result.returncode != 0:
        print(f"    [WARN] run.sh exited with code {result.returncode}")

    if not summary_path.exists():
        print(f"    [ERROR] summary.json not found at {summary_path}")
        return None

    with open(summary_path) as f:
        return json.load(f)


def fitness(summary: dict, w_rejected: float, w_cpu: float, w_memory: float) -> float:
    """
    Lower is better (minimization).
    Combines normalised rejection rate, CPU, and memory.
    """
    rej  = summary.get("total_rejected_flows", 0)
    pkts = summary.get("total_packet_in_flows", 1) or 1
    rej_rate  = rej / pkts * 100           # percentage
    cpu       = summary.get("avg_cpu_percent", 0)
    mem       = summary.get("avg_memory_mb", 0)
    return w_rejected * (rej / TCAM_MAX) + w_cpu * cpu + w_memory * mem


def log_trial(i: int, total: int, params: dict, summary: dict, score: float, is_best: bool):
    tag = "*** BEST ***" if is_best else ""
    print(
        f"  Trial {i+1:>3}/{total}  "
        f"score={score:7.3f}  "
        f"rej={summary['total_rejected_flows']:>6}  "
        f"cpu={summary['avg_cpu_percent']:5.1f}%  "
        f"mem={summary['avg_memory_mb']:5.1f}MB  "
        f"{tag}"
    )


def print_best(best: dict):
    print("\n" + "="*60)
    print("BEST CONFIGURATION")
    print("="*60)
    for k, v in best["params"].items():
        print(f"  {k:<8} = {v}")
    print()
    s = best["summary"]
    print(f"  Rejected flows    : {s['total_rejected_flows']}")
    print(f"  Total packet-ins  : {s['total_packet_in_flows']}")
    rej_rate = s['total_rejected_flows'] / max(s['total_packet_in_flows'], 1) * 100
    print(f"  Rejection rate    : {rej_rate:.2f}%")
    print(f"  Avg CPU           : {s['avg_cpu_percent']:.1f}%")
    print(f"  Avg Memory        : {s['avg_memory_mb']:.1f} MB")
    print(f"  Avg table occ     : {s['avg_table_occupancy_percent']:.1f}%")
    print(f"  Fitness score     : {best['score']:.4f}")
    print("="*60)

    # Print ready-to-use env block
    print("\nPaste into your .env or docker-compose environment:\n")
    for k, v in best["params"].items():
        print(f"  {k}={v}")
    print()


def save_results(all_results: list, out_path: str = "search_results.json"):
    all_results_sorted = sorted(all_results, key=lambda r: r["score"])
    with open(out_path, "w") as f:
        json.dump(all_results_sorted, f, indent=2)
    print(f"All results saved to {out_path}")


# ---------------------------------------------------------------------------
# Search strategies
# ---------------------------------------------------------------------------

def random_params() -> dict:
    params = {}
    for key, (lo, hi, step) in SPACE.items():
        choices = frange(lo, hi, step)
        params[key] = random.choice(choices)
    return params


def random_search(n_trials, w_rejected, w_cpu, w_memory) -> list:
    all_results = []
    best = None

    print(f"\nRandom search: {n_trials} trials")
    print("-" * 60)

    for i in range(n_trials):
        params = random_params()
        print(f"\n  Params: " + "  ".join(f"{k}={v}" for k, v in params.items()))
        write_env(params)

        summary = run_experiment()
        if summary is None:
            print("    Skipping — no summary produced.")
            continue

        score = fitness(summary, w_rejected, w_cpu, w_memory)
        is_best = best is None or score < best["score"]
        if is_best:
            best = {"params": params, "summary": summary, "score": score}

        log_trial(i, n_trials, params, summary, score, is_best)
        all_results.append({"params": params, "summary": summary, "score": score})

    return all_results, best


def tpe_search(n_trials, w_rejected, w_cpu, w_memory) -> list:
    """
    Simple TPE-like search:
    - First 20% trials are random (warm-up).
    - Then sample from the top-25% good configs with Gaussian perturbation.
    """
    all_results = []
    best = None
    warm_up = max(5, n_trials // 5)

    print(f"\nTPE search: {n_trials} trials  (warm-up: {warm_up})")
    print("-" * 60)

    for i in range(n_trials):
        if i < warm_up or len(all_results) < 4:
            params = random_params()
        else:
            # Pick from top 25% and perturb
            top_k = max(1, len(all_results) // 4)
            sorted_res = sorted(all_results, key=lambda r: r["score"])
            parent = random.choice(sorted_res[:top_k])["params"]
            params = {}
            for key, (lo, hi, step) in SPACE.items():
                choices = frange(lo, hi, step)
                base = parent[key]
                # Gaussian perturbation ± 2 steps
                sigma = 2 * step
                candidate = base + random.gauss(0, sigma)
                candidate = max(lo, min(hi, candidate))
                # Snap to grid
                idx = round((candidate - lo) / step)
                idx = max(0, min(len(choices) - 1, idx))
                params[key] = choices[idx]

        print(f"\n  Params: " + "  ".join(f"{k}={v}" for k, v in params.items()))
        write_env(params)

        summary = run_experiment()
        if summary is None:
            print("    Skipping — no summary produced.")
            continue

        score = fitness(summary, w_rejected, w_cpu, w_memory)
        is_best = best is None or score < best["score"]
        if is_best:
            best = {"params": params, "summary": summary, "score": score}

        log_trial(i, n_trials, params, summary, score, is_best)
        all_results.append({"params": params, "summary": summary, "score": score})

    return all_results, best


def grid_search(w_rejected, w_cpu, w_memory) -> list:
    """Full grid — WARNING: can be millions of combos. Use a reduced space."""
    # Coarse grid for feasibility
    coarse = {
        "T_MIN":  frange(0.5, 3.0,  0.5),
        "T_MAX":  frange(10,  50.0, 5.0),
        "ALPHA":  frange(1.0, 10,  1.0),
        "BETA":   frange(1.0, 10,  1.0),
        "DELTA":  frange(5,  80.0, 5.0),
        "GAMMA":  frange(0.5, 5.0,  0.5),
        "ETA":    frange(2,   16.0, 1.0),
        "THETA":  frange(5,   25.0, 1.0),
    }
    keys = list(coarse.keys())
    combos = list(product(*[coarse[k] for k in keys]))
    n = len(combos)
    print(f"\nGrid search: {n} combinations (coarse grid)")
    print("-" * 60)

    all_results = []
    best = None

    for i, combo in enumerate(combos):
        params = dict(zip(keys, combo))
        print(f"\n  [{i+1}/{n}] " + "  ".join(f"{k}={v}" for k, v in params.items()))
        write_env(params)

        summary = run_experiment()
        if summary is None:
            continue

        score = fitness(summary, w_rejected, w_cpu, w_memory)
        is_best = best is None or score < best["score"]
        if is_best:
            best = {"params": params, "summary": summary, "score": score}

        log_trial(i, n, params, summary, score, is_best)
        all_results.append({"params": params, "summary": summary, "score": score})

    return all_results, best


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SDN adaptive timeout optimizer")
    parser.add_argument("--trials",     type=int,   default=30,       help="Number of trials (random/tpe)")
    parser.add_argument("--strategy",   type=str,   default="tpe",    choices=["random", "tpe", "grid"])
    parser.add_argument("--w-rejected", type=float, default=5.0,      help="Weight for rejection rate")
    parser.add_argument("--w-cpu",      type=float, default=3.0,      help="Weight for CPU usage")
    parser.add_argument("--w-memory",   type=float, default=1.0,      help="Weight for memory usage")
    parser.add_argument("--seed",       type=int,   default=None,     help="Random seed for reproducibility")
    parser.add_argument("--out",        type=str,   default="search_results.json")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    print(f"Objective weights — rejected:{args.w_rejected}  cpu:{args.w_cpu}  memory:{args.w_memory}")

    if args.strategy == "random":
        all_results, best = random_search(args.trials, args.w_rejected, args.w_cpu, args.w_memory)
    elif args.strategy == "tpe":
        all_results, best = tpe_search(args.trials, args.w_rejected, args.w_cpu, args.w_memory)
    elif args.strategy == "grid":
        all_results, best = grid_search(args.w_rejected, args.w_cpu, args.w_memory)

    if best is None:
        print("\nNo successful trials. Check your run.sh and results path.")
        sys.exit(1)

    print_best(best)
    save_results(all_results, args.out)

    # Write the best params back to .env
    write_env(best["params"])
    print(f".env updated with best parameters.")


if __name__ == "__main__":
    main()
