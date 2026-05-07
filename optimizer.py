import optuna
import subprocess
import pandas as pd
import os
import time

def objective(trial):

    alpha = trial.suggest_float("ALPHA", 0.5, 10)
    beta = trial.suggest_float("BETA", 0.5, 10)
    delta = trial.suggest_float("DELTA", 5, 40)
    eta = trial.suggest_float("ETA", 1, 20)
    theta = trial.suggest_float("THETA", 1, 20)

    env = os.environ.copy()
    env["ALPHA"] = str(alpha)
    env["BETA"] = str(beta)
    env["DELTA"] = str(delta)
    env["ETA"] = str(eta)
    env["THETA"] = str(theta)

    subprocess.run(["docker","compose","down"])

    subprocess.run(
        ["docker","compose","up","--build","-d","ryu"],
        env=env
    )

    time.sleep(5)

    subprocess.run(["sudo","python3","mininet/topology.py"])

    df = pd.read_csv("results/adaptive/750/metrics.csv")

    score = (
        df["rejected_flows"].max()*10 +
        df["packet_in_count"].max()*3 +
        df["cpu_percent"].mean()*1 +
        df["memory_mb"].mean()*1
    )

    return score


study = optuna.create_study(direction="minimize")
study.optimize(objective, n_trials=50)

print("Best parameters:", study.best_params)
