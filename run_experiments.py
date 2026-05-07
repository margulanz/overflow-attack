import os
import subprocess
import itertools
import time

ALPHA = [1,3,5]
BETA = [1,3,5]
DELTA = [10,20,30]
ETA = [5,8,12]
THETA = [5,10,15]

params = list(itertools.product(ALPHA, BETA, DELTA, ETA, THETA))

for alpha,beta,delta,eta,theta in params:

    print("Running experiment:", alpha,beta,delta,eta,theta)

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

    subprocess.run(["docker","compose","down"])
