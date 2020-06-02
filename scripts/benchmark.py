import subprocess
import os
from time import time
from random import randint
import copy 

import requests
import pandas as pd
import matplotlib.pyplot as plt

MAX_THREADS = 12 

LIN_ENUM_URL = "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
SMART_ENUM_URL = "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh"

ENUMY_LOCATION = "./enumy"
LIN_ENUM_LOCATION = "/tmp/LinEnum.sh"
SMART_ENUM_LOCATION = "/tmp/lse.sh"



def profile(full_scan=False, threads=6) -> dict:
    
    results = dict()
    cmd = [ENUMY_LOCATION, "-t", str(threads)]
    if full_scan:
         cmd.append("-f")

    start = time()
    proc = subprocess.Popen(cmd)
    proc.wait()
    stop = time() - start

    results["total_time"] = stop

    if(full_scan):
        results["scan_type"] = "Enumy - full_scan"
    else:
        results["scan_type"] = "Enumy - quick_scan"
        
    results["threads"] = threads
    return results

def linenum():
    data = requests.get(LIN_ENUM_URL).text
    with open(LIN_ENUM_LOCATION, "w") as f:
        f.writelines(data)
    os.system("chmod +x " + LIN_ENUM_LOCATION)

    start = time()
    proc = subprocess.Popen(["/bin/bash", LIN_ENUM_LOCATION])
    proc.wait()
    stop = time() - start

    results = dict()
    results["total_time"] = stop
    results["scan_type"] = "LinEnum.sh"
    return results

def smart_enum():
    data = requests.get(SMART_ENUM_URL).text
    with open(SMART_ENUM_LOCATION, "w") as f:
        f.writelines(data)
    os.system("chmod +x " + SMART_ENUM_LOCATION)

    start = time()
    proc = subprocess.Popen("echo '' | /bin/bash " + SMART_ENUM_LOCATION, shell=True)
    proc.wait()
    stop = time() - start

    results = dict()
    results["total_time"] = stop
    results["scan_type"] = "linux-smart-enumeration"
    return results


def get_results(start, stop) -> list:

    total_data = list()
    smart_enum_data = smart_enum()
    linenum_data = linenum()

    for x in range(start, stop):
        
        temp_smart_enum_data = copy.copy(smart_enum_data)
        temp_linenum_data = copy.copy(linenum_data)
        temp_linenum_data["threads"] = x
        temp_smart_enum_data["threads"] = x

        total_data.append(profile(full_scan=True, threads=x))
        total_data.append(profile(full_scan=False, threads=x))
        total_data.append(temp_linenum_data)
        total_data.append(temp_smart_enum_data)

    return total_data

    

if __name__ == "__main__":
    print("Starting bechmark")
    start = 4
    stop = 13
    results = get_results(start, stop)
    df = pd.DataFrame(results)
    df = df.pivot(index="threads", columns='scan_type', values='total_time')
    ax = df.plot.line(title="Bench-Marks i7-7700k / 1.8 Million Files")
    ax.set_ylabel("Time (sec)")
    ax.locator_params(integer=True)
    plt.xticks(range(start, stop, 1))
    ax.figure.savefig("benchmark.png")
    print("Stoping bechmark")