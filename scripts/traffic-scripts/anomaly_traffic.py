"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Generates anomalous network traffic to simulate unusual network
behavior for evaluating anomaly detection using Isolation Forest.
"""

import argparse
import csv
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


# ------------------------------------------------------
# Configuration: Server Address and Anomaly Log
# ------------------------------------------------------
SERVER = "10.20.20.10"
LOG = Path.home() / "anomaly_log.csv"


# ------------------------------------------------------
# Method: Generate UTC Timestamp
# ------------------------------------------------------
def timestamp():
    """
    Generate a UTC timestamp to record when anomalous network
    traffic is generated. Timestamps help correlate anomalous
    traffic activities with collected NetFlow records.
    """
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------
# Method: Execute System Command
# ------------------------------------------------------
def run_command(args, timeout):
    """
    Execute system commands used to generate anomalous network
    traffic. The method checks execution status and handles
    command failures, timeouts, and operating system errors.

    Args:
        args (list): Command and arguments to execute.
        timeout (int): Maximum execution time in seconds.

    Returns:
        bool: True if the command executes successfully,
            otherwise False.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# ------------------------------------------------------
# Method: Generate Port Scanning Traffic
# ------------------------------------------------------
def port_scan():
    """
    Generate anomalous network traffic by performing a TCP
    port scan against the server using Nmap. The method scans
    ports 1 through 1000 to simulate network reconnaissance
    activity for evaluating anomaly detection.

    Returns:
        bool: True if the Nmap command completes successfully,
            otherwise False.
    """
    return run_command([
        "nmap", "-sT", "-Pn", # Performs a TCP connect scan and skips host discovery
        "-p", "1-1000", # Scans TCP ports 1 through 1000
        SERVER
    ], timeout=120) # Limits command execution to 120 seconds


# ------------------------------------------------------
# Method: Generate Bandwidth Spike
# ------------------------------------------------------
def bandwidth_spike():
    """
    Generate anomalous TCP traffic using iperf3 to simulate
    an unusually high volume of network data transfers.
    The method targets a bitrate of 20 Mbps for 30 seconds
    to evaluate the detection of bandwidth anomalies.

    Returns:
        bool: True if the iperf3 command completes successfully,
            otherwise False.
    """
    return run_command([
        "iperf3", "-c", SERVER,
        "-p", "5202", # Uses TCP port 5202
        "-b", "20M", # Sets a target bitrate of 20 Mbps
        "-t", "30" # Generates traffic for 30 seconds
    ], timeout=60) # Limits command execution to 60 seconds


# ------------------------------------------------------
# Method: Generate TCP Connection Burst
# ------------------------------------------------------
def connection_burst():
    """
    Generate anomalous network traffic by initiating multiple
    TCP connection attempts to simulate a connection burst.
    This activity is intended to evaluate the detection of
    unusual connection patterns using Isolation Forest.

    Returns:
        bool: True if at least one TCP connection succeeds,
            otherwise False.
    """
    attempts = 200
    connected = 0

    for _ in range(attempts):
        try:
            with socket.create_connection(
                (SERVER, 8000), timeout=2
            ):
                connected += 1
        except OSError:
            pass

        time.sleep(0.02) # Introduce a 20 ms delay between connection attempts.

    return connected > 0


# ------------------------------------------------------
# Configuration: Anomalous Traffic Scenarios
# ------------------------------------------------------
SCENARIOS = {
    "port_scan": port_scan,
    "bandwidth_spike": bandwidth_spike,
    "connection_burst": connection_burst
}


# ------------------------------------------------------
# Method: Execute Anomalous Traffic Scenario
# ------------------------------------------------------
def execute(name):
    """
    Execute a selected anomalous traffic scenario and record
    its execution results. The method captures the start and
    end timestamps, reports execution status, and logs the
    results to a CSV file for experimental documentation.

    Args:
        name (str): Name of the anomalous traffic scenario
            to execute.

    Returns:
        bool: True if the selected scenario succeeds,
            otherwise False.
    """
    start = timestamp()
    print(f"Starting {name}: {start}", flush=True)

    success = SCENARIOS[name]()

    end = timestamp()
    print(
        f"Finished {name}: {end} "
        f"Success: {success}",
        flush=True
    )

    with LOG.open("a", newline="") as file:
        writer = csv.writer(file)

        # Write the CSV header only when the log file is empty.
        if file.tell() == 0:
            writer.writerow([
                "scenario",
                "start_utc",
                "end_utc",
                "success"
            ])

        writer.writerow([
            name,
            start,
            end,
            success
        ])
    return success


# ------------------------------------------------------
# Configuration: Command Line Arguments
# ------------------------------------------------------
parser = argparse.ArgumentParser()

# Allow execution of an individual scenario or all scenarios.
parser.add_argument(
    "--scenario",
    choices=list(SCENARIOS) + ["all"],
    default="all"
)
args = parser.parse_args()


# ------------------------------------------------------
# Main: Execute Selected Anomalous Traffic Scenarios
# ------------------------------------------------------
if args.scenario == "all":
    results = [execute(name) for name in SCENARIOS]
    success = all(results)
else:
    success = execute(args.scenario)

# Return exit code 0 if successful, otherwise 1.
raise SystemExit(0 if success else 1)