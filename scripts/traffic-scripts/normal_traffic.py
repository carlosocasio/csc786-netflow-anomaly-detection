"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest 

Description:
Generates normal network traffic to establish baseline behavior
for evaluating anomaly detection using Isolation Forest.
"""

import argparse
import csv
import random
import socket
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ------------------------------------------------------
# Configuration: Server Address and Traffic Log
# ------------------------------------------------------
SERVER = "10.20.20.10"
LOG = Path.home() / "traffic_log.csv"


# ------------------------------------------------------
# Method: Generate UTC Timestamp
# ------------------------------------------------------
def timestamp():
    """
    Generate a UTC timestamp to record when network traffic
    is generated. Timestamps help correlate traffic generation
    activities with collected NetFlow records.
    """
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------
# Method: Execute System Command
# ------------------------------------------------------
def command(args, timeout=10):
    """
    Execute system commands used to generate network traffic.
    The method checks execution status and handles command
    failures, timeouts, and operating system errors.

    Args:
        args (list): Command and arguments to execute.
        timeout (int): Maximum execution time in seconds.
            Defaults to 10 seconds.

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

        if result.returncode != 0:
            print(f"Command failed: {' '.join(args)}")
            print(f"Error: {result.stderr.strip()}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(args)}")
        return False

    except OSError as error:
        print(f"Command error: {error}")
        return False


# ------------------------------------------------------
# Method: Generate HTTP Traffic
# ------------------------------------------------------
def http():
    """
    Generate HTTP traffic by sending a request to the server
    on port 8000. This simulates normal web activity for
    establishing baseline network behavior.

    Returns:
        bool: True if the server returns HTTP status 200,
            otherwise False.
    """
    try:
        with urllib.request.urlopen(
            f"http://{SERVER}:8000", timeout=5
        ) as response:
            return response.status == 200
    except Exception:
        return False


# ------------------------------------------------------
# Method: Generate HTTPS Traffic
# ------------------------------------------------------
def https():
    """
    Generate HTTPS traffic by sending a request to the server
    on port 8443 using curl. This simulates encrypted web
    activity for establishing baseline network behavior.

    Returns:
        bool: True if the curl command completes successfully,
            otherwise False.
    """
    return command([
        "curl", "-ksS", "--max-time", "5",
        f"https://{SERVER}:8443/"
    ])


# ------------------------------------------------------
# Method: Generate SSH Traffic
# ------------------------------------------------------
def ssh():
    """
    Generate SSH traffic by establishing a TCP connection
    to the server on port 22 without requiring authentication.
    The method verifies SSH connectivity by checking the
    server's identification banner.

    Returns:
        bool: True if the server responds with an SSH
            identification banner, otherwise False.
    """
    try:
        with socket.create_connection((SERVER, 22), timeout=5) as conn:
            banner = conn.recv(256)
            return banner.startswith(b"SSH-")
    except (OSError, socket.timeout):
        return False


# ------------------------------------------------------
# Method: Generate ICMP Traffic
# ------------------------------------------------------
def icmp():
    """
    Generate ICMP traffic by sending three echo requests
    to the server using the ping command. This simulates
    normal network connectivity checks for establishing
    baseline network behavior.

    Returns:
        bool: True if the ping command completes successfully,
            otherwise False.
    """
    return command([
        "ping", "-c", "3", "-W", "2", SERVER
    ])


# ------------------------------------------------------
# Method: Generate DNS Traffic
# ------------------------------------------------------
def dns():
    """
    Generate DNS traffic by querying the server for the
    IPv4 address of server.lab using the dig command.
    This simulates normal DNS resolution activity for
    establishing baseline network behavior.

    The method verifies that the DNS query succeeds and
    that the response contains the expected server IP address.

    Returns:
        bool: True if the DNS query succeeds and returns
            the expected IP address, otherwise False.
    """
    try:
        result = subprocess.run(
            [
                "dig", f"@{SERVER}", "server.lab",
                "A", "+short", "+time=2", "+tries=1"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )
        return (
            result.returncode == 0
            and SERVER in result.stdout.splitlines()
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


# ------------------------------------------------------
# Method: Generate TCP Traffic
# ------------------------------------------------------
def tcp():
    """
    Generate TCP traffic using iperf3 to simulate normal
    network data transfers. The method establishes a TCP
    connection to the server and transfers data for two
    seconds to establish baseline network behavior.

    Returns:
        bool: True if the iperf3 command completes successfully,
            otherwise False.
    """
    return command([
        "iperf3", "-c", SERVER,
        "-b", "1M",
        "-t", "2"
    ], timeout=20)


# ------------------------------------------------------
# Method: Generate UDP Traffic
# ------------------------------------------------------
def udp():
    """
    Generate UDP traffic using iperf3 to simulate normal
    network data transfers. The method sends UDP traffic
    to the server at a target bitrate of 100 Kbps for two
    seconds to establish baseline network behavior.

    Returns:
        bool: True if the iperf3 command completes successfully,
            otherwise False.
    """
    return command([
        "iperf3", "-c", SERVER, "-u",
        "-b", "100K", "-t", "2"
    ], timeout=20)


# ------------------------------------------------------
# Configuration: Network Traffic Types
# ------------------------------------------------------
# Map each traffic type to its corresponding generation method.
TRAFFIC = {
    "HTTP": http,
    "HTTPS": https,
    "SSH": ssh,
    "ICMP": icmp,
    "DNS": dns,
    "TCP": tcp,
    "UDP": udp
}


# ------------------------------------------------------
# Configuration: Traffic Generation Parameters
# ------------------------------------------------------
# Parse command line arguments for duration and random seed.
parser = argparse.ArgumentParser()
parser.add_argument("--minutes", type=float, default=5)
parser.add_argument("--seed", type=int, default=1153)
args = parser.parse_args()

# Initialize the random generator and calculate the end time.
rng = random.Random(args.seed)
end = time.monotonic() + args.minutes * 60

print("Starting normal traffic:", timestamp())
print(f"Duration: {args.minutes} minutes")
print(f"Random seed: {args.seed}")


# ------------------------------------------------------
# Main: Generate and Log Normal Network Traffic
# ------------------------------------------------------
# Open the traffic log in append mode and initialize CSV logging.
with LOG.open("a", newline="") as file:
    writer = csv.writer(file)

    # Write CSV headers only when the log file is empty.
    if file.tell() == 0:
        writer.writerow([
            "timestamp_utc",
            "traffic_type",
            "success"
        ])

    # Execute each traffic type once before randomized
    # selection to ensure all traffic types are attempted.
    for name, generator in TRAFFIC.items():
        success = generator()
        now = timestamp()

        writer.writerow([now, name, success])
        file.flush()

        print(now, name, "OK" if success else "FAILED")

    # Continue generating a random mixture of network traffic.
    while time.monotonic() < end:
        name = rng.choice(list(TRAFFIC))
        success = TRAFFIC[name]()
        now = timestamp()

        writer.writerow([now, name, success])
        file.flush()

        print(now, name, "OK" if success else "FAILED")

        # Randomize the delay between traffic generation events.
        remaining = end - time.monotonic()

        if remaining > 0:
            time.sleep(min(rng.uniform(1, 3), remaining))

print("Finished:", timestamp())