"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Coordinates the execution of network traffic generation
scenarios for the NetFlow anomaly detection experiment.
"""

import argparse
import csv
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


# ------------------------------------------------------
# Configuration: Home Directory and Random Seed
# ------------------------------------------------------
HOME = Path.home()
SEED = 1153  # Fixed random seed for reproducible experiments 


# ------------------------------------------------------
# Method: Generate UTC Timestamp
# ------------------------------------------------------
def timestamp():
    """
    Generate a UTC timestamp to record when experimental
    activities occur. Timestamps help document execution
    times and correlate traffic generation activities
    with collected NetFlow records.

    Returns:
        str: Current UTC timestamp in ISO 8601 format.
    """
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------
# Method: Generate Anomalous Traffic Schedule
# ------------------------------------------------------
def create_schedule(minutes):
    """
    Generate a reproducible schedule of anomalous traffic
    events for the experiment. Each hour includes six anomaly
    events consisting of two executions of each scenario.

    Three distinct 10 minute blocks are randomly selected
    per hour, with two anomaly events scheduled within each
    selected block. A fixed random seed ensures reproducible
    scheduling across experiments.

    Args:
        minutes (int): Total experiment duration in minutes.
            Must be a positive multiple of 60.

    Returns:
        list: Chronologically sorted tuples containing the
            scheduled minute and anomalous traffic scenario.

    Raises:
        ValueError: If the experiment duration is not a
            positive multiple of 60 minutes.
    """
    if minutes <= 0 or minutes % 60 != 0:
        raise ValueError(
            "Experiment duration must be a positive multiple of 60 minutes"
        )

    rng = random.Random(SEED)
    schedule = []

    for hour in range(minutes // 60):
        # Schedule two executions of each anomaly type per hour.
        scenarios = [
            "port_scan",
            "port_scan",
            "bandwidth_spike",
            "bandwidth_spike",
            "connection_burst",
            "connection_burst"
        ]

        # Randomize scenario order while preserving two of each type.
        rng.shuffle(scenarios)

        # Select three distinct 10 minute blocks per hour.
        # Place two anomalies in each selected block.
        blocks = rng.sample(range(6), 3)

        event_times = []

        for block in blocks:
            block_start = hour * 60 + block * 10

            # Schedule two anomalies within each selected block.
            first = block_start + rng.uniform(1, 3)
            second = block_start + rng.uniform(5, 7)

            event_times.extend([first, second])

        event_times.sort()

        # Assign shuffled scenarios to the scheduled event times.
        for minute, scenario in zip(event_times, scenarios):
            schedule.append((minute, scenario))

    return sorted(schedule)


# ------------------------------------------------------
# Method: Execute NetFlow Traffic Experiment
# ------------------------------------------------------
def main(minutes):
    """
    Coordinate the execution of normal and anomalous network
    traffic for the specified experiment duration.

    The method generates a reproducible anomaly schedule,
    starts normal traffic generation, executes anomalies at
    their scheduled times, and records experimental events
    in a CSV log. It also monitors execution status and
    terminates normal traffic generation when necessary.

    Args:
        minutes (int): Total experiment duration in minutes.
    """
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = HOME / f"experiment_{run_id}.csv"

    def log_event(event, details):
        with log_path.open("a", newline="") as file:
            writer = csv.writer(file)            
            # Write the CSV header only when the log is empty.
            if file.tell() == 0:
                writer.writerow(["timestamp_utc", "event", "details"])
            writer.writerow([timestamp(), event, details])

    schedule = create_schedule(minutes)

    print(f"Starting {minutes} minute experiment")
    print(f"Random seed: {SEED}")
    print(f"Experiment log: {log_path}")

    for minute, scenario in schedule:
        print(f"Minute {minute:.2f}: {scenario}")
        log_event(
            "anomaly_scheduled",
            f"minute={minute:.3f},scenario={scenario}"
        )

    duration = minutes * 60
    start = time.monotonic()
    normal = None
    status = "interrupted"

    log_event("experiment_start", f"duration={minutes},seed={SEED}")

    try:
        # Start normal traffic generation as a separate process.
        normal = subprocess.Popen([
            "python3",
            str(HOME / "normal_traffic.py"),
            "--minutes",
            str(minutes),
            "--seed",
            str(SEED)
        ])

        log_event("normal_traffic_start", f"seed={SEED}")

        for minute, scenario in schedule:
            # Calculate the remaining time until the next anomaly.
            remaining = minute * 60 - (time.monotonic() - start)

            if remaining > 0:
                time.sleep(remaining)

            log_event("anomaly_start", scenario)

            result = subprocess.run([
                "python3",
                str(HOME / "anomaly_traffic.py"),
                "--scenario",
                scenario
            ])

            log_event(
                "anomaly_end",
                f"{scenario},returncode={result.returncode}"
            )

            if result.returncode != 0:
                raise RuntimeError(f"Anomaly failed: {scenario}")

        # Wait until the requested experiment duration has elapsed.
        remaining = duration - (time.monotonic() - start)

        if remaining > 0:
            time.sleep(remaining)

        normal.wait()
        log_event("normal_traffic_end", f"returncode={normal.returncode}")

        if normal.returncode != 0:
            raise RuntimeError("Normal traffic generator failed")

        status = "completed"

    finally:
        # Terminate normal traffic if the experiment ends unexpectedly.
        if normal is not None and normal.poll() is None:
            normal.terminate()
            normal.wait()

        log_event("experiment_end", status)
        print(f"Experiment status: {status}")


# ------------------------------------------------------
# Main: Configure and Start Experiment
# ------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Set experiment duration in minutes, defaulting to 60.
    parser.add_argument("--minutes", type=int, default=60)
    args = parser.parse_args()
    main(args.minutes)