"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Generates reproducible synthetic NetFlow records representing seven
days of network activity for evaluating anomaly detection using
Isolation Forest.

The script simulates normal network traffic and three anomaly
scenarios: port scanning, connection bursts, and bandwidth spikes.

The generated records follow the same NetFlow format used in the
six hour lab experiment and support temporal aggregation into
1, 5, and 10 minute windows.

All generated traffic is synthetic and does not represent actual
network observations.
"""

from pathlib import Path
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import csv
import numpy as np


# ------------------------------------------------------
# Configuration: Data Directory
# ------------------------------------------------------
BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data" / "synthetic_7d"


# ------------------------------------------------------
# Configuration: Synthetic Experiment Parameters
# ------------------------------------------------------
SEED = 1153
DURATION_HOURS = 168
CLIENT = "10.10.10.10"
SERVER = "10.20.20.10"
START = datetime(2026, 11, 16, 0, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=DURATION_HOURS)


# ------------------------------------------------------
# Configuration: Output Files
# ------------------------------------------------------
FLOW_FILE = DATA / "netflow_7d_raw.csv"
EVENT_FILE = DATA / "experiment_7d.csv"


# ------------------------------------------------------
# Configuration: Anomaly Generation Parameters
# ------------------------------------------------------
EPISODES_PER_DAY = 8
MIN_EPISODE_GAP_SECONDS = 20 * 60


# ------------------------------------------------------
# Configuration: CSV Output Columns
# ------------------------------------------------------
FLOW_COLUMNS = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "ipkt", "ibyt"]
EVENT_COLUMNS = ["timestamp_utc", "event", "details"]


# ------------------------------------------------------
# Method: Format UTC Timestamps
# ------------------------------------------------------
def utc_string(moment):
    """
    Convert a datetime object into an ISO 8601 timestamp
    with microsecond precision.

    The formatted timestamp is used when recording synthetic
    experiment events in the CSV event log.

    Args:
        moment (datetime): Timestamp to format.

    Returns:
        str: ISO 8601 formatted timestamp with microseconds.
    """
    return moment.isoformat(timespec="microseconds")


# ------------------------------------------------------
# Method: Format NetFlow Collector Timestamps
# ------------------------------------------------------
def collector_string(moment):
    # The existing feature engineering script localizes naive timestamps
    # as America/New_York, so write Eastern standard time for November 2026.
    return moment.astimezone(ZoneInfo("America/New_York")).strftime("%Y-%m-%d %H:%M:%S.%f")


# ------------------------------------------------------
# Method: Generate Synthetic NetFlow Record
# ------------------------------------------------------
def make_flow(moment, port, protocol, packets, byte_count, duration, source_port):
    """
    Generate a synthetic NetFlow record using the supplied
    traffic parameters.

    The method calculates the flow ending timestamp and
    ensures it does not exceed the experiment duration.
    It also calculates the actual flow duration and formats
    the timestamps to match the NetFlow collector.

    Args:
        moment (datetime): Flow starting timestamp.
        port (int): Destination port number.
        protocol (str): Network protocol.
        packets (int): Number of packets in the flow.
        byte_count (int): Total bytes transferred.
        duration (float): Requested flow duration in seconds.
        source_port (int): Source port number.

    Returns:
        list: Synthetic NetFlow record containing timestamps,
            duration, source and destination addresses,
            ports, protocol, packet count, and byte count.
    """
    finish = min(moment + timedelta(seconds=duration), END - timedelta(microseconds=1))
    actual_duration = max(0.001, (finish - moment).total_seconds())
    return [
        collector_string(moment), collector_string(finish),
        round(actual_duration, 3), CLIENT, SERVER,
        int(source_port), int(port), protocol,
        int(packets), int(byte_count),
    ]


# ------------------------------------------------------
# Method: Generate Normal Synthetic Network Traffic
# ------------------------------------------------------
def normal_flows(rng, minute_start):
    """
    Generate synthetic NetFlow records representing normal
    network activity during a one minute interval.

    The method adjusts traffic volume based on the time
    of day and day of the week. It uses random distributions
    to simulate variations in connection counts, destination
    ports, packet counts, byte counts, and flow durations.

    Each generated flow is formatted using make_flow().

    Args:
        rng (numpy.random.Generator): Random number generator
            used to produce reproducible traffic.
        minute_start (datetime): Starting timestamp of the
            one minute interval.

    Yields:
        list: Synthetic NetFlow record representing normal
            network traffic.
    """
    local_hour = minute_start.astimezone(timezone(timedelta(hours=-5))).hour
    daytime = 1.0 if 8 <= local_hour < 19 else 0.58
    weekday = 1.0 if minute_start.weekday() < 5 else 0.76
    mean = 12.0 * daytime * weekday
    count = int(rng.poisson(mean))

    for _ in range(count):
        moment = minute_start + timedelta(seconds=float(rng.uniform(0, 60)))
        if moment >= END:
            continue
        port = int(rng.choice([443, 80, 53, 22, 8000], p=[0.48, 0.19, 0.20, 0.05, 0.08]))
        protocol = "UDP" if port == 53 else "TCP"
        packets = max(1, int(rng.lognormal(mean=2.0, sigma=0.75)))
        mean_packet_size = float(rng.uniform(75, 900))
        byte_count = max(packets * 40, int(packets * mean_packet_size))
        duration = float(rng.lognormal(mean=-0.1, sigma=1.0))
        source_port = int(rng.integers(32768, 61000))
        yield make_flow(moment, port, protocol, packets, byte_count, duration, source_port)


# ------------------------------------------------------
# Method: Schedule Synthetic Anomaly Episodes
# ------------------------------------------------------
def schedule_episodes(rng):
    scenarios = ["port_scan", "connection_burst", "bandwidth_spike"]
    episodes = []
    for day in range(DURATION_HOURS // 24):
        day_start = START + timedelta(days=day)
        # Spread episodes through the day, avoiding tightly clustered events.
        for slot in range(EPISODES_PER_DAY):
            slot_start = day_start + timedelta(seconds=(slot * 3 + 1) * 3600)
            offset = int(rng.integers(0, 35 * 60))
            beginning = slot_start + timedelta(seconds=offset)
            duration = int(rng.integers(45, 181))
            ending = beginning + timedelta(seconds=duration)
            scenario = scenarios[(slot + day) % len(scenarios)]
            intensity = float(rng.uniform(0.65, 1.35))
            episodes.append((beginning, ending, scenario, intensity))
    episodes.sort(key=lambda entry: entry[0])
    for previous, current in zip(episodes, episodes[1:]):
        assert (current[0] - previous[1]).total_seconds() >= MIN_EPISODE_GAP_SECONDS
    return episodes


# ------------------------------------------------------
# Method: Write Synthetic Experiment Events
# ------------------------------------------------------
def write_events(episodes):
    """
    Write the synthetic experiment events to a CSV file.

    The method records the experiment starting time, ending
    time, and the beginning and ending of each anomaly episode.

    Events are sorted chronologically and written to the
    experiment event log using UTC timestamps.

    Args:
        episodes (list): Scheduled anomaly episodes containing
            starting time, ending time, scenario, and intensity.

    Returns:
        None
    """
    events = [(START, "experiment_start", f"duration={DURATION_HOURS * 60},seed={SEED},synthetic=true")]
    for start, end, scenario, _ in episodes:
        events.append((start, "anomaly_start", scenario))
        events.append((end, "anomaly_end", f"{scenario},returncode=0"))
    events.append((END, "experiment_end", "synthetic=true"))
    events.sort(key=lambda row: row[0])
    with EVENT_FILE.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(EVENT_COLUMNS)
        for moment, event, details in events:
            writer.writerow([utc_string(moment), event, details])


# ------------------------------------------------------
# Method: Execute Synthetic NetFlow Experiment
# ------------------------------------------------------
def main():
    """
    Execute the seven day synthetic NetFlow experiment.

    The method initializes the random number generator,
    schedules anomaly episodes, and creates the experiment
    event log.

    It generates normal network traffic for each minute
    and adds synthetic anomaly traffic whenever an anomaly
    episode overlaps that interval.

    Three anomaly scenarios are simulated:
        port_scan: Connections to multiple destination ports.
        connection_burst: High volumes of short TCP connections.
        bandwidth_spike: Flows with large packet and byte counts.

    Generated flows are sorted chronologically and written
    to a CSV file using the same format as the original
    NetFlow collector.

    The method processes one minute at a time to reduce
    memory usage and displays an experiment summary when
    generation is complete.

    Returns:
        None
    """
    DATA.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)
    episodes = schedule_episodes(rng)
    write_events(episodes)

    # Generate normal and anomaly traffic one minute at a time.
    # Sort the flows by timestamp to maintain chronological order.
    # Processing one minute at a time reduces memory usage.
    total = 0
    with FLOW_FILE.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(FLOW_COLUMNS)
        minute = START
        episode_index = 0
        while minute < END:
            minute_end = minute + timedelta(minutes=1)
            rows = list(normal_flows(rng, minute))
            while episode_index < len(episodes) and episodes[episode_index][1] <= minute:
                episode_index += 1
            j = episode_index
            while j < len(episodes) and episodes[j][0] < minute_end:
                start, end, scenario, intensity = episodes[j]
                overlap_start = max(minute, start)
                overlap_end = min(minute_end, end)
                if overlap_start < overlap_end:
                    # Spread each episode's flow count over its actual duration.
                    fraction = (overlap_end - overlap_start).total_seconds() / (end - start).total_seconds()
                    if scenario == "port_scan":
                        count = max(1, int(round(110 * intensity * fraction)))
                    elif scenario == "connection_burst":
                        count = max(1, int(round(230 * intensity * fraction)))
                    else:
                        count = max(1, int(round(65 * intensity * fraction)))
                    for i in range(count):
                        moment = overlap_start + timedelta(seconds=float(rng.uniform(0, (overlap_end - overlap_start).total_seconds())))
                        if scenario == "port_scan":
                            port, protocol = 1000 + int(rng.integers(0, 55000)), "TCP"
                            packets = int(rng.integers(1, 4))
                            byte_count = packets * int(rng.integers(40, 90))
                            duration = float(rng.uniform(0.001, 0.15))
                        elif scenario == "connection_burst":
                            port, protocol = int(rng.choice([80, 443, 8000])), "TCP"
                            packets = int(rng.integers(2, 13))
                            byte_count = packets * int(rng.integers(55, 500))
                            duration = float(rng.uniform(0.005, 0.6))
                        else:
                            port, protocol = 8000, "TCP"
                            packets = int(rng.integers(200, 1300))
                            byte_count = packets * int(rng.integers(900, 1400))
                            duration = float(rng.uniform(1.0, 12.0))
                        rows.append(make_flow(moment, port, protocol, packets, byte_count, duration, int(rng.integers(32768, 61000))))
                j += 1
            rows.sort(key=lambda row: row[0])
            writer.writerows(rows)
            total += len(rows)
            minute = minute_end

    print(f"Synthetic experiment: {DURATION_HOURS} hours")
    print(f"Seed: {SEED}")
    print(f"Anomaly episodes: {len(episodes)}")
    print(f"Flow records: {total:,}")
    print(f"Raw flows: {FLOW_FILE}")
    print(f"Event log: {EVENT_FILE}")


if __name__ == "__main__":
    main()
