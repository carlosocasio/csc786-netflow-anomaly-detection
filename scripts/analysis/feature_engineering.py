"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Processes collected NetFlow records and extracts network
traffic features using different temporal aggregation
windows for evaluating anomaly detection with Isolation Forest.
"""

from pathlib import Path
import numpy as np
import pandas as pd


# ------------------------------------------------------
# Configuration: Data Files and Aggregation Parameters
# ------------------------------------------------------
BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data" / "lab_6h"

FLOW_FILE = DATA / "netflow_6h_raw.csv"  # Raw NetFlow dataset collected during the six hour experiment
EVENT_FILE = DATA / "experiment_20261108T055029Z.csv"  # Experiment log containing scheduled and recorded events

WINDOWS = [1, 5, 10]  # Temporal aggregation intervals in minutes.
CLIENT = "10.10.10.10"  # IP address of the traffic generation client
TIMEZONE = "America/New_York"  # Eastern time zone used for timestamp processing


# ------------------------------------------------------
# Configuration: NetFlow Features for Anomaly Detection
# ------------------------------------------------------
# Define the traffic features used to train and evaluate Isolation Forest.
FEATURES = [
    "flow_count",  # Number of flows within an aggregation window
    "total_bytes",  # Total bytes transferred
    "total_packets",  # Total packets transferred
    "unique_dst_ports",  # Number of distinct destination ports
    "unique_src_ports",  # Number of distinct source ports
    "avg_flow_duration",  # Average flow duration
    "avg_bytes_per_flow",  # Average bytes per flow
    "tcp_flow_ratio",  # Proportion of flows using TCP
    "flows_per_second",  # Average number of flows per second
    "bytes_per_second",  # Average number of bytes per second
    "short_flow_ratio",  # Proportion of flows classified as short
    "dst_port_entropy",  # Diversity of destination port distribution measured using entropy
]


# ------------------------------------------------------
# Method: Load Experiment Events and Anomaly Timestamps
# ------------------------------------------------------
def load_events():
    """
    Load the experiment log and extract the experiment start
    and end timestamps along with recorded anomaly intervals.

    The method identifies anomaly start and end events to
    establish the time periods during which anomalous traffic
    was generated. These intervals support labeling NetFlow
    aggregation windows for model evaluation.

    Returns:
        tuple: Experiment start timestamp, experiment end
            timestamp, and a list of anomaly dictionaries
            containing the scenario type and start and end
            timestamps.
    """
    events = pd.read_csv(EVENT_FILE)
    events["timestamp_utc"] = pd.to_datetime(
        events["timestamp_utc"], utc=True
    )

    start = events.loc[
        events["event"] == "experiment_start",
        "timestamp_utc"
    ].iloc[0]

    end = events.loc[
        events["event"] == "experiment_end",
        "timestamp_utc"
    ].iloc[0]

    anomalies = []
    current = None

    # Match anomaly start and end events to identify execution intervals.
    for row in events.itertuples(index=False):
        if row.event == "anomaly_start":
            current = {
                "type": row.details,
                "start": row.timestamp_utc
            }

        elif row.event == "anomaly_end" and current:
            current["end"] = row.timestamp_utc
            anomalies.append(current)
            current = None

    return start, end, anomalies


# ------------------------------------------------------
# Method: Load and Prepare NetFlow Records
# ------------------------------------------------------
def load_flows():
    """
    Load raw NetFlow records and prepare the data for feature
    extraction and temporal aggregation.

    The method converts collector timestamps to UTC, filters
    records originating from the traffic generation client,
    and converts selected NetFlow fields to numeric values.
    Missing packet counts, byte counts, and flow durations
    are replaced with zeros.

    Returns:
        pandas.DataFrame: Processed NetFlow records containing
            client traffic and standardized timestamps.
    """
    flows = pd.read_csv(FLOW_FILE, low_memory=False)

    # NetFlow timestamps are in the collector's local time.
    for column in ["ts", "te"]:
        flows[column] = (
            pd.to_datetime(flows[column])
            .dt.tz_localize(TIMEZONE)
            .dt.tz_convert("UTC")
        )

    # Retain flows originating from the traffic generation client.
    flows = flows[flows["sa"] == CLIENT].copy()

    for column in ["ipkt", "ibyt", "td", "sp", "dp"]:
        flows[column] = pd.to_numeric(
            flows[column], errors="coerce"
        )

    flows[["ipkt", "ibyt", "td"]] = (
        flows[["ipkt", "ibyt", "td"]].fillna(0)
    )

    return flows


# ------------------------------------------------------
# Method: Calculate Destination Port Entropy
# ------------------------------------------------------
def entropy(values):
    """
    Calculate Shannon entropy to measure the diversity of
    destination ports within a NetFlow aggregation window.

    Higher entropy values indicate a more diverse distribution
    of destination ports, which may be associated with unusual
    network activity such as port scanning.

    Args:
        values (pandas.Series): Destination port values
            used to calculate entropy.

    Returns:
        float: Shannon entropy in bits, or 0.0 if no valid
            destination port values are available.
    """
    counts = values.dropna().value_counts()

    if counts.empty:
        return 0.0

    probabilities = counts / counts.sum()
    return float(
        -(probabilities * np.log2(probabilities)).sum()
    )


# ------------------------------------------------------
# Method: Calculate NetFlow Traffic Features
# ------------------------------------------------------
def calculate_features(group, seconds):
    """
    Calculate network traffic features from NetFlow records
    within a specified temporal aggregation window.

    The method extracts 12 features describing traffic volume,
    port diversity, flow duration, protocol distribution,
    and connection rates. These features are used to evaluate
    anomaly detection using Isolation Forest.

    Args:
        group (pandas.DataFrame): NetFlow records associated
            with the aggregation window.
        seconds (int): Duration of the aggregation window
            in seconds.

    Returns:
        dict: Dictionary containing the 12 calculated traffic
            features, or zero values if the window is empty.
    """
    count = len(group)

    # Assign zero values when no flows occur within the window.
    if count == 0:
        return {feature: 0.0 for feature in FEATURES}

    bytes_total = group["ibyt"].sum()
    packets_total = group["ipkt"].sum()

    return {
        "flow_count": count,
        "total_bytes": bytes_total,
        "total_packets": packets_total,
        "unique_dst_ports": group["dp"].nunique(),
        "unique_src_ports": group["sp"].nunique(),
        "avg_flow_duration": group["td"].mean(),
        "avg_bytes_per_flow": bytes_total / count,
        "tcp_flow_ratio": (
            (group["pr"] == "TCP").sum() / count
        ),
        "flows_per_second": count / seconds,
        "bytes_per_second": bytes_total / seconds,
        "short_flow_ratio": (
            (group["td"] < 1).sum() / count
        ),
        "dst_port_entropy": entropy(group["dp"]),
    }


# ------------------------------------------------------
# Method: Build Temporal Aggregation Dataset
# ------------------------------------------------------
def build_dataset(flows, start, end, anomalies, minutes):
    """
    Build a NetFlow feature dataset using the specified
    temporal aggregation interval.

    The method divides the experiment into fixed time windows,
    calculates 12 network traffic features for each window,
    and assigns ground truth labels based on overlapping
    anomaly execution intervals.

    Args:
        flows (pandas.DataFrame): Processed NetFlow records.
        start (pandas.Timestamp): Experiment start timestamp.
        end (pandas.Timestamp): Experiment end timestamp.
        anomalies (list): Recorded anomaly execution intervals.
        minutes (int): Temporal aggregation interval in minutes.

    Returns:
        pandas.DataFrame: Aggregated NetFlow features, window
            timestamps, anomaly labels, and anomaly types.
    """
    seconds = minutes * 60

    # Align all intervals to the experiment start.
    # Use a fixed duration of 360 minutes for the six hour experiment.
    boundaries = pd.date_range(
        start=start,
        periods=(360 // minutes) + 1,
        freq=f"{minutes}min"
    )

    rows = []

    for index in range(len(boundaries) - 1):
        window_start = boundaries[index]
        window_end = boundaries[index + 1]

        # Assign each flow to its start time.
        group = flows[
            (flows["ts"] >= window_start)
            & (flows["ts"] < window_end)
        ]

        features = calculate_features(group, seconds)

        # Ground truth: any overlap with an anomaly.
        overlapping = [
            anomaly["type"]
            for anomaly in anomalies
            if anomaly["start"] < window_end
            and anomaly["end"] > window_start
        ]

        features["window_start"] = window_start
        features["window_end"] = window_end
        features["label"] = int(bool(overlapping))
        features["anomaly_type"] = (
            "|".join(sorted(set(overlapping)))
            if overlapping else "normal"
        )

        rows.append(features)

    return pd.DataFrame(rows)


# ------------------------------------------------------
# Method: Generate NetFlow Feature Datasets
# ------------------------------------------------------
def main():
    """
    Coordinate the NetFlow feature engineering process by
    loading experiment events and collected NetFlow records.

    The method filters traffic to the experiment duration,
    generates feature datasets using 1, 5, and 10 minute
    aggregation windows, and saves the resulting datasets
    as CSV files for Isolation Forest evaluation.
    """
    start, end, anomalies = load_events()
    flows = load_flows()

    # Keep only flows that started during the experiment.
    flows = flows[
        (flows["ts"] >= start)
        & (flows["ts"] < end)
    ].copy()

    print(f"Loaded {len(flows)} client NetFlow records")
    print(f"Loaded {len(anomalies)} anomaly events")

    # Generate and save datasets for each aggregation interval.
    for minutes in WINDOWS:
        dataset = build_dataset(
            flows, start, end, anomalies, minutes
        )

        output = DATA / f"netflow_features_{minutes}min.csv"
        dataset.to_csv(output, index=False)

        print(
            f"{minutes} minute windows: "
            f"{len(dataset)} records, "
            f"{dataset['label'].sum()} anomalous"
        )
        print(f"Saved: {output}")


if __name__ == "__main__":
    main()