"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Processes synthetic NetFlow records representing seven days of
network activity and extracts 12 traffic features using 1, 5,
and 10 minute temporal aggregation windows.

The synthetic dataset is used to evaluate the behavior of
Isolation Forest with a larger number of observations.
"""

from pathlib import Path
import numpy as np
import pandas as pd


# ------------------------------------------------------
# Configuration: Data Directory
# ------------------------------------------------------
BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data" / "synthetic_7d"


# ------------------------------------------------------
# Configuration: Input Files
# ------------------------------------------------------
FLOW_FILE = DATA / "netflow_7d_raw.csv"
EVENT_FILE = DATA / "experiment_7d.csv"


# ------------------------------------------------------
# Configuration: Experiment Parameters
# ------------------------------------------------------
WINDOWS = [1, 5, 10]
CLIENT = "10.10.10.10"
TIMEZONE = "America/New_York"


# ------------------------------------------------------
# Configuration: NetFlow Features
# ------------------------------------------------------
FEATURES = [
    "flow_count",
    "total_bytes",
    "total_packets",
    "unique_dst_ports",
    "unique_src_ports",
    "avg_flow_duration",
    "avg_bytes_per_flow",
    "tcp_flow_ratio",
    "flows_per_second",
    "bytes_per_second",
    "short_flow_ratio",
    "dst_port_entropy",
]


# ------------------------------------------------------
# Method: Load Synthetic Experiment Events
# ------------------------------------------------------
def load_events():
    """
    Load experiment timestamps and anomaly intervals from
    the synthetic experiment event log.

    The method reads the CSV event log and converts timestamps
    to UTC. It identifies the experiment starting and ending
    times and matches anomaly start and end events to determine
    the duration of each anomaly episode.

    The method also validates the event sequence to ensure
    anomaly intervals are properly recorded and the experiment
    duration is valid.

    Returns:
        tuple: Experiment starting timestamp, ending timestamp,
            and a list of anomaly intervals containing the
            anomaly type, starting time, and ending time.

    Raises:
        ValueError: If anomaly events are incorrectly paired,
            anomaly durations are invalid, or the experiment
            duration is invalid.
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

    for row in events.itertuples(index=False):

        if row.event == "anomaly_start":
            if current is not None:
                raise ValueError("Overlapping anomaly start events")

            current = {
                "type": row.details,
                "start": row.timestamp_utc
            }

        elif row.event == "anomaly_end":
            if current is None:
                raise ValueError("Anomaly end without a start")

            if row.timestamp_utc <= current["start"]:
                raise ValueError("Invalid anomaly duration")

            current["end"] = row.timestamp_utc
            anomalies.append(current)
            current = None

    if current is not None:
        raise ValueError("Anomaly start without an end")

    if end <= start:
        raise ValueError("Invalid experiment duration")

    return start, end, anomalies


# ------------------------------------------------------
# Method: Load Synthetic NetFlow Records
# ------------------------------------------------------
def load_flows():
    """
    Load and prepare synthetic NetFlow records for feature engineering.

    The method reads the synthetic NetFlow CSV file and converts
    the starting and ending timestamps from Eastern time to UTC.

    It filters the records to include only traffic originating
    from the configured client and converts packet counts,
    byte counts, flow durations, and port numbers to numeric
    values.

    Missing or invalid packet counts, byte counts, and flow
    durations are replaced with zero.

    Returns:
        pandas.DataFrame: Synthetic NetFlow records with
            standardized timestamps and numeric fields.
    """

    flows = pd.read_csv(FLOW_FILE, low_memory=False)

    for column in ["ts", "te"]:
        flows[column] = (
            pd.to_datetime(flows[column])
            .dt.tz_localize(TIMEZONE)
            .dt.tz_convert("UTC")
        )

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
    Calculate Shannon entropy for destination port values.

    The method measures the distribution of destination ports
    within a collection of NetFlow records. Higher entropy
    indicates traffic distributed across more destination ports,
    while lower entropy indicates traffic concentrated on
    fewer ports.

    Missing values are excluded from the calculation.
    If no valid port values exist, the method returns zero.

    Args:
        values (pandas.Series): Destination port values
            from the NetFlow records.

    Returns:
        float: Shannon entropy calculated using base 2.
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
    Calculate the 12 NetFlow features used for anomaly detection.

    The method processes a group of NetFlow records within
    a specified aggregation interval and calculates traffic
    volume, port diversity, flow duration, protocol ratios,
    traffic rates, and destination port entropy.

    The same 12 features are used in the original six hour
    experiment to maintain consistency between datasets.

    If the aggregation window contains no flows, all feature
    values are set to zero.

    Args:
        group (pandas.DataFrame): NetFlow records belonging
            to the aggregation window.
        seconds (int): Duration of the aggregation window
            in seconds.

    Returns:
        dict: Dictionary containing the 12 calculated
            NetFlow features.
    """
    count = len(group)

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
# Method: Build Aggregated NetFlow Dataset
# ------------------------------------------------------
def build_dataset(flows, start, end, anomalies, minutes):
    """
    Build a NetFlow dataset using the specified aggregation interval.

    The method divides the experiment into fixed time windows
    of 1, 5, or 10 minutes and groups NetFlow records according
    to their starting timestamps.

    For each window, it calculates the 12 NetFlow features
    and assigns a ground truth anomaly label based on whether
    the window overlaps a recorded anomaly episode.

    Windows containing anomalous activity receive a label
    of 1, while normal windows receive a label of 0.
    Windows without any flows are assigned zero feature values.

    The method also records the anomaly type associated
    with each window. Multiple anomaly types are recorded
    if more than one episode overlaps the same window.

    Args:
        flows (pandas.DataFrame): Synthetic NetFlow records.
        start (pandas.Timestamp): Experiment starting timestamp.
        end (pandas.Timestamp): Experiment ending timestamp.
        anomalies (list): Recorded anomaly intervals containing
            the anomaly type, starting time, and ending time.
        minutes (int): Aggregation interval in minutes.

    Returns:
        pandas.DataFrame: Aggregated NetFlow dataset containing
            the 12 features, window timestamps, anomaly labels,
            and anomaly types.

    Raises:
        ValueError: If the experiment duration is not evenly
            divisible by the aggregation interval.
    """
    seconds = minutes * 60

    # Determine the actual experiment duration.
    duration = (end - start).total_seconds()

    window_count = int(duration // seconds)

    if duration % seconds != 0:
        raise ValueError(
            f"Experiment duration is not divisible by {minutes} minutes"
        )

    boundaries = pd.date_range(
        start=start,
        periods=window_count + 1,
        freq=f"{minutes}min"
    )

    # Group flows into windows using their starting timestamps.
    # This avoids repeatedly searching the entire dataset.
    window_numbers = (
        (flows["ts"] - start).dt.total_seconds() // seconds
    ).astype(int)

    grouped = {
        int(index): group
        for index, group in flows.groupby(window_numbers)
    }

    rows = []

    for index in range(window_count):

        window_start = boundaries[index]
        window_end = boundaries[index + 1]

        group = grouped.get(index)

        if group is None:
            group = flows.iloc[0:0]

        features = calculate_features(group, seconds)

        # Label any window overlapping an anomaly episode.
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
# Method: Generate Synthetic Feature Datasets
# ------------------------------------------------------
def main():
    """
    Generate aggregated NetFlow feature datasets for the
    seven day synthetic experiment.

    The method loads the synthetic NetFlow records and
    experiment event log, then filters traffic to include
    only flows within the experiment duration.

    It generates separate datasets using 1, 5, and 10 minute
    aggregation intervals. Each dataset contains the 12
    NetFlow features, window timestamps, and ground truth
    anomaly labels.

    The resulting datasets are saved as CSV files for
    evaluation using Isolation Forest.

    The method also displays the number of loaded flows,
    anomaly episodes, aggregation windows, and anomalous
    windows for each dataset.

    Returns:
        None
    """

    start, end, anomalies = load_events()
    flows = load_flows()

    # Retain only flows within the experiment duration.
    flows = flows[
        (flows["ts"] >= start)
        & (flows["ts"] < end)
    ].copy()

    print(f"Loaded {len(flows)} synthetic NetFlow records")
    print(f"Loaded {len(anomalies)} anomaly episodes")
    print(f"Experiment start: {start}")
    print(f"Experiment end: {end}")

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
