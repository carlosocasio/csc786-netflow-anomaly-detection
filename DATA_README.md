# NetFlow Dataset Documentation

## Data Source

The dataset is synthetically generated using Python, NumPy, and pandas in Google Colab. No actual network traffic was captured.

## Dataset Description

The notebook generates 1,000 simulated NetFlow records containing eight fields:

* timestamp: Simulated time associated with each record.
* src_ip: Source IP address.
* dst_ip: Destination IP address.
* src_port: Source port number.
* dst_port: Destination port number.
* protocol: TCP or UDP.
* packets: Simulated packet count.
* bytes: Simulated byte count.

## Data Generation

The notebook uses NumPy with a fixed random seed of 42 to produce reproducible values.

Records begin at October 1, 2026, at 08:00:00, with timestamps spaced 10 seconds apart.

The source and destination addresses use private IPv4 address ranges. The generated values are illustrative and do not represent measured network behavior.

## Data Storage

The records are saved to `netflow_sample.csv` and loaded again using pandas to verify successful storage.

The CSV file is generated when the notebook runs.

## Limitations

This preliminary dataset does not contain actual NetFlow captures, verified attack labels, or realistic traffic distributions. It is intended to demonstrate the data generation and storage workflow, not to evaluate anomaly detection accuracy.

Actual experimental data collection and Isolation Forest evaluation are planned for a later phase of the research.
