# NetFlow Behavioral Anomaly Detection

## Project Overview

This repository supports my CSC 786 research project, *Evaluating Temporal Aggregation for NetFlow Behavioral Anomaly Detection Using Isolation Forest*.

The research investigates how different NetFlow aggregation intervals (1, 5, and 10 minutes) affect anomaly detection performance using Isolation Forest.

## Current Implementation

The Google Colab notebook `NetFlow_Data_Collection.ipynb` demonstrates a preliminary data generation workflow.

The notebook:

1. Generates 1,000 synthetic NetFlow records.
2. Includes timestamps, source and destination IP addresses, ports, protocols, packet counts, and byte counts.
3. Saves the records to a CSV file.
4. Reads the CSV file to verify successful storage.

**Note:** The dataset is synthetic and does not represent actual captured network traffic.

## How to Run

1. Open `NetFlow_Data_Collection.ipynb` in Google Colab.
2. Select Runtime, then Run all.
3. Confirm that 1,000 records are generated.
4. Verify that the CSV file is saved and loaded successfully.

## Requirements

Python 3 and the pandas and NumPy libraries, available in Google Colab.

## Future Work

The next phase will involve collecting actual NetFlow traffic from a controlled lab environment, performing temporal aggregation, and evaluating Isolation Forest anomaly detection performance.
