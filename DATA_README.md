# NetFlow Dataset Documentation

## Data Source

This research uses three NetFlow datasets to evaluate the effects of temporal aggregation on behavioral anomaly detection using Isolation Forest.

Two datasets were collected in a controlled virtual laboratory environment, while the third was generated synthetically using Python.

The datasets contain normal network activity and intentionally introduced anomalies for evaluating detection performance.


## Dataset Description

**6 Hour Laboratory Dataset**

The six hour laboratory dataset contains 20,107 client NetFlow records collected from a controlled virtual network environment.

The experiment includes normal network activity and intentionally generated anomalies.

The dataset is stored in `data/lab_6h/`.

**72 Hour Laboratory Dataset**

The 72 hour laboratory dataset contains 224,321 client NetFlow records collected over a 72 hour period in the controlled laboratory environment.

The experiment includes normal network activity and intentionally generated anomalies.

The dataset is stored in `data/lab_72h/`.

**7 Day (168 Hour) Synthetic Dataset**

The 7 day (168 hour) synthetic dataset contains 95,318 programmatically generated NetFlow records representing seven days of network activity.

The dataset includes 56 anomaly episodes and was generated to support evaluation over a longer observation period.

The dataset is stored in `data/synthetic_7d/`.


## Feature Engineering
NetFlow records are processed into 1, 5, and 10 minute aggregation windows.

Twelve traffic features are extracted from the aggregated records:

01. Flow count
02. Total bytes
03. Total packets
04. Unique destination ports
05. Unique source ports
06. Average flow duration
07. Average bytes per flow
08. TCP flow ratio
09. Flows per second
10. Bytes per second
11. Short flow ratio
12. Destination port entropy

These features are used as inputs to the Isolation Forest anomaly detection model.


## Aggregated Dataset Summary

| **Dataset** | **1 Minute Windows** | **5 Minute Windows** | **10 Minute Windows** |
|---|---:|---:|---:|
| 6 Hour Laboratory | 360 | 72 | 36 |
| 72 Hour Laboratory | 4,320 | 864 | 432 |
| 7 Day Synthetic | 10,080 | 2,016 | 1,008 |

Each aggregated dataset includes labels identifying windows associated with anomalous activity.


## Data Storage

The `data/` directory contains the raw NetFlow datasets, experiment logs, and aggregated feature files.

The `results/` directory contains the Isolation Forest evaluation results, prediction files, and threshold sensitivity comparisons.

The research notebooks in `notebooks/` provide instructions for reproducing the experiments using Google Colab.


## Limitations

The laboratory datasets were collected in a controlled virtual environment and may not fully represent production network traffic.

The seven day dataset was generated synthetically and may not reflect the complexity and variability of real network behavior.

The number and proportion of anomalous windows vary across aggregation intervals, which limits direct comparisons of model performance.

These limitations are considered when interpreting the experimental results.