# NetFlow Behavioral Anomaly Detection

## Project Overview

This repository supports my CSC 786 research project, Evaluating Temporal Aggregation for NetFlow Behavioral Anomaly Detection Using Isolation Forest.

The research investigates how different NetFlow aggregation intervals (1, 5, and 10 minutes) affect anomaly detection performance using Isolation Forest. It also examines how anomaly detection thresholds influence precision, recall, F1 score, false positive rates, and alert volume.

## Datasets

The project includes three datasets:

1. **6 Hour Laboratory Dataset:** NetFlow records collected from a controlled virtual network environment. The dataset contains 20,107 client NetFlow records and includes normal network activity and intentionally generated anomalies.

2. **72 Hour Laboratory Dataset:** NetFlow records collected over a 72 hour period in the controlled laboratory environment. The dataset contains 224,321 client NetFlow records and includes normal network activity and intentionally generated anomalies.

3. **Seven Day (168 Hour) Synthetic Dataset:** A programmatically generated dataset containing 95,318 NetFlow records and 56 anomaly episodes, used to evaluate the model over a longer observation period.

All three datasets are available in the data directory.

## Reproducing the Experiments

The experiments can be reproduced using Google Colab. Each notebook provides the analysis and visualizations for its corresponding dataset.

**Six Hour Laboratory Experiment**

[Open Six Hour Laboratory Notebook in Google Colab]
(https://colab.research.google.com/github/carlosocasio/csc786-netflow-anomaly-detection/blob/main/notebooks/NetFlow_Anomaly_Detection_6Hour_Lab.ipynb)

**72 Hour Laboratory Experiment**

[Open 72 Hour Laboratory Notebook in Google Colab]
(https://colab.research.google.com/github/carlosocasio/csc786-netflow-anomaly-detection/blob/main/notebooks/NetFlow_Anomaly_Detection_72Hour_Lab.ipynb)

**Seven Day Synthetic Experiment**

[Open Seven Day Synthetic Notebook in Google Colab]
(https://colab.research.google.com/github/carlosocasio/csc786-netflow-anomaly-detection/blob/main/notebooks/NetFlow_Anomaly_Detection_7Day_Synthetic.ipynb)

To reproduce an experiment:

1. Open the corresponding research notebooks using one of the links above.

2. In Google Colab, select **Runtime**, then **Run all**.

3. Allow the notebook to clone the GitHub repository, install the required Python libraries, and execute the analysis scripts.

4. Review the resulting performance metrics, confusion matrices, charts, and interpretations.

Each notebook evaluates Isolation Forest using 1, 5, and 10 minute aggregation intervals and compares detection performance across different thresholds.


## Repository Organization

* `notebooks/` contains the three research notebooks used to reproduce and review the experiments.
* `scripts/analysis/` contains the feature engineering, Isolation Forest baseline, and threshold evaluation scripts for the laboratory datasets.
* `scripts/synthetic/` contains the scripts for generating and evaluating synthetic NetFlow data.
* `scripts/traffic-scripts/` contains scripts used to generate normal and anomalous network activity in the laboratory.
* `data/` contains the laboratory and synthetic datasets and their aggregated features.
* `results/` contains the experimental comparison results, predictions, and threshold evaluations.
* `DATA_README.md` provides additional information about the datasets.
* `ETHICS.md` documents ethical considerations related to the project.


## Requirements

The project uses Python 3, pandas, NumPy, and scikit-learn.

Dependencies are listed in `requirements.txt` and are installed automatically when executing the research notebooks in Google Colab.


## Research Status

The 6 hour laboratory, 72 hour laboratory, and 7 day (168 hour) synthetic experiments have been implemented and evaluated.

All three research notebooks have been tested in fresh Google Colab environments, successfully reproducing the original Isolation Forest baseline evaluation results.

The experimental results have been analyzed and compared in the final research report.