# NetFlow Behavioral Anomaly Detection

## Project Overview

This repository supports my CSC 786 research project, *Evaluating Temporal Aggregation for NetFlow Behavioral Anomaly Detection Using Isolation Forest*.

The research investigates how different NetFlow aggregation intervals (1, 5, and 10 minutes) affect anomaly detection performance using Isolation Forest. It also examines how anomaly detection thresholds influence precision, recall, false positive rates, and alert volume.

## Datasets

The project currently includes two datasets:

1. **Six Hour Laboratory Dataset:** NetFlow records collected from a controlled virtual network environment. The dataset contains 20,107 client NetFlow records and includes normal network activity and intentionally generated anomalies.

2. **Seven Day Synthetic Dataset:** A generated dataset containing 95,318 NetFlow records, used to evaluate the model over a longer observation period.

Both datasets are available in the `data` directory.

## Reproducing the Six Hour Laboratory Experiment

The six hour experiment can be reproduced using Google Colab.

**Research Notebook:** [NetFlow Anomaly Detection 6 Hour Lab](https://colab.research.google.com/github/carlosocasio/csc786-netflow-anomaly-detection/blob/main/notebooks/NetFlow_Anomaly_Detection_6Hour_Lab.ipynb)

To reproduce the experiment:

1. Open the research notebook using the link above.
2. In Google Colab, select **Runtime**, then **Run all**.
3. Allow the notebook to clone the GitHub repository, install the required Python libraries, and execute the analysis scripts.
4. Review the resulting performance metrics, confusion matrices, charts, and interpretations.

The notebook evaluates Isolation Forest using 1, 5, and 10 minute aggregation intervals and compares detection performance across different thresholds.

## Repository Organization

* `notebooks/` contains the research notebook used to reproduce and review the laboratory experiment.
* `scripts/analysis/` contains the feature engineering, Isolation Forest baseline, and threshold evaluation scripts for the laboratory dataset.
* `scripts/synthetic/` contains the scripts for generating and evaluating synthetic NetFlow data.
* `scripts/traffic-scripts/` contains the scripts used to generate normal and anomalous network activity in the laboratory.
* `data/` contains the laboratory and synthetic datasets and their aggregated features.
* `results/` contains the experimental comparison results.
* `DATA_README.md` provides additional information about the datasets.
* `ETHICS.md` documents ethical considerations related to the project.

## Requirements

The project uses Python 3, pandas, NumPy, and scikit-learn.

Dependencies are listed in `requirements.txt` and are installed automatically when executing the research notebook in Google Colab.

## Research Status

The six hour laboratory experiment and seven day synthetic experiment have been implemented and evaluated. Additional laboratory data collection and evaluation are planned to further investigate the effects of temporal aggregation and threshold selection.
