"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Evaluates the effect of different anomaly detection thresholds
on Isolation Forest performance using NetFlow datasets generated
with 1, 5, and 10 minute temporal aggregation windows.
"""

from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.metrics import roc_auc_score

# ------------------------------------------------------
# Configuration: Data and Results Directories
# ------------------------------------------------------
BASE = Path(__file__).resolve().parents[2]
DATA = BASE / "data" / "lab_6h"
RESULTS = BASE / "results" / "lab_6h"


RESULTS.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------
# Configuration: Isolation Forest Evaluation Parameters
# ------------------------------------------------------
SEED = 1153
WINDOWS = [1, 5, 10]
TRAIN_RATIO = 0.70
CONTAMINATION = 0.10


# ------------------------------------------------------
# Configuration: Detection Threshold Percentiles
# ------------------------------------------------------
# Percentiles of normal training anomaly scores.
# 95% - conservative detection
# 90% - baseline threshold
# 85% - sensitive detection
# 80% - most sensitive detection
PERCENTILES = [95, 90, 85, 80]


# ------------------------------------------------------
# Configuration: NetFlow Features for Model Evaluation
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
# Method: Evaluate Isolation Forest Detection Thresholds
# ------------------------------------------------------
def evaluate_thresholds(minutes):
    """
    Evaluate the effect of different detection thresholds on
    Isolation Forest anomaly detection performance.

    The method loads the specified NetFlow aggregation dataset,
    splits the observations chronologically, and trains an
    Isolation Forest model using normal traffic windows.

    Anomaly scores from the training data establish detection
    thresholds at the configured percentiles. Each threshold
    is evaluated against the same testing dataset to compare
    precision, recall, F1 score, false positive rate, and
    alert volume.

    Testing anomaly scores are saved to a CSV file, and the
    evaluation results are returned for comparison.

    Args:
        minutes (int): Temporal aggregation interval in minutes.

    Returns:
        list: Evaluation results for each threshold, including
            detection metrics, alert counts, and confusion
            matrix values.
    """
    input_file = DATA / f"netflow_features_{minutes}min.csv"
    df = pd.read_csv(input_file)

    # Split chronologically using a common boundary.
    start = pd.to_datetime(df["window_start"].iloc[0])
    duration = len(df) * minutes

    split_minutes = int(duration * TRAIN_RATIO)
    split_minutes = (split_minutes // 10) * 10

    boundary = start + pd.Timedelta(minutes=split_minutes)
    train = df[pd.to_datetime(df["window_end"]) <= boundary].copy()
    test = df[pd.to_datetime(df["window_start"]) >= boundary].copy()

    # Ground truth labels select normal training windows.
    X_train = train.loc[
        train["label"] == 0, FEATURES
    ]

    X_test = test[FEATURES]
    y_test = test["label"]

    # Train one model for this aggregation interval.
    model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=SEED,
    )

    model.fit(X_train)

    # Higher scores indicate greater anomaly severity.
    train_scores = -model.score_samples(X_train)
    test_scores = -model.score_samples(X_test)

    auc = (
        roc_auc_score(y_test, test_scores)
        if y_test.nunique() == 2
        else np.nan
    )

    results = []

    print(f"\n{minutes} minute aggregation")
    print("=" * 55)
    print(f"Normal training windows: {len(X_train)}")
    print(f"Testing windows: {len(test)}")
    print(f"True anomalous windows: {int(y_test.sum())}")

    for percentile in PERCENTILES:
        # Threshold derived exclusively from training scores.
        threshold = np.percentile(
            train_scores, percentile
        )

        predictions = (
            test_scores > threshold
        ).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        ).ravel()

        precision = precision_score(
            y_test, predictions, zero_division=0
        )

        recall = recall_score(
            y_test, predictions, zero_division=0
        )

        f1 = f1_score(
            y_test, predictions, zero_division=0
        )

        fpr = (
            fp / (fp + tn)
            if (fp + tn) > 0
            else np.nan
        )

        alerts = int(predictions.sum())

        results.append({
            "aggregation_minutes": minutes,
            "percentile": percentile,
            "threshold": threshold,
            "training_windows": len(X_train),
            "testing_windows": len(test),
            "true_anomalies": int(y_test.sum()),
            "alert_count": alerts,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "roc_auc": auc,
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        })

        print(
            f"Percentile {percentile:>2}: "
            f"Threshold={threshold:.4f} "
            f"Alerts={alerts:>3} "
            f"Precision={precision:.3f} "
            f"Recall={recall:.3f} "
            f"F1={f1:.3f} "
            f"FPR={fpr:.3f}"
        )

    # Save anomaly scores independently of the threshold.
    test["anomaly_score"] = test_scores

    scores_file = RESULTS / f"threshold_scores_{minutes}min.csv"
    test.to_csv(scores_file, index=False)

    print(f"Saved scores: {scores_file}")

    return results


# ------------------------------------------------------
# Method: Run Threshold Sensitivity Evaluation
# ------------------------------------------------------
def main():
    """
    Evaluate detection thresholds across all configured
    temporal aggregation intervals.

    The method collects threshold evaluation results for
    the 1, 5, and 10 minute datasets and saves the combined
    metrics to a CSV file.

    A summary of alert counts, precision, recall, F1 score,
    and false positive rate is displayed for comparison.
    """
    all_results = []

    for minutes in WINDOWS:
        results = evaluate_thresholds(minutes)
        all_results.extend(results)

    summary = pd.DataFrame(all_results)

    output = RESULTS / "threshold_comparison.csv"
    summary.to_csv(output, index=False)

    print("\n" + "=" * 55)
    print("THRESHOLD SENSITIVITY COMPARISON")
    print("=" * 55)

    print(
        summary[
            [
                "aggregation_minutes",
                "percentile",
                "alert_count",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
            ]
        ].to_string(index=False)
    )

    print(f"\nSaved comparison: {output}")


if __name__ == "__main__":
    main()