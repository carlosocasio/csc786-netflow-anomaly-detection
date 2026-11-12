"""
Carlos Ocasio
CSC 786 - Computer Science Problems
Professor: Dr. Abid Mehmood

Final Project - Implementation and Evaluation of a NetFlow Behavioral
Anomaly Detection Prototype Using Isolation Forest

Description:
Evaluates baseline Isolation Forest anomaly detection performance
using NetFlow datasets generated with 1, 5, and 10 minute temporal
aggregation windows.
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
DATA = BASE / "data" / "synthetic_7d"
RESULTS = BASE / "results" / "synthetic_7d"

RESULTS.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------
# Configuration: Isolation Forest Evaluation Parameters
# ------------------------------------------------------
SEED = 1153
WINDOWS = [1, 5, 10]
TRAIN_RATIO = 0.70
CONTAMINATION = 0.10


# -------------------------------------------------------
# Configuration: NetFlow Features for Baseline Evaluation
# -------------------------------------------------------
# Define the traffic features used to train and evaluate Isolation Forest.
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
# Method: Train and Evaluate Isolation Forest Baseline
# ------------------------------------------------------
def evaluate_model(minutes):
    """
    Train and evaluate an Isolation Forest model using NetFlow
    features from the specified temporal aggregation interval.

    The method splits the dataset chronologically, trains the
    model using normal traffic windows, and evaluates anomaly
    detection performance on the remaining testing windows.

    Anomaly scores from the training data are used to establish
    the detection threshold. Model performance is evaluated
    using precision, recall, F1 score, false positive rate,
    ROC AUC, and confusion matrix results.

    Testing predictions and anomaly scores are saved to a CSV
    file, and evaluation metrics are returned for comparison
    across aggregation intervals.

    Args:
        minutes (int): Temporal aggregation interval in minutes.

    Returns:
        dict: Evaluation results including training and testing
            window counts, anomaly predictions, detection
            threshold, performance metrics, and confusion
            matrix values.
    """
    # Load the aggregation dataset.
    input_file = DATA / f"netflow_features_{minutes}min.csv"
    df = pd.read_csv(input_file)

    # Split the dataset chronologically into 70% training and 30% testing.
    start = pd.to_datetime(df["window_start"].iloc[0])
    duration = len(df) * minutes

    split_minutes = int(duration * TRAIN_RATIO)
    split_minutes = (split_minutes // 10) * 10

    boundary = start + pd.Timedelta(minutes=split_minutes)
    train = df[pd.to_datetime(df["window_end"]) <= boundary].copy()
    test = df[pd.to_datetime(df["window_start"]) >= boundary].copy()

    # Use normal training windows only.
    X_train = train.loc[
        train["label"] == 0, FEATURES
    ]

    # Evaluate against all testing windows.
    X_test = test[FEATURES]
    y_test = test["label"]

    # Create and train Isolation Forest.
    model = IsolationForest(
        n_estimators=100,
        contamination=CONTAMINATION,
        random_state=SEED,
    )

    model.fit(X_train)

    # Calculate anomaly scores.
    # Higher scores indicate more anomalous behavior.
    train_scores = -model.score_samples(X_train)
    test_scores = -model.score_samples(X_test)

    # Select the detection threshold using training data only.
    # The highest scoring 10% of normal training windows
    # establish the initial anomaly threshold.
    threshold = np.quantile(
        train_scores,
        1 - CONTAMINATION
    )

    # Predict anomalies in the testing dataset.
    predictions = (test_scores > threshold).astype(int)

    # Calculate the confusion matrix.
    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ).ravel()

    # Calculate performance metrics.
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

    auc = (
        roc_auc_score(y_test, test_scores)
        if y_test.nunique() == 2
        else np.nan
    )

    # Display evaluation results.
    print(f"\nIsolation Forest: {minutes} minute aggregation")
    print("=" * 50)

    print(f"Training windows: {len(train)}")
    print(f"Normal training windows used: {len(X_train)}")
    print(f"Testing windows: {len(test)}")
    print(f"True anomalies: {int(y_test.sum())}")
    print(f"Predicted anomalies: {int(predictions.sum())}")

    print(f"\nThreshold: {threshold:.4f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1 score: {f1:.3f}")
    print(f"False positive rate: {fpr:.3f}")
    print(f"ROC AUC: {auc:.3f}")

    print("\nConfusion Matrix")
    print(f"True negatives: {tn}")
    print(f"False positives: {fp}")
    print(f"False negatives: {fn}")
    print(f"True positives: {tp}")

    # Save testing predictions.
    test["prediction"] = predictions
    test["anomaly_score"] = test_scores

    output = RESULTS / f"predictions_{minutes}min.csv"
    test.to_csv(output, index=False)

    print(f"\nSaved predictions: {output}")

    # Return metrics for comparison.
    return {
        "aggregation_minutes": minutes,
        "training_windows": len(train),
        "normal_training_windows": len(X_train),
        "testing_windows": len(test),
        "true_anomalies": int(y_test.sum()),
        "predicted_anomalies": int(predictions.sum()),
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "roc_auc": auc,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


# ------------------------------------------------------
# Method: Run Baseline Evaluation and Compare Results
# ------------------------------------------------------
def main():
    """
    Run the Isolation Forest baseline evaluation for each
    configured temporal aggregation interval.

    The method evaluates the 1, 5, and 10 minute datasets,
    collects the performance metrics, and saves the results
    to a CSV file for comparison.

    A summary of precision, recall, F1 score, false positive
    rate, and ROC AUC is displayed for each aggregation interval.
    """
    results = []

    for minutes in WINDOWS:
        metrics = evaluate_model(minutes)
        results.append(metrics)

    # Save the comparison of all three models.
    summary = pd.DataFrame(results)

    output = RESULTS / "isolation_forest_comparison.csv"
    summary.to_csv(output, index=False)

    print("\n" + "=" * 50)
    print("AGGREGATION COMPARISON")
    print("=" * 50)

    print(
        summary[
            [
                "aggregation_minutes",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
                "roc_auc",
            ]
        ].to_string(index=False)
    )

    print(f"\nSaved comparison: {output}")


if __name__ == "__main__":
    main()
