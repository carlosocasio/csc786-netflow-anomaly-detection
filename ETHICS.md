# Ethical Considerations

## Project Overview

This project investigates how NetFlow aggregation intervals affect the performance of Isolation Forest for network anomaly detection.


## Data Privacy

This research uses two datasets collected in a controlled virtual laboratory environment and one synthetically generated dataset.

The laboratory network traffic was generated specifically for research purposes. No production network traffic or personal user activity was collected.

The synthetic dataset uses simulated network traffic records and does not represent actual user communications.


## Laboratory Data Collection

The 6 hour and 72 hour laboratory experiments were conducted in a controlled virtual network environment. Normal network activity and intentionally generated anomalies were collected to evaluate the anomaly detection model.

Although NetFlow records do not contain packet payloads, they can reveal communication patterns, IP addresses, timestamps, and traffic volumes. Therefore, laboratory NetFlow records are handled carefully to protect privacy.


## Security Measures

Sensitive information, credentials, and confidential network configurations are not published in the GitHub repository.

Only laboratory generated, synthetic, or appropriately sanitized research data is shared.


## Responsible Research

The project is intended to evaluate network anomaly detection techniques, not to monitor individuals or conduct unauthorized surveillance.

Experimental results are reported accurately, including limitations, false positives, and differences in detection performance across aggregation intervals.


## Current Limitations

The laboratory datasets were collected in a controlled virtual environment and may not represent the complexity of production network traffic.

The synthetic dataset was programmatically generated and may not reflect realistic network traffic distributions.

The experimental results demonstrate the behavior of Isolation Forest under the evaluated conditions but do not establish its effectiveness in production environments.
