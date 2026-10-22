# Project Log

Running record of decisions, results and limitations. The README is written from this file.

## Setup
- Python 3.15 could not build PyYAML (no prebuilt wheel, needs a C++ compiler); the project uses Python 3.13 in `.venv`.
- Repo structure: `src/ids/` (code), `data/` (datasets, gitignored), `docs/`, `models/`, `tests/`.

## Data
- Own capture: `sample.pcapng`, 84,405 packets of ordinary home Wi-Fi browsing, unlabeled. 84,333 were IP packets (64,495 UDP, 19,838 TCP). UDP dominance is likely QUIC and DNS.
- Version 1 flow extractor grouped by destination port, which split each connection into two flows (670 flows). Replaced by a bidirectional extractor.
- Bidirectional extractor (`flows.py`): 580 flows (341 UDP, 239 TCP), 120-second idle timeout, features chosen to match UNSW-NB15 column names.
- UNSW-NB15 official training set: 175,341 flows (119,341 attack, 56,000 normal). Official testing set: 82,332 flows (45,332 attack, 37,000 normal). Downloaded from the official UNSW Canberra source.

## Results (train on official training set, test on official testing set)
- Random Forest (200 trees, balanced class weights): accuracy 89.09%, attack recall 95.33%, normal recall 81.44%, attack precision 86.29%. Confusion matrix [[30133, 6867], [2118, 43214]].
- Isolation Forest (trained on normal flows only): accuracy 60.93%, attack recall 39.31%.
- Own capture scored with the Random Forest: 545 of 580 flows flagged as attack (544 in later runs; small variation between runs).

## Experiments
- Feature importance ranked `sttl` first (23%).
- UNSW training set TTL distribution: 70% of normal flows have `sttl` = 31; 103,513 attack flows have `sttl` = 254.
- TTL ablation: removing `sttl` and `dttl` changed UNSW accuracy from 89.15% to 88.81% and left own-capture flagged flows at 544 of 580, so TTL is not the source of the domain shift. Feature importance was misleading because correlated features share the signal.
- Flow size: 92.4% of UNSW training flows with 2 or fewer packets are attacks (80,320 flows); 51.4% of own flows have 2 or fewer packets (mostly DNS and QUIC).
- Dropping timing and TTL features: UNSW accuracy 89.67%, own flows flagged 556 of 580, so timing is not the main driver.
- Flagged flows by size: 281 of 298 flows with 1 to 2 packets, but also 188 of 201 flows with 20+ packets, so flow size explains only about half of the false positives.
- Matched comparison (own flows with 10 to 30 packets, n = 128, against UNSW flows of the same size): packet counts match, but bytes per packet are about 4x higher (source) and 12x higher (destination) in own traffic. Timing differs by about 5x at most.

## Limitations
- Own capture is unlabeled normal traffic only, so real detection performance on it cannot be measured.
- UNSW-NB15 features come from Argus and Bro tooling; the Scapy-based features here only approximate them (byte counting and timing definitions may differ).
- Domain shift: UNSW-NB15 was generated in a 2015 lab network; own capture is a modern home network over the real internet. The model flags almost all own flows as attacks.
- UNSW-NB15 class balance (about 55% attack) is far from real networks.
- In UNSW, tiny flows are overwhelmingly attacks, so DNS-like own flows are misclassified.
- Possible capture artifact: maximum packet length of 44,858 bytes in own capture suggests NIC offload coalescing (unverified; length check pending).
- Capture only on networks you own or have permission to monitor.

## Next steps
- Run the packet-length check on own capture.
- Generate labeled attack traffic in a VM lab (planned) to evaluate detection on real captures.
- Evaluate on matched feature definitions or flows produced by the same tool as the training data.