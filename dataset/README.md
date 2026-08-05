# Dataset Folder — CICIDS2017

**Action required from you:** paste your downloaded CICIDS2017 CSV files directly into this folder.

## What goes here

The CICIDS2017 dataset (Canadian Institute for Cybersecurity, 2017) is distributed as
eight CSV files, one per capture day/attack scenario. The typical filenames are:



```
dataset/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

The exact names do not have to match. The Phase 2 training script globs for
`dataset/**/*.csv`, so any layout works as long as the files are CSVs sitting in
this folder (subfolders are fine too).

## Why this dataset

CICIDS2017 contains labelled network *flows* — not raw packets. Each row is one
connection summarised into ~78 numeric features (duration, packet counts, byte
counts, flag counts, inter-arrival times) plus a `Label` column that says whether
the flow was `BENIGN` or a named attack (`DDoS`, `PortScan`, `Bot`, `FTP-Patator`,
`Web Attack – Brute Force`, and so on).

This shape is what makes the project work end to end: in Phase 4 we compute the
*same kind* of flow-level features from live packets captured on your machine, so
the model trained here in Phase 2 can score real traffic in Phase 5.

## Important note about file size

These CSVs total roughly 500 MB. They are excluded from Git via `.gitignore` —
never commit them. Anyone cloning the repo re-downloads the dataset themselves.

## Where to download

Official source: <https://www.unb.ca/cic/datasets/ids-2017.html>
(Registration is required; the "GeneratedLabelledFlows" archive is the one containing these CSVs.)

## How to verify your files are in place

From the project root, with the virtual environment active:

```bash
python scripts/verify_setup.py
```

It will report how many CSV files it found here.
