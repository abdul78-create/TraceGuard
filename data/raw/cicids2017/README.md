# CIC-IDS2017 Raw Dataset Storage

This directory is designated for the raw, unmodified CSV files of the **CIC-IDS2017** dataset.

## How to Populate

1. Visit the official Canadian Institute for Cybersecurity (UNB) page:  
   https://www.unb.ca/cic/datasets/ids-2017.html
2. Download the flow dataset: `MachineLearningCSV.zip` (~430 MB).
3. Extract the 8 CSV files directly into this directory:
   - `Monday-WorkingHours.pcap_ISCX.csv`
   - `Tuesday-WorkingHours.pcap_ISCX.csv`
   - `Wednesday-workingHours.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
   - `Friday-WorkingHours-Morning.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

## Critical Rules
- **DO NOT** modify, rename, or edit the raw files.
- **DO NOT** commit raw CSV or ZIP files to Git. (Configured in `.gitignore`).
- Keep files intact for reproducible auditing via `python -m ml.data_audit`.
