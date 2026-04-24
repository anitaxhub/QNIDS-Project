# QNIDS — Quantum-Inspired Network Intrusion Detection System

## Final Year Project — BSCS 2021-2025

## Project Overview
A Quantum-Inspired NIDS using QPSO feature 
selection + Random Forest + Anomaly Detection.

## Team
- Person A: Backend / ML / QPSO
- Person B: GUI / Frontend

## Tech Stack
- Python 3.x
- PyQt5 (GUI)
- scikit-learn (ML)
- DEAP (QPSO)
- Scapy (Network)
- Matplotlib (Charts)
- ReportLab (PDF Export)

## Datasets
- NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
- UNSW-NB15: https://research.unsw.edu.au

## Models
Download trained models separately and place in:
qnids_final_complete/models/
qnids_final_complete/data/

## Installation
pip install -r requirements.txt
python gui/main_window.py

## Features
- Real-time network traffic monitoring
- QPSO-optimized feature selection (41→19)
- Known attack classification
- Unknown threat detection
- PDF/CSV export
- Dark theme GUI dashboard