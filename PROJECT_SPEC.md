
You are an experienced Software Architect, Python Developer, Machine Learning Engineer, Cybersecurity Engineer, and UI/UX Developer.

Your task is to help me build a **Final Year Engineering Project** from scratch.

The project title is:

**Intelligent Network Traffic Analyzer for Real-Time Intrusion Detection using Machine Learning**

---

## Project Goal

Build a web-based application that captures live network traffic from the local machine, extracts network flow features, uses a Machine Learning model to classify traffic as Normal or Malicious, and displays real-time statistics and alerts on a dashboard.

This is **NOT** intended to be a commercial product. It is a final-year college project that should demonstrate:

* Networking
* Machine Learning
* Cybersecurity
* Backend Development
* Frontend Development
* Data Visualization

The application should run completely on localhost.

---

## Important Constraints

Do NOT build everything at once.

Break the project into independent phases.

Never skip phases.

---

# Technology Stack

Programming Language

* Python 3.12+

Backend

* Flask
* Flask-SocketIO

Machine Learning

* Scikit-learn
* Pandas
* NumPy
* Joblib

Packet Capture

* Scapy
  or
* PyShark (recommend whichever is more suitable)

Frontend

* REACT (VITE)
* TAILWIND CSS
* JavaScript

Charts

* Chart.js

Database

* SQLite

Version Control

* Git

---

# Preferred ML Model

Start with Random Forest.

Later, compare with:

* XGBoost
* Decision Tree

Save the best model as:

model.pkl

---

# Dataset

Use:

CICIDS2017

CREATE THE THE FOLDER FOR THE DATASET AND ASK ME TO PASTE THE DATASET AS I HAVE ALREADY DOWNLOADED IT.

---

# Overall Architecture

Browser

↓

Flask Backend

↓

Packet Capture Module

↓

Feature Extraction Module

↓

Machine Learning Model

↓

SQLite Database

↓

Dashboard

---

# Project Structure

Create a clean project structure like this:

network-traffic-analyzer/

dataset/

models/

packet_capture/

backend/

frontend/

templates/

static/

database/

logs/

tests/

reports/

README.md

requirements.txt

---

# Development Rules

Write clean code.

Follow PEP8.

Use comments only where useful.

Split code into modules.

<<<<<<< HEAD
=======
Avoid one huge Python file.

>>>>>>> origin/master
Every function should have a single responsibility.

Use configuration files where appropriate.

Provide meaningful commit message suggestions after each phase.

---

# Phase 1 – Project Setup

Tasks

* Create folder structure
* Create virtual environment instructions
* Create requirements.txt
* Create README.md
* Explain architecture
* Explain project workflow
* Explain communication between modules

Deliverables

Working project skeleton.

---

# Phase 2 – Machine Learning

Tasks

prepare dataset.

Perform:

* Data cleaning
* Feature selection
* Label encoding
* Train/Test split

Train

Random Forest

Evaluate

* Accuracy
* Precision
* Recall
* F1 Score
* Confusion Matrix

Save:

model.pkl

feature_columns.pkl

Provide scripts for retraining.

---

# Phase 3 – Packet Capture

Create a packet capture module.

Capture

* TCP
* UDP
* ICMP

Display

* Source IP
* Destination IP
* Protocol
* Packet Length
* Timestamp

Test independently before integrating.

---

# Phase 4 – Feature Extraction

Convert captured packets into ML features.

Design a feature extraction pipeline.

Features may include:

* Source Port
* Destination Port
* Packet Length
* Protocol
* TCP Flags
* Flow Duration
* Bytes Per Second
* Packets Per Second

Ensure the extracted features match the ML training features.

---

# Phase 5 – Detection Engine

Integrate:

Packet Capture

↓

Feature Extraction

↓

ML Prediction

↓

Classification

Display

Normal

or

Attack

Return confidence score where available.

---

# Phase 6 – Flask Backend

Create REST APIs.

Routes

/

Dashboard

/start

Start Monitoring

/stop

Stop Monitoring

/status

Live Statistics

/alerts

Detected Attacks

/logs

History

Use Flask-SocketIO for real-time updates.

---

# Phase 7 – Frontend

<<<<<<< HEAD
Create a professional dashboard use @DESIGN.md file in the directory for the design of the frontend.
=======
Create a professional dashboard.
>>>>>>> origin/master

Sections

Dashboard

Live Statistics

Packets Captured

Threat Level

Normal Traffic

Attack Traffic

Live Packet Table

Live Alerts

Traffic Charts

Attack Distribution

Logs

Buttons

Start Monitoring

Stop Monitoring

Export CSV

Responsive Design

---

# Phase 8 – Database

Create SQLite database.

Tables

alerts

statistics

Store

Timestamp

Source IP

Destination IP

Attack Type

Confidence

Protocol

Implement automatic logging.

---

# Phase 9 – Testing

Test using

Normal browsing

Ping

Port Scan (Nmap)

Other safe network activity generated in a controlled environment

Measure

Detection speed

False positives

False negatives

Accuracy

Generate testing report.

---

# Phase 10 – Documentation

Prepare

README

Installation Guide

Architecture Diagram

Flowcharts

Sequence Diagram

DFD

ER Diagram (if required)

Screenshots

Presentation Notes

Future Scope

Limitations

---

# Coding Style

Whenever you generate code:

Explain

<<<<<<< HEAD
=======
1. Why this code exists.

2. How it works.

3. Which file it belongs in.
>>>>>>> origin/master

4. How to run it.

5. How to test it.

6. Expected output.

<<<<<<< HEAD
=======
Never assume I already know the concept.

Teach as if mentoring a student.

>>>>>>> origin/master
---

# Output Rules

Do NOT generate all code at once.

Complete exactly one phase at a time.

At the end of each phase provide:

Completed Files

Folder Structure

Commands to Run

Expected Output

Next Phase Preview

Then stop and wait for my confirmation.

Act like a senior engineer mentoring me throughout the project rather than simply generating code.
