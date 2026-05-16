# Neurscan - Architecture & Project Documentation

## 1. Project Description
Neurscan is an advanced, multi-engine malware orchestration platform built in Python. It is designed to analyze potentially suspicious files and determine if they are malicious or benign. It does this by combining static heuristics, machine learning, cloud threat intelligence, and dynamic behavioral analysis (sandboxing). Finally, it leverages AI-driven analysis to provide a comprehensive threat intelligence report.

---

# Tool Screenshot

!<img width="1570" height="850" alt="Image" src="https://github.com/user-attachments/assets/82fe19dd-4e77-4aaa-abc8-6e8163c435fa" />

---

# Tool Scan Demonstration

## After Scan
!<img width="1919" height="1016" alt="Image" src="https://github.com/user-attachments/assets/d1215f8c-8d53-4529-aae3-4af59f550d9e" />

---

# HTML Report Preview

## HTML Report - Executive Summary
!<img width="1328" height="729" alt="Image" src="https://github.com/user-attachments/assets/762c20f0-686e-4a00-b9bc-81051fc4f829" />

## HTML Report - Threat Intelligence
!<img width="971" height="884" alt="Image" src="https://github.com/user-attachments/assets/e14e8c62-8478-4af0-bf38-09e686fef895" />

---

# PDF Report Preview

## PDF Report - Page 1
!<img width="758" height="841" alt="Image" src="https://github.com/user-attachments/assets/3d7c8113-614c-4a82-b5af-fd42f4f0ee2d" />

## PDF Report - Page 2
!<img width="732" height="844" alt="Image" src="https://github.com/user-attachments/assets/3850b4ac-b48c-4478-b784-699c0ad4d7c8" />

---

## 2. Core Architecture
The project follows a modular architecture orchestrated by a central component. The main logic resides within the `Neurscan/malware_tools` directory.

### 2.1 The Orchestrator (`orchestrator.py`)
This is the core engine of the application. It receives a file, initializes the requested scanning modules, executes them in sequence, and aggregates the results into a `FinalVerdict`. 

- **Scoring System**: Computes a combined threat score (out of 100) based on individual engine weights:
  - YARA: 20%
  - ML/EMBER: 25%
  - VirusTotal: 25%
  - Sandbox Detonation: 30%

- **Confidence Levels**: Maps the combined score into actionable verdicts:
  - CLEAN
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL

### 2.2 Scanning Engines

- **YARA Scanner (`yara_scanner.py`)**  
  Uses local YARA rules to detect specific byte patterns, strings, or signatures indicative of known malware families.

- **Machine Learning / EMBER (`lief` and `lightgbm`)**  
  Extracts static features from Portable Executable (PE) files using the EMBER framework and evaluates them against a pre-trained LightGBM model (`ember_model_2018.txt`) to predict the probability of maliciousness.

- **VirusTotal Scanner (`vt_scanner.py`)**  
  Queries the VirusTotal API (cloud-based intelligence) to check if the file hash has been analyzed and flagged by commercial antivirus engines.

- **Sandbox Detonation (`sandbox.py`)**  
  Submits PE files to the Falcon Sandbox (Hybrid Analysis) for dynamic detonation. It retrieves threat scores, executive summaries, and behavioral tactics mapped to the MITRE ATT&CK framework.

### 2.3 AI Threat Intelligence (`llm_analyzer.py`)
Enhances the raw JSON results from the Sandbox by feeding them into a Large Language Model (via the Groq API). It generates a human-readable summary, extracts critical:

- Capabilities
- MITRE ATT&CK Techniques
- Indicators of Compromise (IOCs)
- Actionable recommendations

### 2.4 Supporting Components

- **User Interface (`gui.py`)**  
  A modern, dark-themed graphical user interface built with the `flet` framework. It allows users to:
  - Pick files
  - Toggle sandbox detonation
  - Enable auto-quarantine
  - View analysis cards and AI insights interactively

- **Quarantine Manager (`quarantine.py`)**  
  If the combined threat score surpasses a safety threshold (default 75.0), this module safely moves and isolates the dangerous file into a quarantine zone to prevent accidental execution.

---

## 3. Workflow Explanation

### 1. Input Phase
The user selects a suspicious file via the `gui.py` interface. They can optionally enable:

- Deep Sandbox Detonation
- Auto-Quarantine

### 2. Analysis Phase

- The orchestrator checks if the file is a PE format (Windows executable by checking the `MZ` header).
- YARA rules run against the file to look for static signatures.
- If it's a PE file, ML features are extracted and scored.
- The file is hashed and queried against VirusTotal.
- If enabled and the file is a PE, it is uploaded to the Falcon Sandbox for behavioral execution.

### 3. Synthesis Phase
The Orchestrator gathers all scores, applies their respective weights, and produces a final `combined_score`.

### 4. AI Augmentation
If sandbox data is present, the LLM analyzer parses the output to present plain-English threat intelligence directly in the UI, including:

- Capabilities
- IOCs
- Techniques

### 5. Action & Output
The GUI updates in real-time with visual cards (Score/Verdict) for each engine. The application logs the scan to the local database, and if the final score indicates HIGH/CRITICAL risk and auto-quarantine is enabled, the file is moved to the quarantine folder.
