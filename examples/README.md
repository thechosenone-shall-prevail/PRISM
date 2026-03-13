# PRISM Example Files

## Overview

This directory contains ready-to-use example files demonstrating PRISM's multi-file attack chain analysis feature.

## Files

### 1. attack_scenario_lazarus.txt
**Type**: Attack Scenario  
**Content**: Realistic financial institution breach narrative  
**Details**: 3-week attack timeline targeting cryptocurrency and SWIFT systems

### 2. ttps_lazarus.txt
**Type**: TTPs (Tactics, Techniques, Procedures)  
**Content**: 20+ MITRE ATT&CK technique IDs  
**Details**: Techniques observed in the attack scenario

### 3. iocs_lazarus.txt
**Type**: Indicators of Compromise  
**Content**: IPs, domains, file hashes, CVEs  
**Details**: Infrastructure and artifacts from the attack

### 4. sysmon_logs_lazarus.log
**Type**: Log Files  
**Content**: Sample Sysmon event logs  
**Details**: Process creation, registry changes, network connections

## Usage

### Quick Test
1. Start PRISM: `python -m streamlit run main.py`
2. Navigate to: Analyze → [ Multi-File Analysis ]
3. Upload these files in respective sections
4. Click: 🚀 ANALYZE COMPLETE ATTACK CHAIN

### Expected Result
- **Attribution**: Lazarus Group
- **Confidence**: 85-90%
- **Techniques**: 20+
- **Context**: financial, cryptocurrency

## Attribution

These examples are based on publicly documented Lazarus Group TTPs and are for educational/testing purposes only.
