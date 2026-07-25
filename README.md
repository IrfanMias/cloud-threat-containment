🛡️ Automated Cloud Threat Containment Engine (Azure SOAR)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Azure Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-SOAR-0089D6?style=flat&logo=microsoftazure&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-v3_API-3949AB?style=flat)

---

📌 Executive Summary

Security Operations Centers (SOCs) face alert fatigue, with analyst response times often taking minutes to hours during active perimeter scans. This project implements a **Serverless Security Orchestration, Automation, and Response (SOAR)** pipeline. 

By intercepting security alerts from Microsoft Sentinel, extracting IP telemetry, and querying global threat intelligence via VirusTotal, the playbook dynamically enforces Network Security Group (NSG) firewall blocks on high-risk IPs in sub-second intervals without human intervention.

---

📐 Architecture & Operational Data Flow

[ SIEM Alert Trigger ] 
          │ (HTTP POST Webhook / Alert Payload)
          ▼
[ Azure Logic App Playbook ]
          │ 
          ├─► 1. Parse Alert Payload (Extract IP Entity)
          ├─► 2. Query VirusTotal API v3 (Threat Score Lookup)
          │
          ▼
[ Conditional Logic Evaluator ]
          │
    ┌─────┴──────────────────────────────┐
    │                                    │
 [ Malicious Score > 0 ]           [ Clean Score = 0 ]
    │                                    │
    ▼                                    ▼
[ Update Azure NSG Rule ]        [ Pass & Log Event ]
 (Inbound DENY Injected)         (Alert Closed Cleanly)
