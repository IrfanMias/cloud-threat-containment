import os
import json
import requests
import time

def simulate_azure_logic_app(sentinel_payload, api_key):
    print("\n--- [AZURE LOGIC APP SIMULATION STARTED] ---")
    
    # 1. THE TRIGGER: Simulating the HTTP POST reception
    print("[*] Webhook triggered by incoming Sentinel alert.")
    time.sleep(1)
    
    # 2. DATA EXTRACTION: Replicating the 'Extract_IP_Entity' block
    try:
        # This mirrors the Logic App expression: @triggerBody()?['Entities'][0]?['Address']
        suspect_ip = sentinel_payload["Entities"][0]["Address"]
        alert_name = sentinel_payload["AlertDisplayName"]
        print(f"[+] Alert Parsed: '{alert_name}'")
        print(f"[+] Extracted Suspect IP: {suspect_ip}")
    except KeyError:
        print("[!] Error: Malformed Sentinel Payload.")
        return

    # 3. THREAT INTEL QUERY: Replicating the 'Query_VirusTotal_API' block
    print("\n[*] Querying VirusTotal Threat Intelligence API...")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{suspect_ip}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    
    response = requests.get(url, headers=headers)
    time.sleep(1)
    
    if response.status_code == 200:
        data = response.json()
        malicious_score = data['data']['attributes']['last_analysis_stats']['malicious']
        print(f"[+] VirusTotal Threat Score (Malicious Vendor Hits): {malicious_score}")
        
        # 4. CONTAINMENT ENGINE: Replicating the 'Evaluate_Threat_Score' conditional logic
        print("\n[*] Evaluating Conditional Rules...")
        time.sleep(1)
        
        if malicious_score > 0:
            print("[!] THREAT DETECTED: Score crosses malicious threshold (>0).")
            print("[*] Executing 'Block_IP_in_Network_Security_Group' block...")
            print(f"[+] SUCCESS: Azure NSG updated. Inbound traffic from {suspect_ip} is now DENIED.")
        else:
            print("[+] IP reputation is clean. No containment action required. Alert closed.")
    else:
        print(f"[!] API Error: {response.status_code}")
        
    print("--- [SIMULATION COMPLETE] ---\n")

if __name__ == "__main__":
    VT_API_KEY = os.getenv("VT_API_KEY", "API_KEY_HERE")
    
    # MOCK DATA: This is the exact JSON structure Microsoft Sentinel generates
    sentinel_alert_payload = {
        "WorkspaceId": "a1b2c3d4-5678-90ef-gh12-34567890ijkl",
        "AlertDisplayName": "Suspicious RDP Brute Force Attempt",
        "Entities": [
            {
                "Type": "ip",
                "Address": "8.8.8.8"
            }
        ]
    }
    
    print("\n[*] MOCK SIEM: Generating synthetic Sentinel alert payload...")
    time.sleep(1)
    
    # Send the mock payload into our simulated Logic App
    simulate_azure_logic_app(sentinel_alert_payload, VT_API_KEY)