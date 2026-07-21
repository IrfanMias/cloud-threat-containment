import os
import requests
import json

def test_vt_ip_lookup(ip_address, api_key):
    # The standard VirusTotal v3 endpoint for IP address reports
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    # VirusTotal requires the API key to be passed in the 'x-apikey' header
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    print(f"[*] Sending test payload to VirusTotal for IP: {ip_address}...")
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print("[+] Connection successful! Parsing payload...")
        data = response.json()
        
        # Extracting the malicious vote count as a proof-of-concept for our Logic App
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        print(f"[-] Malicious hits for {ip_address}: {malicious_votes}")
        
        # Save the full JSON response to a local file for architecture review
        with open("scripts/vt_sample_response.json", "w") as f:
            json.dump(data, f, indent=4)
        print("[+] Full JSON payload saved to 'scripts/vt_sample_response.json'")
    
    elif response.status_code == 401:
        print("[!] Error 401: Unauthorized. Please check your API key.")
    else:
        print(f"[!] Error {response.status_code}: {response.text}")

if __name__ == "__main__":
    # Use Google's public DNS (8.8.8.8) as a safe baseline test
    TEST_IP = "8.8.8.8"
    
    VT_API_KEY = os.getenv("VT_API_KEY", "API_KEY_HERE")
    
    test_vt_ip_lookup(TEST_IP, VT_API_KEY)