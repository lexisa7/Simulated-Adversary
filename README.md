# Simulated-Adversary, # SOC, #Tryhackme
CYBER DEFENSE FRAMEWORKS: Summit Project 

Objective: Penetration test, Detect and block
Environment: Sandbox environment presented by TRYHACKME
Information provided: SHA1, SHA256 AND MD5, IP, Port info, some logs, 6 simulations/samples



Sample 1
Action: Copy and paste the SHA256 hash related to the malicious file.
Outcome: Updated the EDR (Endpoint Detection and Response) to improve detection and block similar hashes.

Sample 2
Action: Ran Sample 2 in the sandbox environment. Documented the IP address manually during the second penetration test.

Created a firewall rule:
Type: Egress
Source: Any
Destination IP: 154.35.10.113
Action: Deny

Outcome:
Controlled incoming and outgoing traffic.

Sample 3
Action: Documented key information such as HTTP requests, TCP/UDP connections, and DNS requests.

Observed the following:
- 2 HTTP requests
- 4 TCP/UDP connections
- 2 DNS requests
- Noted a backdoor access with the IP address: 62.123.140.9:80.
- Created a DNS rule based on the accessed DNS via the backdoor
Input:
Name: Sample3
Category: Malware
DNS: emudyn.bresconicz.info
Action: Deny

Outcome:
Controlled incoming and outgoing traffic by filtering the DNS.


Sample 4
Action: Identified changes/artifacts left by malware on the victim's host systems. Documented the IP address: 102.23.20.118.
Observed:
- 2 HTTP requests
- 3 TCP/UDP connections
- 1 DNS request
- Noted Process IDs (PID) and actions:
- PIDs: 3806, 1928, 9876
  
Actions: Disable RT Monitoring, Enable Balloon Tips, Progid

Attempted to create a firewall rule, but it did not detect or block any malicious activity. Developed a Sigma rule blocker.
Analyzed Sysmon event logs and created a registry modification to detect system changes.

Set rule conditions with the following:
Registry Key: Provided key
Registry Name: Disablerealtimemonitoring
Value: 1
ATT&CK ID: Defense Evasion
Outcome: Created a Sigma rule to identify suspicious activity.

Sample 5
Action: This was the most challenging sample. Attempted firewall and DNS rules before creating a Sigma rule.
Documented key information:
- Suspicious Activity: Downloading executable files from the internet
- 402 HTTP requests
- 3 TCP/UDP connections
- 1 DNS request
- Domain: bababa10la.cn
- IP: 51.102.10.19

Selected network connection details and input:
Remote IP: Replaced with "ANY" due to advanced malicious attempt
Remote Port: Replaced with "ANY"
Frequency: Observed every 30 minutes (converted to 1800 seconds)
Defined conditions for command and control (C2) attack.
Outcome: Set rules for network connections from the host with specific conditions.

Sample 6
Documented:
- Downloadable executable files
- 2 HTTP requests
- 3 TCP/UDP connections
- 1 DNS request

Action: Created a Sigma rule for process creation:
Process: cmd.exe
String: %temp%\exfiltr8.log
Outcome: Successfull completion of the simulation.
