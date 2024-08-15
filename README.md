# Email Threat Analysis Using Cisco Talos Intelligence

## Objective

The objective of this project is to analyze a suspicious email file (`Email1.eml`) using Thunderbird within a virtual machine (VM) to identify potential threats. The analysis includes inspecting the email content, headers, and using Cisco Talos Intelligence for deeper threat investigation. The VM does not have internet access, so external research is performed on a separate device.

## Skills Learned

- Email threat detection and analysis
- Utilization of Thunderbird for offline email inspection
- Application of Cisco Talos Intelligence for threat research
- Manual header analysis and IP defanging
- Understanding of phishing tactics and email spoofing

## Tools Used

- **Thunderbird:** Email client used for analyzing `Email1.eml`.
- **Cisco Talos Intelligence:** A threat intelligence platform for researching identified IOCs.
- **CyberChef:** A tool used for defanging IP addresses.
- **PhishTool:** Used for analyzing email headers and metadata (when online access is available).
- **Virtual Machine (VM):** An isolated environment for safe analysis.

## Steps

1. **Setup:**
   - Launch the provided VM and open Thunderbird.
   - Open the `Email1.eml` file from the Desktop.

2. **Email Inspection:**
   - Bypass Thunderbird’s account setup.
   - Analyze the email for obvious indicators of phishing or malicious content.

3. **Header Analysis:**
   - Access email headers via `More > View Source`.
   - Search for key indicators like "Sender IP" and analyze the email hops.

4. **Identify Key Information:**
   - **Attacker's Posed Platform:** LinkedIn.
   - **Sender's Email Address:** darkabutla@sc500.whpservers.com
   - **Recipient's Email Address:** cabbagecare@hotsmail.com
   - **Originating IP Address (Defanged):** 204[.]93[.]183[.]11
   - **Email Hops:** 4 hops.

5. **Research with Cisco Talos Intelligence:**
   - Use Talos to search for the IP address.
   - **Domain of IP Address:** scnet.net
   - **Customer Name:** Complete Web Reviews

6. **Documentation:**
   - Summarize findings and record answers to the provided questions.
   - Use external resources to further validate the identified threats.

## Results

- **Phishing Attempt Detected:** The attacker attempted to impersonate LinkedIn.
- **Threats Identified:** Several indicators point to phishing and possible email spoofing.
- **Cisco Talos Insights:** The IP is linked to a known domain and customer, indicating potential malicious activity.

## Conclusion

This project involved a comprehensive analysis of a suspicious email in a secure offline environment. The process highlighted the importance of understanding email headers and using tools like Cisco Talos for effective threat intelligence.

