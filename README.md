# SOC Analyst Email Investigation

## Objective
As a SOC (Security Operations Center) Analyst, the task was to analyze multiple suspicious emails reported by coworkers. Using a combination of email analysis tools and techniques, the goal was to extract relevant information from the emails and identify any malicious content or indicators of compromise.

## Skills Learned
- Email Header Analysis
- Defanging IP Addresses
- Malware Identification
- Using CyberChef for data manipulation
- WHOIS Lookup for IP Address Investigation
- Understanding of Cisco Talos Intelligence

## Tools Used
- **Mozilla Thunderbird**: For viewing and managing the suspicious emails.
- **CyberChef**: To defang IP addresses and analyze suspicious strings.
- **Cisco Talos Intelligence**: To gather additional information on IP addresses.
- **DomainTools**: For performing WHOIS lookups to identify the owner of suspicious IPs.
- **VirusTotal**: To scan and identify malware associated with suspicious email attachments.

## Steps

### 1. Analyze Email Headers
- **Objective**: Extract information about the email's origin and path.
- **Tools Used**: Mozilla Thunderbird, Pluma text editor.
- **Action**: Opened `Email1.eml`, `Email2.eml`, and `Email3.eml` using Mozilla Thunderbird and inspected the headers using the Pluma text editor.
- **Outcome**: Determined the originating IP addresses and noted the number of hops the email took to reach the recipient.

![Email Header Analysis](https://user-images.githubusercontent.com/12345678/123456789-email-header-analysis.png)

### 2. Defang IP Addresses
- **Objective**: Make the IP addresses safe to share and analyze.
- **Tools Used**: CyberChef.
- **Action**: Used CyberChef to defang the IP address `204.93.183.11` from the email headers.
- **Outcome**: IP address was successfully defanged for further analysis.

![CyberChef Defanging](https://user-images.githubusercontent.com/12345678/123456789-cyberchef-defang.png)

### 3. Perform IP Address Lookup
- **Objective**: Identify the owner of the IP address and gather more details.
- **Tools Used**: Cisco Talos Intelligence, DomainTools.
- **Action**: Looked up the IP address `204.93.183.11` using Cisco Talos Intelligence and DomainTools WHOIS Lookup.
- **Outcome**: Determined that the IP address belonged to `scnet.net`, associated with `Complete Web Reviews`.

![Cisco Talos Lookup](https://user-images.githubusercontent.com/12345678/123456789-cisco-talos.png)
![DomainTools WHOIS Lookup](https://user-images.githubusercontent.com/12345678/123456789-domaintools-whois.png)

### 4. Analyze Suspicious Attachments
- **Objective**: Identify and understand the nature of attachments associated with the suspicious emails.
- **Tools Used**: Mozilla Thunderbird, VirusTotal.
- **Action**: Downloaded and analyzed the attachments from `Email3.eml`, specifically `Sales_Receipt 5606.xls`, using VirusTotal.
- **Outcome**: Identified the malware associated with the attachment as **Dridex**.

![VirusTotal Analysis](https://user-images.githubusercontent.com/12345678/123456789-virustotal.png)

## Summary of Findings
- **Email1.eml**: Phishing attempt posing as LinkedIn, originating from IP `204.93.183.11`.
- **Email2.eml**: Malicious email containing the malware **HIDDENEXT/Worm.Gen**.
- **Email3.eml**: Attached file `Sales_Receipt 5606.xls` was confirmed to be part of the **Dridex** malware family.

This investigation showcases the importance of thorough email analysis in identifying potential threats and protecting the organization's security posture. By following structured analysis steps and leveraging various tools, it was possible to uncover the malicious intent behind these emails and respond accordingly.

