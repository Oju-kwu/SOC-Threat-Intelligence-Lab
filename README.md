# SOC-Threat-Intelligence-Lab

## Objective
This project aims to analyze and enhance threat intelligence feeds to improve SOC operations by integrating VirusTotal into Wazuh. The integration of threat intelligence feeds helps analyze and optimize alerts within Wazuh, using the VirusTotal.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in monitoring, analyzing and interpreting alert logs.
- Creating custom rule for SIEM to trigger alert and query Virustotal.
- Ability to integrate threat intelligence tools in a SIEM using API.
- Enhanced threat intelligence IOCs gathering.
- Compliance in security operations using cybersecurity frameworks.
- Deployment of endpoints to Cloud SIEM.
- Navigating through alerts and generating comprehensive reports.

### Tools Used
- AWS based Security Information and Event Management (SIEM) tool, Wazuh.
- Open Source Intelligence Tool, Virustotal.
- Windows endpoints to generate alerts.
- kali Linux

### Steps
- Launch an EC2 instance
- Connect to EC2 instance
- Update Server using the following command; sudo apt-get update and sudo apt-get upgrade
- Download Wazuh and Install using the  command; curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

![image](https://github.com/user-attachments/assets/c0ca6910-97ba-4590-bdef-78f0911686fe)

*Ref 1: Configuration and installation of agents to Wazuh*

![image](https://github.com/user-attachments/assets/1f1c74f8-4300-48bd-a5d2-e5f9146563a1)

*Ref 2: Deployment  of agents to Wazuh*

Create an account on virustotal to get the API key 
![Picture1](https://github.com/user-attachments/assets/c1d067ad-3920-4f66-b7b2-a43bbadda172)

*Ref 3: Virustotal account API*

Copy the API key and open the configuration file /var/ossec/etc/ossec.conf  and add the API key on wazuh server to enable virustotal integration and save.

Go to settings on wazuh manager to confirm the integration of virustotal API key and restart manager.

Enable file integrity monitoring in configuration file to make wazuh to trigger virustotal integration when FIM alert occurs.
![Picture2](https://github.com/user-attachments/assets/329f452b-22c9-4f66-a555-b85c535e5fd7)

*Ref 4: Integration Virustotal API to Wazuh Configuration Manager*

![image](https://github.com/user-attachments/assets/6919e10b-385e-4299-a86c-a4b4144f974c)

*Ref 5: Wazuh Dashboard for alert monitoring and analysis*

### Conclusion
In conclusion, this project has highlighted the critical role of enhanced threat intelligence feeds in supporting effective SOC operations. Small enhancements in threat intelligence processing can yield significant improvements. These changes reduce the workload on SOC analysts and empower them to respond to genuine threats more rapidly.

Future work could further explore automation and machine learning techniques, aiming to make threat intelligence feeds even more adaptive to emerging cyber threats. Ultimately, this project contributes to a foundational understanding that enriched, high-quality intelligence feeds are essential for improved SOC operations. As cyber threats evolve, so must the methods of intelligence gathering and processing, making it imperative for SOCs to continuously refine their threat intelligence strategies.

