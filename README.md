# fairwall_python_code
cyber security project
Firewall_on_Windows-or-Linux_task_4_Elevate-Labs A firewall is a network security device or software that monitors and controls incoming and outgoing traffic based on predefined rules. It acts as a barrier between a trusted internal network (like a company's LAN) and untrusted external networks (such as the internet), blocking unauthorized access while allowing legitimate communication.

Types of Firewalls Hardware Firewalls: Physical devices (e.g., routers with built-in firewalls) that protect entire networks. Software Firewalls: Programs installed on computers or servers (e.g., Windows Firewall) for individual device protection. Next-Generation Firewalls (NGFW): Advanced versions that include features like deep packet inspection, intrusion prevention, and application awareness.

Intrusion Detection System (IDS) An IDS is a security tool that monitors network traffic or system activities for signs of malicious behavior, policy violations, or security threats. It analyzes data in real-time or retrospectively, generating alerts when anomalies are detected (e.g., unusual login attempts or known attack patterns). IDS operates passively, meaning it doesn't block threats itself but notifies administrators for response. Types include:

Network-based IDS (NIDS): Monitors network packets. Host-based IDS (HIDS): Focuses on individual devices.

Intrusion Prevention System (IPS) An IPS builds on IDS by not only detecting threats but actively preventing them. It inspects traffic, identifies malicious activity, and takes automated actions like blocking IP addresses, dropping packets, or resetting connections. IPS can be inline (traffic passes through it) or integrated with firewalls. It's proactive, reducing response time compared to IDS alone, but may cause false positives leading to legitimate traffic being blocked.

Common Configuration Types Rule-Based: Simple allow/deny lists (e.g., iptables on Linux). Stateful Inspection: Tracks connection states (e.g., allows return traffic for outbound requests). Application Layer: Inspects content (e.g., URL filtering in NGFWs). VPN Integration: Configures tunnels for secure remote access.
