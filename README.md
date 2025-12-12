# PacketSentinel

### Real-Time Network Intrusion Detection System (NIDS)

PacketSentinel is a lightweight, Python-based NIDS designed to monitor network traffic in real-time, detect suspicious anomalies, and provide actionable forensic logs. Built with **Scapy**, it acts as a standalone security agent for listening to network packets and identifying potential threats like Syn Floods or suspicious port scanning.

## Features
- **Real-Time Traffic Monitoring:** Captures and analyzes TCP/UDP/ICMP packets on the fly.
- **Anomaly Detection:** Identifies potential threats using customizable rule-based logic.
- **Forensic Logging:** Exports detailed incident logs to \packetsentinel_logs.json\ for further analysis.
- **Dashboard Interface:** Includes a live console dashboard for viewing packet statistics.

## Installation

1. Clone the repository:
   \\\ash
   git clone https://github.com/JAMPANIKOMAL/My-SIEM.git
   cd My-SIEM/agent
   \\\`n
2. Install dependencies:
   \\\ash
   pip install -r requirements.txt
   \\\`n
## Usage

**Note:** Network sniffing requires elevated privileges.

1. Run the agent (as Administrator/Root):
   \\\ash
   # Linux/Mac
   sudo python app.py

   # Windows (Run Terminal as Admin)
   python app.py
   \\\`n
2. Open the dashboard:
   - Go to \http://127.0.0.1:5000\ in your browser.
   - Select your network interface to begin sniffing.

## Future Roadmap
- [ ] **Data Persistence:** Migrate to Elasticsearch/SQLite for long-term log storage.
- [ ] **Threat Intelligence:** Integrate real-time threat feeds (AlienVault OTX).
- [ ] **Web Dashboard:** Replace console output with a Flask/React dashboard for visualization.
