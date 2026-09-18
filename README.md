# PacketSentinel

### Real-Time Network Intrusion Detection System (NIDS)

PacketSentinel is a lightweight, Python-based NIDS designed to monitor network traffic in real-time, detect suspicious anomalies, and provide actionable forensic logs. Built with **Scapy**, it acts as a standalone security agent for listening to network packets and identifying potential threats like SYN floods or suspicious port scanning, with a live web dashboard.

## Features
- **Real-Time Traffic Monitoring:** Captures and analyzes TCP/UDP/ICMP packets on the fly via Scapy.
- **Rule-Based Blocking:** Blocks traffic matching configurable IP/port/protocol rules (`agent/rules.json`), editable live from the dashboard.
- **Live Web Dashboard:** Flask + Socket.IO dashboard streaming packet events in real time, with charts by protocol, action, and top talkers.
- **Forensic Logging:** All captured events are stored in a local SQLite database and can be exported as JSON from the dashboard.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/JampaniKomal/PacketSentinal.git
   cd PacketSentinal/agent
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

**Note:** Network sniffing requires elevated privileges.

1. Run the agent (as Administrator/Root):
   ```bash
   # Linux/Mac
   sudo python app.py

   # Windows (Run Terminal as Admin)
   python app.py
   ```
2. Open the dashboard at `http://127.0.0.1:5000` and select a network interface to begin sniffing.

The dashboard is bound to localhost only and has no authentication, so it's meant to run on the same machine you're viewing it from — don't expose it to a network.

## Testing & Verification

- Ran the sniffer against live local traffic and confirmed packets stream to the dashboard in real time, charts update, and rule add/remove/save-logs all work end to end.
- Found and fixed a real cross-platform bug: `block_ip()` shelled out to `iptables` unconditionally. On any non-Linux OS (including the Windows setup this README documents), that raised an uncaught `FileNotFoundError` mid-packet-handling, silently breaking logging for any packet that matched a block rule. It's now gated on `platform.system() == "Linux"` and degrades to a warning instead of crashing elsewhere.
- The dashboard previously ran with `host="0.0.0.0"` and Flask `debug=True` — reachable from the network with an unauthenticated Werkzeug debug console (a real remote-code-execution surface) attached. Now bound to `127.0.0.1` with debug mode off.

## Known Limitations

- **IP blocking is Linux-only.** It shells out to `iptables`; on Windows/Mac, matching packets are still logged and flagged as blocked in the dashboard, but no OS-level firewall rule is actually applied.
- **No authentication** on the dashboard — acceptable only because it's bound to localhost.
- Detection logic is simple rule matching (blocked IPs/ports/protocols) rather than statistical anomaly detection.

## Future Roadmap
- [ ] **Data Persistence:** Migrate to Elasticsearch/SQLite for long-term log storage.
- [ ] **Threat Intelligence:** Integrate real-time threat feeds (AlienVault OTX).
- [ ] **Anomaly Detection:** Flag traffic patterns (frequent source IPs, rare protocols, repeated blocks) beyond simple rule matching.

## License

MIT — see [LICENSE](LICENSE).
