# Network Safety Monitor - Detection Rules

## Overview

The detection engine monitors network traffic in real-time and generates alerts when suspicious activity is identified. Each rule is designed to detect specific threat patterns while minimizing false positives.

---

## Built-in Detection Rules

### 1. Port Scan Detection

**Rule ID:** `port_scan`  
**Severity:** Warning  
**Default Threshold:** 10 different ports in 60 seconds

**What It Detects:**
An IP address connecting to many different ports on your network in a short time period.

**Why It's Suspicious:**
Port scanning is often the first step in an attack. Attackers scan ports to find which services are running and potentially vulnerable. Normal applications typically only connect to 1-3 specific ports.

**Example Alert:**
```
Title: Port Scan Detected
Description: IP 192.168.1.50 connected to 15 different ports in 60 seconds
Explanation: This behavior is consistent with port scanning, which attackers use 
to discover what services are running on your network. If this is a known device 
performing legitimate network discovery, you can acknowledge this alert.
```

**Tuning:**
- Increase threshold if you have legitimate scanning tools
- Decrease time window for more sensitive detection

---

### 2. ARP Spoofing Detection

**Rule ID:** `arp_spoof`  
**Severity:** Critical  
**Detection Method:** MAC/IP inconsistency tracking

**What It Detects:**
When an IP address is suddenly associated with a different MAC address than previously seen.

**Why It's Suspicious:**
ARP spoofing (also called ARP poisoning) is a man-in-the-middle attack where an attacker sends fake ARP messages to link their MAC address with another host's IP. This allows them to intercept, modify, or stop data in transit.

**Example Alert:**
```
Title: Possible ARP Spoofing
Description: IP 192.168.1.1 changed from MAC AA:BB:CC:DD:EE:FF to 11:22:33:44:55:66
Explanation: The gateway's MAC address has changed unexpectedly. This could indicate 
an ARP spoofing attack where someone is trying to intercept traffic between you and 
the router. However, this can also happen legitimately if network equipment was 
replaced or if you have redundant routers.
```

**False Positives:**
- Network equipment replacement
- Virtual machine MAC changes
- DHCP reassignments

---

### 3. DNS Tunneling Detection

**Rule ID:** `dns_tunnel`  
**Severity:** Warning  
**Default Threshold:** DNS packets > 512 bytes

**What It Detects:**
Unusually large DNS queries or responses that may indicate data exfiltration through DNS.

**Why It's Suspicious:**
DNS tunneling encodes data in DNS queries to bypass firewalls. Attackers use this technique to:
- Exfiltrate stolen data
- Establish command-and-control channels
- Bypass network restrictions

Normal DNS queries are typically small (< 200 bytes).

**Example Alert:**
```
Title: Possible DNS Tunneling
Description: Large DNS packet (1024 bytes) detected to suspicious-domain.com
Explanation: This DNS transaction is unusually large, which could indicate that 
data is being hidden inside DNS traffic. This technique is used to bypass firewalls. 
Some legitimate services like DNSSEC can also produce large DNS packets.
```

**False Positives:**
- DNSSEC responses
- DNS-over-HTTPS responses
- TXT record queries for SPF/DKIM

---

### 4. Packet Flood Detection

**Rule ID:** `packet_flood`  
**Severity:** Critical  
**Default Threshold:** 1000 packets in 10 seconds from single source

**What It Detects:**
An excessive number of packets from a single IP address in a short time frame.

**Why It's Suspicious:**
Packet floods are used in Denial of Service (DoS) attacks to overwhelm a target system. Types include:
- SYN floods
- UDP floods
- ICMP floods

**Example Alert:**
```
Title: Packet Flood Detected
Description: IP 192.168.1.75 sent 2500 packets in 10 seconds
Explanation: This is an abnormally high packet rate that could indicate a denial 
of service attack or a malfunctioning device. Normal network activity rarely 
exceeds a few hundred packets per second from a single source.
```

**False Positives:**
- High-bandwidth file transfers
- Video streaming
- Online gaming
- Network backup operations

---

### 5. Suspicious Port Detection

**Rule ID:** `suspicious_port`  
**Severity:** Warning  
**Detection Method:** Known malware port list

**What It Detects:**
Traffic on ports commonly used by malware, backdoors, or potentially unwanted programs.

**Monitored Ports:**

| Port | Associated Threat |
|------|------------------|
| 4444 | Metasploit default |
| 5554 | Sasser worm |
| 6666-6669 | IRC (botnet control) |
| 31337 | Back Orifice |
| 12345 | NetBus trojan |
| 27374 | SubSeven trojan |
| 1433 | SQL Server (often attacked) |
| 3389 | RDP (brute force target) |

**Example Alert:**
```
Title: Suspicious Port Activity
Description: Connection detected on port 4444 (common Metasploit port)
Explanation: Port 4444 is the default port for Metasploit, a penetration testing 
tool that is also used by attackers. If you're not running a security test, 
investigate this connection immediately.
```

**False Positives:**
- Legitimate security testing
- Some gaming servers
- Custom applications using these ports

---

### 6. ICMP Sweep Detection

**Rule ID:** `icmp_sweep`  
**Severity:** Info  
**Default Threshold:** 5 different destinations in 60 seconds

**What It Detects:**
ICMP echo requests (pings) sent to multiple IP addresses from a single source.

**Why It's Suspicious:**
ICMP sweeps are used for network reconnaissance to discover which hosts are online before launching targeted attacks. While ping is a legitimate diagnostic tool, automated sweeping across many addresses is suspicious.

**Example Alert:**
```
Title: ICMP Sweep Detected
Description: IP 192.168.1.50 pinged 20 different hosts in 60 seconds
Explanation: This host is systematically pinging multiple addresses, which is 
typically done to map the network and find active hosts. This is often a 
precursor to further scanning or attacks.
```

**False Positives:**
- Network monitoring tools
- Legitimate network diagnostics
- Network discovery protocols

---

### 7. SYN Flood Detection

**Rule ID:** `syn_flood`  
**Severity:** Critical  
**Default Threshold:** 100 SYN packets without ACK in 10 seconds

**What It Detects:**
A high number of TCP SYN packets without corresponding acknowledgments.

**Why It's Suspicious:**
SYN flood is a classic DoS attack that exploits the TCP handshake:
1. Attacker sends many SYN requests
2. Server allocates resources waiting for ACK
3. ACK never comes, resources exhausted

**Example Alert:**
```
Title: Possible SYN Flood Attack
Description: 150 unanswered SYN packets from 192.168.1.100 in 10 seconds
Explanation: This pattern matches a SYN flood attack, which tries to exhaust 
server resources by initiating many connections without completing them. 
This could render the target unresponsive.
```

---

## Detection Configuration

### Enabling/Disabling Rules

Rules can be toggled in Settings → Detection Rules or via API:

```bash
# Disable a rule
PATCH /api/alerts/rules/port_scan
{"is_enabled": false}

# Adjust threshold
PATCH /api/alerts/rules/packet_flood
{"threshold": 2000}
```

### Default Thresholds

| Rule | Threshold | Time Window |
|------|-----------|-------------|
| port_scan | 10 ports | 60 seconds |
| dns_tunnel | 512 bytes | N/A |
| packet_flood | 1000 packets | 10 seconds |
| icmp_sweep | 5 hosts | 60 seconds |
| syn_flood | 100 SYN packets | 10 seconds |

---

## Alert Rate Limiting

To prevent alert spam during sustained attacks, the system implements:

- **Per-rule cooldown:** 60 seconds between alerts for the same rule/source
- **Global rate limit:** Maximum 100 alerts per minute
- **Deduplication:** Similar alerts within cooldown are counted, not repeated

---

## Creating Custom Rules

Custom rules can be added by extending the detection engine:

```python
# In detection/engine.py

def detect_custom_threat(self, packet_data: dict) -> Optional[Alert]:
    """
    Custom detection logic example.
    """
    if packet_data.get('destination_port') == 9999:
        return self.create_alert(
            severity='warning',
            title='Custom Port Alert',
            description=f"Traffic on monitored port 9999",
            explanation="This port is being monitored for specific activity.",
            source_ip=packet_data.get('source_ip'),
            rule_id='custom_port_9999'
        )
    return None
```

---

## Interpreting Alerts

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **Info** | Noteworthy activity | Review when convenient |
| **Warning** | Suspicious behavior | Investigate soon |
| **Critical** | Likely attack | Investigate immediately |

### Investigation Steps

1. **Review the alert details** - Check source/destination IPs, ports, timing
2. **Identify the source device** - Use Network Map to find the host
3. **Check for patterns** - Are there related alerts?
4. **Verify legitimacy** - Is this expected behavior?
5. **Take action** - Block, investigate further, or acknowledge

### Common False Positive Resolution

| Alert Type | Common Cause | Solution |
|------------|--------------|----------|
| Port Scan | Network monitoring tool | Whitelist the scanner IP |
| ARP Spoof | Router replacement | Acknowledge and update baseline |
| DNS Tunnel | DNSSEC | Adjust size threshold |
| Packet Flood | Large file transfer | Increase threshold |

---

## Advanced Detection Rules (v2.0)

The following rules use behavioral analysis and correlation to detect sophisticated threats.

### 8. Lateral Movement Detection

**Rule ID:** `LATERAL_MOVEMENT`  
**Severity:** Critical  
**Default Threshold:** 3 internal hosts via admin ports in 5 minutes

**What It Detects:**
A single host connecting to multiple internal systems using administrative protocols (SMB, RDP, SSH, WinRM, etc.).

**Monitored Admin Ports:**

| Port | Protocol | Description |
|------|----------|-------------|
| 22 | SSH | Secure Shell |
| 23 | Telnet | Legacy terminal |
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | Windows networking |
| 445 | SMB | Windows file sharing |
| 3389 | RDP | Remote Desktop |
| 5985/5986 | WinRM | Windows Remote Management |

**Why It's Critical:**
Lateral movement is a key phase in advanced attacks (APT). After gaining initial access to one system, attackers move sideways through the network to:
- Find valuable data
- Gain higher privileges
- Maintain persistence on multiple systems

**Example Alert:**
```
Title: Lateral Movement Detected
Description: 192.168.1.50 connected to 5 internal hosts via admin ports (SMB/RDP)
Explanation: This host has connected to multiple internal systems using administrative 
protocols (file sharing, remote desktop). This pattern is common when an attacker has 
compromised a system and is moving through your network. If this is IT staff doing 
maintenance, you can acknowledge this alert.
Evidence:
- Internal hosts contacted: 192.168.1.10, .20, .30, .40, .50
- Ports used: 445 (SMB), 3389 (RDP)
- Time span: 4 minutes
Confidence: 0.88 (high - 5 hosts exceeds threshold of 3)
```

**False Positives:**
- IT administrators doing maintenance
- Automated deployment/patch tools
- Network inventory scanners

---

### 9. Beaconing Detection

**Rule ID:** `BEACONING_DETECTED`  
**Severity:** Warning  
**Detection Method:** Connection interval regularity analysis

**What It Detects:**
Regular, automated "phone home" communication patterns typically used by malware to communicate with command-and-control (C2) servers.

**How Detection Works:**
1. Track connection timestamps to external destinations
2. Calculate intervals between connections
3. Compute Coefficient of Variation (CV = std_dev / mean)
4. CV < 0.15 with 10+ samples = suspicious regularity

**Why It's Suspicious:**
Humans don't do things on exact schedules. When connections happen at very regular intervals (e.g., exactly every 30 seconds), it's almost certainly automated:
- Malware beacons
- RAT (Remote Access Trojan) check-ins
- Botnet command channels

**Example Alert:**
```
Title: Beaconing Pattern Detected
Description: 192.168.1.75 showing regular callbacks to 203.0.113.50:443
Explanation: This host is making connections at very regular intervals (avg 30.2 sec, 
CV=0.08), which strongly suggests automated communication. Normal human activity 
shows irregular timing. This could indicate malware "phoning home" for instructions.
Evidence:
- Mean interval: 30.2 seconds
- Coefficient of Variation: 0.08 (very regular)
- Sample size: 25 connections
- Destination: 203.0.113.50:443
Confidence: 0.91
```

**False Positives:**
- Legitimate monitoring agents
- Health check services
- Scheduled sync applications

---

### 10. Broadcast Storm Detection

**Rule ID:** `BROADCAST_STORM`  
**Severity:** Warning  
**Default Threshold:** 100 broadcasts per minute from single source

**What It Detects:**
Excessive broadcast traffic from a single device that could degrade network performance.

**Why It's Concerning:**
Broadcasts go to ALL devices on the network segment. Excessive broadcasts can:
- Saturate network bandwidth
- Force all NICs to process packets
- Indicate malfunctioning hardware
- Be a deliberate DoS attack

**Example Alert:**
```
Title: Broadcast Storm Detected
Description: 192.168.1.100 sending 250 broadcasts/minute
Explanation: This device is flooding the network with broadcast packets, which all 
devices must process. This significantly impacts network performance. Common causes 
include network loops, malfunctioning network cards, or misconfigured applications.
Evidence:
- Broadcast count: 250 in 60 seconds
- Top broadcast types: ARP (120), NetBIOS (80), DHCP (50)
Confidence: 0.82
```

---

### 11. Rogue DHCP Server Detection

**Rule ID:** `ROGUE_DHCP`  
**Severity:** Critical  
**Detection Method:** Multiple DHCP server identification

**What It Detects:**
More than one device responding to DHCP requests on the network.

**Why It's Critical:**
A rogue DHCP server is one of the most dangerous network attacks because it can:
- Assign itself as the default gateway (intercept all traffic)
- Point devices to malicious DNS servers
- Create network chaos with conflicting IP assignments

You should only have ONE authorized DHCP server (usually your router).

**Example Alert:**
```
Title: Rogue DHCP Server Detected
Description: Multiple DHCP servers found: 192.168.1.1 (expected), 192.168.1.200 (ROGUE)
Explanation: Your network should only have one DHCP server, but we detected two devices 
responding to DHCP requests. The unauthorized server at 192.168.1.200 could be 
redirecting network traffic through an attacker's system. INVESTIGATE IMMEDIATELY.
Evidence:
- Authorized DHCP server: 192.168.1.1
- Rogue DHCP server: 192.168.1.200
Confidence: 0.95
```

**False Positives:**
- Legitimate secondary DHCP server
- Testing environment
- VM host running DHCP

---

### 12. New Device Risk Scoring

**Rule ID:** `NEW_DEVICE_RISK`  
**Severity:** Varies (based on risk score)  
**Observation Period:** 5 minutes

**What It Detects:**
New devices joining the network that exhibit suspicious initial behavior patterns.

**Risk Scoring Factors:**

| Factor | Weight | What It Means |
|--------|--------|---------------|
| Immediate external traffic | 15% | Contacts outside IPs right away |
| Contacts many internal hosts | 20% | Potential scanning |
| Uses suspicious ports | 25% | Known-bad ports (4444, etc.) |
| Accesses admin ports | 15% | Tries RDP, SMB, SSH |
| High traffic volume | 10% | Unusual bandwidth |
| Unknown MAC vendor | 10% | Can't identify manufacturer |

**Why It's Useful:**
When a new device joins your network, its initial behavior reveals intent:
- Legitimate devices: get IP, check for updates, normal traffic
- Malicious devices: scan network, beacon out, probe admin ports

**Example Alert:**
```
Title: High-Risk New Device
Description: New device AA:BB:CC:DD:EE:FF scored 72/100 risk
Explanation: A new device joined your network and immediately exhibited concerning 
behavior. Within 5 minutes it: contacted 15 internal hosts, attempted connections 
to port 4444, and started beaconing to an external IP. This warrants investigation.
Risk Factors:
- Immediate external traffic: +15%
- Contacted 15 internal hosts: +20%
- Used suspicious port 4444: +25%
- Attempted SMB (port 445): +15%
Overall Risk Score: 72/100
Confidence: 0.78
```

---

### 13. Correlated Attack Chain Detection

**Rule ID:** `CORRELATED_ATTACK`  
**Severity:** Varies (escalates with chain length)  
**Detection Method:** Attack phase state machine

**What It Detects:**
Multiple related detections that together indicate a coordinated attack campaign.

**Attack Phases Tracked:**

| Phase | Associated Detections |
|-------|----------------------|
| Reconnaissance | Port scan, ICMP sweep |
| Initial Access | Suspicious port, packet flood |
| Lateral Movement | Lateral movement, ARP spoof |
| Persistence | Rogue DHCP |
| Command & Control | Beaconing |
| Exfiltration | DNS tunneling |

**State Machine:**
```
IDLE → RECON_DETECTED → ACCESS_DETECTED → ACTIVE_ATTACK → POST_COMPROMISE
```

**Why Correlation Matters:**
Individual detections might be false positives. But when we see a sequence:
1. Port scan from IP X
2. Suspicious port traffic from IP X
3. Lateral movement from IP X
4. Beaconing from IP X

...we can be much more confident this is a real attack.

**Example Alert:**
```
Title: Correlated Attack Chain: 4 Indicators
Description: Attack progression detected from 192.168.1.50
Explanation: Multiple related security events from 192.168.1.50 suggest a coordinated 
attack rather than isolated incidents. The pattern shows: initial scanning, followed 
by suspicious traffic, then spreading to other systems, and finally regular callbacks 
to an external server. This is consistent with a successful network compromise.

Attack Timeline:
- 10:05:23 - PORT_SCAN_DETECTION (Reconnaissance)
- 10:08:45 - SUSPICIOUS_PORT traffic (Initial Access)
- 10:12:01 - LATERAL_MOVEMENT to 3 hosts (Spreading)
- 10:15:33 - BEACONING_DETECTED to 45.33.32.156 (C2 established)

Attack State: ACTIVE_ATTACK
Confidence: 0.92 (4 correlated indicators)
False Positive Likelihood: Very Low
```

---

## Evidence Model

All advanced detections include structured evidence for full transparency:

```json
{
  "time_window": {
    "start": "2024-01-15T10:00:00Z",
    "end": "2024-01-15T10:05:00Z",
    "duration_seconds": 300
  },
  "evidence_items": [
    {
      "type": "unique_targets",
      "key": "internal_hosts_contacted",
      "value": 5,
      "threshold": 3,
      "unit": "hosts",
      "description": "Unique internal hosts accessed via admin ports"
    }
  ],
  "confidence": {
    "base_score": 0.7,
    "adjustments": [
      {"reason": "Threshold exceeded by 1.67x", "value": 0.10},
      {"reason": "Multiple admin ports used", "value": 0.08}
    ],
    "final_score": 0.88
  },
  "false_positive": {
    "likelihood": "medium",
    "score": 0.35,
    "possible_reasons": ["IT maintenance", "deployment automation"],
    "mitigation_hints": ["Check if source is IT workstation", "Verify with IT team"]
  },
  "recommended_action": {
    "priority": "immediate",
    "summary": "Investigate source device for compromise",
    "steps": [
      "1. Identify the device at 192.168.1.50",
      "2. Check for unauthorized software",
      "3. Review recent login activity",
      "4. Consider isolating from network"
    ]
  }
}
```

---

## Best Practices

1. **Start with default thresholds** - Adjust based on your network's baseline
2. **Review alerts regularly** - Don't let them accumulate unacknowledged
3. **Document false positives** - Helps tune detection over time
4. **Correlate alerts** - Multiple alerts often indicate a single incident
5. **Keep rules enabled** - Disable only when absolutely necessary
6. **Trust the evidence** - Every detection shows exactly why it triggered
7. **Investigate attack chains** - Correlated alerts deserve priority attention
8. **Monitor new devices** - Initial behavior reveals intent
