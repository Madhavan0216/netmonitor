# NetMonitor Detection System

> "Zeek-level thinking, but readable."

## Philosophy

Every detection in NetMonitor follows these principles:

1. **No hidden heuristics** - Every decision is explainable
2. **No "AI decided"** - All logic is auditable and documented
3. **No scoring without justification** - Confidence comes from observable factors
4. **Beginner-friendly explanations** - Plain English, no unexplained jargon

---

## Detection Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Detection Engine                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Core Rules  │  │  Advanced   │  │ Correlation │              │
│  │             │  │   Rules     │  │   Engine    │              │
│  │ • Port Scan │  │ • Lateral   │  │             │              │
│  │ • Flood     │  │   Movement  │  │ • State     │              │
│  │ • ARP Spoof │  │ • Beaconing │  │   Machines  │              │
│  │ • DNS Abuse │  │ • Broadcast │  │ • Attack    │              │
│  │ • ICMP Sweep│  │ • Device    │  │   Chains    │              │
│  │             │  │   Risk      │  │             │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                           │                                      │
│                    ┌──────▼──────┐                              │
│                    │  Evidence   │                              │
│                    │   Model     │                              │
│                    └─────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Evidence Model

Every detection includes a complete evidence package:

### Evidence Structure

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
      "key": "destination_ports",
      "value": 47,
      "threshold": 10,
      "unit": "ports",
      "description": "Unique destination ports contacted"
    }
  ],
  "confidence": {
    "base_score": 0.7,
    "adjustments": [
      {"reason": "Threshold exceeded by 4.7x", "value": 0.15}
    ],
    "final_score": 0.85
  },
  "false_positive": {
    "likelihood": "medium",
    "score": 0.35,
    "possible_reasons": ["legitimate_scanner", "monitoring_tool"],
    "mitigation_hints": ["Check if source is IT workstation"]
  },
  "recommended_action": {
    "priority": "soon",
    "summary": "Investigate source device",
    "steps": ["1. Identify device", "2. Check for scanning software", "..."]
  }
}
```

### Evidence Types

| Type | Description | Example |
|------|-------------|---------|
| `packet_count` | Number of packets/connections | 150 SYN packets |
| `unique_targets` | Unique destinations | 47 different ports |
| `time_pattern` | Timing regularity | CV=0.08 (very regular) |
| `threshold_breach` | Value exceeded limit | 1000 > 100 threshold |
| `state_change` | Something changed | MAC address changed |
| `behavioral` | Pattern over time | Risk factors list |
| `correlation` | Combined signals | 3 related detections |
| `statistical` | Anomaly measure | 2.5 std deviations |

### Confidence Calculation

Confidence is **calculated**, not guessed:

```
Base confidence (from rule design)
  + Sample size adjustment (+/- based on observation count)
  + Threshold ratio adjustment (+/- based on how much limit exceeded)
  + Corroboration adjustment (+ if multiple signals agree)
  = Final confidence (clamped to 0.1 - 0.99)
```

---

## Core Detection Rules

### 1. Port Scan Detection

**Rule ID:** `PORT_SCAN_DETECTION`  
**Severity:** Warning  
**Threshold:** 10 unique ports in 60 seconds (configurable)

**What it detects:**
A host connecting to many different ports on your network.

**Evidence collected:**
- Unique destination ports contacted
- Total connection attempts
- Sample of scanned ports

**Plain English:**
> Port scanning is like someone walking down a hallway trying every door handle. 
> They're looking for unlocked doors (running services). By itself it's not an attack, 
> but it's often reconnaissance before one.

**False positive likelihood:** Medium
- Legitimate causes: vulnerability scanners, IT monitoring tools, backup software

---

### 2. Packet Flood Detection

**Rule ID:** `PACKET_FLOOD_DETECTION`  
**Severity:** Critical  
**Threshold:** 1000 packets in 10 seconds

**What it detects:**
Unusually high packet rate from a single source.

**Evidence collected:**
- Packet count in window
- Destination being flooded (if identifiable)

**Plain English:**
> Imagine someone yelling so loud in a room that no one else can talk. A packet flood 
> tries to overwhelm your network or a specific service with so much traffic that 
> legitimate traffic can't get through.

**False positive likelihood:** Medium
- Legitimate causes: large file transfers, video streaming, backups

---

### 3. ARP Spoofing Detection

**Rule ID:** `ARP_SPOOF_DETECTION`  
**Severity:** Critical  
**Detection:** MAC address change for known IP

**What it detects:**
An IP address suddenly associated with a different MAC address.

**Evidence collected:**
- Previous MAC address
- New MAC address
- IP address affected

**Plain English:**
> Your network uses ARP to know which physical device (MAC) owns which IP address. 
> If an attacker wants to intercept your traffic, they can pretend to be your router 
> by announcing "I'm the router now!" with their own MAC address. Then your traffic 
> goes to them first.

**False positive likelihood:** Medium
- Legitimate causes: device replacement, VM migration, DHCP reassignment

---

### 4. DNS Tunneling Detection

**Rule ID:** `DNS_TUNNEL_DETECTION`  
**Severity:** Warning  
**Threshold:** DNS queries > 50 characters

**What it detects:**
Unusually long DNS queries that may encode hidden data.

**Evidence collected:**
- Query length
- Query preview
- Source IP

**Plain English:**
> DNS is supposed to be for looking up domain names, like translating "google.com" 
> to an IP address. But clever attackers can hide data inside DNS queries to sneak 
> information out of your network, because most firewalls allow DNS traffic.

**False positive likelihood:** Low
- Legitimate causes: DNSSEC, some CDN providers, TXT records

---

### 5. DNS High Rate Detection

**Rule ID:** `DNS_HIGH_RATE`  
**Severity:** Warning  
**Threshold:** 100 queries per minute

**What it detects:**
Unusually high DNS query frequency from a single source.

**Evidence collected:**
- Query count
- Time window

**Plain English:**
> Normal computers make maybe a few DNS queries per minute. If something is making 
> hundreds, it might be malware "phoning home" through DNS, or there could be a 
> misconfigured application.

---

### 6. Suspicious Port Detection

**Rule ID:** `SUSPICIOUS_PORT`  
**Severity:** Warning  
**Monitored ports:** 4444, 5555, 6666, 31337, 12345, 65535, 1337, 6667

**What it detects:**
Traffic on ports commonly used by hacking tools and malware.

**Evidence collected:**
- Port number
- Traffic direction (inbound/outbound)
- Source and destination IPs

**Plain English:**
> Some port numbers are infamous because they're the defaults for hacking tools. 
> Port 4444 is Metasploit's default, port 31337 ("elite" in hacker speak) was used 
> by Back Orifice. If you see traffic on these, something suspicious might be happening.

---

### 7. ICMP Sweep Detection

**Rule ID:** `ICMP_SWEEP_DETECTION`  
**Severity:** Info  
**Threshold:** 20 ICMP requests in 30 seconds

**What it detects:**
Systematic pinging of multiple hosts (host discovery).

**Evidence collected:**
- Ping count
- Source IP

**Plain English:**
> A ping sweep is like calling every phone number in sequence to see who answers. 
> Attackers use it to find which computers are online before targeting them. Your 
> IT team might also do this legitimately for network inventory.

---

### 8. Failed Connection Detection

**Rule ID:** `FAILED_CONN_DETECTION`  
**Severity:** Info  
**Threshold:** 20 TCP RST packets in 60 seconds

**What it detects:**
Repeated connection failures to a destination.

**Evidence collected:**
- Reset count
- Destination IP

**Plain English:**
> TCP RST (reset) packets mean "connection refused." Lots of them usually means 
> someone is trying to connect to ports that aren't open - either scanning, or 
> a misconfigured application, or a crashed service.

---

## Advanced Detection Rules

### 9. Lateral Movement Detection

**Rule ID:** `LATERAL_MOVEMENT`  
**Severity:** Critical  
**Threshold:** 3+ internal hosts via admin ports (SMB/RDP/SSH) in 5 minutes

**What it detects:**
A host connecting to multiple internal hosts using administrative protocols.

**Evidence collected:**
- Internal hosts contacted
- Admin ports used (22, 445, 3389, etc.)
- Connection timeline

**Plain English:**
> After an attacker compromises one computer, they try to spread to others. This is 
> called "lateral movement." They use admin tools like file sharing (SMB), remote 
> desktop (RDP), or SSH to move from machine to machine, looking for valuable data 
> or more powerful access.
>
> If your IT admin is doing maintenance, this is normal. If not, someone might be 
> moving through your network after an initial breach.

**Why it matters:**
- Indicates post-compromise activity
- May mean multiple systems affected
- Requires immediate investigation

---

### 10. Beaconing Detection

**Rule ID:** `BEACONING_DETECTED`  
**Severity:** Warning  
**Threshold:** CV (coefficient of variation) < 0.15 over 10+ connections

**What it detects:**
Regular, automated "phone home" communication patterns.

**Evidence collected:**
- Connection interval regularity (CV)
- Mean interval
- Sample count
- Packet size consistency

**Plain English:**
> When malware infects a computer, it needs to "phone home" to get instructions from 
> its controller. It does this on a schedule - maybe every 30 seconds, or every 5 minutes. 
> Humans don't check things on exact schedules, but malware does.
>
> We measure how regular the timing is. If it's suspiciously regular (like a heartbeat), 
> it might be automated malware communication.

**How we detect it:**
1. Track connection times to external destinations
2. Calculate intervals between connections
3. Compute coefficient of variation (stdev / mean)
4. CV < 0.15 = very regular = suspicious

---

### 11. Broadcast Abuse Detection

**Rule ID:** `BROADCAST_STORM`  
**Severity:** Warning  
**Threshold:** 100 broadcasts per minute from single source

**What it detects:**
Excessive broadcast traffic that could degrade network performance.

**Evidence collected:**
- Broadcast count
- Breakdown by port/protocol
- Source identification

**Plain English:**
> Broadcast packets go to EVERY device on your network. It's like someone using a 
> megaphone in a quiet room. A little is normal, but too much slows everyone down. 
> A malfunctioning device, misconfigured software, or deliberate attack can cause this.

---

### 12. Rogue DHCP Detection

**Rule ID:** `ROGUE_DHCP`  
**Severity:** Critical  
**Threshold:** 2+ DHCP servers detected

**What it detects:**
Unauthorized DHCP server on the network.

**Evidence collected:**
- All detected DHCP servers
- Timestamps

**Plain English:**
> DHCP is how devices get their network settings (IP address, gateway, DNS). You 
> should only have one DHCP server (usually your router). If an attacker sets up 
> their own, they can give devices fake settings that route traffic through them.
>
> This is one of the most dangerous attacks because it affects all new device connections.

---

### 13. New Device Risk Scoring

**Rule ID:** `NEW_DEVICE_RISK`  
**Severity:** Varies (based on score)  
**Observation period:** 5 minutes

**What it detects:**
New devices exhibiting risky behavior patterns.

**Risk factors scored:**
| Factor | Weight | Description |
|--------|--------|-------------|
| Immediate external traffic | 15% | Contacts external IPs right away |
| Contacts many hosts | 20% | Potential scanning behavior |
| Suspicious ports | 25% | Uses known-bad ports |
| Admin port access | 15% | Tries SMB/RDP/SSH |
| High traffic volume | 10% | Unusual bandwidth usage |
| Unknown vendor | 10% | MAC vendor not recognized |

**Plain English:**
> When a new device joins your network, we watch what it does for the first few minutes. 
> Most new devices do predictable things - get an IP, maybe check for updates. But a 
> device that immediately starts scanning or connecting to suspicious services is concerning.

---

## Correlation Engine

### Attack Chain Detection

**Rule ID:** `CORRELATED_ATTACK`  
**Severity:** Varies (based on phases observed)

The correlation engine connects multiple detections into attack chains.

**Attack Phases Tracked:**
| Phase | Detections | Description |
|-------|------------|-------------|
| Reconnaissance | Port scan, ICMP sweep | Finding targets |
| Initial Access | Suspicious port, flood | Gaining foothold |
| Lateral Movement | Lateral movement, ARP spoof | Spreading |
| Persistence | Rogue DHCP | Maintaining access |
| C2 | Beaconing | Command & control |
| Exfiltration | DNS tunneling | Data theft |

**State Machine:**
```
IDLE → RECON_DETECTED → ACCESS_DETECTED → ACTIVE_ATTACK → POST_COMPROMISE
```

**Why correlation matters:**
> Any single detection might be a false positive. But when we see port scanning, 
> then suspicious port traffic, then lateral movement from the same IP - that's 
> a pattern. Multiple correlated signals dramatically reduce false positive likelihood.

---

## Alert Examples

### Example 1: Port Scan

```json
{
  "rule_id": "PORT_SCAN_DETECTION",
  "severity": "warning",
  "title": "Port Scan Detected",
  "source_ip": "192.168.1.50",
  "description": "Host 192.168.1.50 has probed 47 different ports",
  "explanation": "We detected that 192.168.1.50 is connecting to many different ports on your network (47 ports in 60 seconds). This pattern is typical of port scanning...",
  "confidence": 0.85,
  "evidence": {
    "evidence_items": [
      {
        "type": "unique_targets",
        "key": "destination_ports",
        "value": 47,
        "threshold": 10
      }
    ],
    "confidence": {
      "base_score": 0.7,
      "adjustments": [{"reason": "Threshold exceeded by 4.7x", "value": 0.15}],
      "final_score": 0.85
    }
  },
  "recommended_action": "Verify if this IP belongs to a known security scanner; if not, investigate the source device."
}
```

### Example 2: Correlated Attack

```json
{
  "rule_id": "CORRELATED_ATTACK",
  "severity": "critical",
  "title": "Correlated Attack Pattern: 4 Indicators",
  "source_ip": "192.168.1.50",
  "description": "Attack chain from 192.168.1.50 showing reconnaissance, initial access, lateral movement",
  "explanation": "We've detected multiple related security events from 192.168.1.50 that together suggest a coordinated attack rather than isolated incidents...",
  "confidence": 0.92,
  "evidence": {
    "evidence_items": [
      {
        "type": "correlation",
        "key": "related_detections",
        "value": 4
      },
      {
        "type": "behavioral",
        "key": "attack_phases",
        "value": ["reconnaissance", "initial_access", "lateral_movement"]
      },
      {
        "type": "time_pattern",
        "key": "attack_timeline",
        "value": [
          {"time": "10:05:23", "detection": "PORT_SCAN_DETECTION"},
          {"time": "10:08:45", "detection": "SUSPICIOUS_PORT"},
          {"time": "10:12:01", "detection": "LATERAL_MOVEMENT"},
          {"time": "10:15:33", "detection": "BEACONING_DETECTED"}
        ]
      }
    ],
    "false_positive": {
      "likelihood": "low",
      "score": 0.15
    }
  }
}
```

---

## Tuning Guide

### Adjusting Thresholds

All thresholds are configurable in `app/core/config.py`:

```python
# Detection settings
PORT_SCAN_THRESHOLD = 10        # Unique ports before alerting
FLOOD_THRESHOLD = 1000          # Packets per 10 seconds
DETECTION_WINDOW_SECONDS = 60   # Sliding window for most rules
```

### When to Increase Thresholds

- You have legitimate scanning tools (increase port scan threshold)
- High-bandwidth applications (increase flood threshold)
- Very active network (increase most thresholds)

### When to Decrease Thresholds

- Small, quiet network (lower thresholds catch more)
- High security requirements (more sensitive detection)
- Testing detection capabilities

---

## API Endpoints

### Get Detection Statistics

```http
GET /api/dashboard/detection-stats
```

Returns counts of each detection type and correlation statistics.

### Get Active Attack Chains

```http
GET /api/alerts/attack-chains
```

Returns currently tracked attack chains with full timeline.

### Get ARP Cache

```http
GET /api/packets/arp-cache
```

Returns current ARP table for spoofing analysis.

---

## Glossary

| Term | Meaning |
|------|---------|
| **CV** | Coefficient of Variation - measures how regular a pattern is (lower = more regular) |
| **Beaconing** | Regular "phone home" communication from malware to its controller |
| **Lateral Movement** | Attacker spreading from one compromised system to others |
| **C2** | Command and Control - the server that controls malware |
| **False Positive** | Alert for something that isn't actually malicious |
| **Threshold** | The limit that triggers a detection |
| **Correlation** | Connecting multiple detections into a larger pattern |
| **Evidence** | The data that supports why we think something is suspicious |
