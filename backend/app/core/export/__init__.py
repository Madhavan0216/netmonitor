"""
Data Export Module

Provides export functionality:
- PCAP-lite (simplified packet export)
- JSON export
- CSV export
- Future: SIEM-compatible formats
"""

import gzip
import json
import csv
import io
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ExportMetadata:
    """Metadata for exported data."""
    export_type: str
    created_at: str
    source: str = "netmonitor"
    version: str = "1.0.0"
    record_count: int = 0
    filters_applied: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PCAPLiteExporter:
    """
    Simplified PCAP-like exporter.
    
    Exports packet metadata (not raw bytes) in a structured format.
    Compatible with analysis tools but doesn't require raw packet storage.
    
    Format:
    - JSON Lines (.jsonl.gz)
    - Each line: packet metadata with timestamp, IPs, ports, protocol, size
    """
    
    MAGIC = 0xA1B2C3D4  # PCAP-lite magic number
    VERSION = 1
    
    def __init__(self):
        self._buffer: List[Dict[str, Any]] = []
        self._metadata: Optional[ExportMetadata] = None
    
    def add_packet(self, packet_info: Dict[str, Any]):
        """Add a packet to the export buffer."""
        # Normalize packet info
        record: Dict[str, Any] = {
            "ts": packet_info.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "src": packet_info.get("source_ip", ""),
            "dst": packet_info.get("destination_ip", ""),
            "sport": packet_info.get("source_port"),
            "dport": packet_info.get("destination_port"),
            "proto": packet_info.get("protocol", ""),
            "len": packet_info.get("size", 0),
            "flags": packet_info.get("flags"),
            "info": packet_info.get("info", "")
        }
        self._buffer.append(record)
    
    def add_packets(self, packets: List[Dict[str, Any]]):
        """Add multiple packets."""
        for p in packets:
            self.add_packet(p)
    
    def export_jsonl(self, compress: bool = True) -> bytes:
        """
        Export as JSON Lines format.
        
        Args:
            compress: Whether to gzip compress the output
            
        Returns:
            Bytes of the export (optionally compressed)
        """
        self._metadata = ExportMetadata(
            export_type="pcap-lite-jsonl",
            created_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(self._buffer)
        )
        
        # Build output
        lines: List[str] = [json.dumps({"_meta": self._metadata.to_dict()})]
        for record in self._buffer:
            lines.append(json.dumps(record))
        
        content = "\n".join(lines).encode("utf-8")
        
        if compress:
            return gzip.compress(content)
        return content
    
    def export_to_file(self, filepath: Union[str, Path], compress: bool = True) -> int:
        """
        Export to file.
        
        Args:
            filepath: Output file path
            compress: Whether to compress
            
        Returns:
            Number of bytes written
        """
        data = self.export_jsonl(compress=compress)
        
        filepath = Path(filepath)
        if compress and not filepath.suffix == ".gz":
            filepath = filepath.with_suffix(filepath.suffix + ".gz")
        
        filepath.write_bytes(data)
        logger.info("PCAP-lite export completed", path=str(filepath), records=len(self._buffer))
        
        return len(data)
    
    def clear(self):
        """Clear the buffer."""
        self._buffer.clear()
        self._metadata = None
    
    @property
    def count(self) -> int:
        """Get buffered packet count."""
        return len(self._buffer)


class JSONExporter:
    """
    JSON export for various data types.
    
    Exports:
    - Alerts
    - Scan results
    - Topology snapshots
    - Statistics
    """
    
    def __init__(self, pretty: bool = False):
        self._pretty = pretty
    
    def export_alerts(
        self,
        alerts: List[Dict[str, Any]],
        include_metadata: bool = True
    ) -> str:
        """Export alerts to JSON."""
        output: Dict[str, Any] = {
            "alerts": alerts
        }
        
        if include_metadata:
            output["_meta"] = ExportMetadata(
                export_type="alerts",
                created_at=datetime.now(timezone.utc).isoformat(),
                record_count=len(alerts)
            ).to_dict()
        
        return self._to_json(output)
    
    def export_scan(
        self,
        scan_result: Dict[str, Any],
        include_metadata: bool = True
    ) -> str:
        """Export scan results to JSON."""
        output: Dict[str, Any] = {
            "scan": scan_result
        }
        
        if include_metadata:
            output["_meta"] = ExportMetadata(
                export_type="scan",
                created_at=datetime.now(timezone.utc).isoformat(),
                record_count=len(scan_result.get("hosts", []))
            ).to_dict()
        
        return self._to_json(output)
    
    def export_topology(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        include_metadata: bool = True
    ) -> str:
        """Export topology to JSON."""
        output: Dict[str, Any] = {
            "nodes": nodes,
            "edges": edges
        }
        
        if include_metadata:
            output["_meta"] = ExportMetadata(
                export_type="topology",
                created_at=datetime.now(timezone.utc).isoformat(),
                record_count=len(nodes) + len(edges)
            ).to_dict()
        
        return self._to_json(output)
    
    def export_statistics(
        self,
        stats: Dict[str, Any],
        include_metadata: bool = True
    ) -> str:
        """Export statistics to JSON."""
        output: Dict[str, Any] = {
            "statistics": stats
        }
        
        if include_metadata:
            output["_meta"] = ExportMetadata(
                export_type="statistics",
                created_at=datetime.now(timezone.utc).isoformat()
            ).to_dict()
        
        return self._to_json(output)
    
    def _to_json(self, data: Dict[str, Any]) -> str:
        """Convert to JSON string."""
        if self._pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)


class CSVExporter:
    """CSV export for tabular data."""
    
    def export_packets(self, packets: List[Dict[str, Any]]) -> str:
        """Export packets to CSV."""
        if not packets:
            return ""
        
        output = io.StringIO()
        fieldnames = [
            "timestamp", "source_ip", "destination_ip",
            "source_port", "destination_port", "protocol",
            "size", "flags", "info"
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(packets)
        
        return output.getvalue()
    
    def export_alerts(self, alerts: List[Dict[str, Any]]) -> str:
        """Export alerts to CSV."""
        if not alerts:
            return ""
        
        output = io.StringIO()
        fieldnames = [
            "id", "severity", "title", "description",
            "source_ip", "destination_ip", "protocol",
            "port", "rule_id", "created_at"
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(alerts)
        
        return output.getvalue()
    
    def export_hosts(self, hosts: List[Dict[str, Any]]) -> str:
        """Export discovered hosts to CSV."""
        if not hosts:
            return ""
        
        output = io.StringIO()
        fieldnames = [
            "ip_address", "mac_address", "hostname",
            "device_type", "vendor", "ports",
            "first_seen", "last_seen"
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(hosts)
        
        return output.getvalue()


# =============================================================================
# SIEM Compatibility Documentation
# =============================================================================

SIEM_COMPATIBILITY_DOC = """
# SIEM Integration Guide

NetMonitor supports export formats compatible with popular SIEM platforms.

## Supported Formats

### 1. JSON/JSON Lines
- **Use case**: Splunk, Elastic, Azure Sentinel
- **Endpoint**: GET /api/export/alerts?format=json
- **Features**: Full alert details, metadata

### 2. CEF (Common Event Format)
- **Use case**: ArcSight, QRadar
- **Status**: PLANNED (not yet implemented)
- **Format**: CEF:0|NetMonitor|IDS|1.0|{rule_id}|{title}|{severity}|...

### 3. Syslog
- **Use case**: Syslog servers, SIEM collectors
- **Status**: PLANNED (not yet implemented)
- **Transport**: UDP/TCP to configured syslog server

### 4. STIX/TAXII
- **Use case**: Threat intelligence sharing
- **Status**: PLANNED (not yet implemented)
- **Format**: STIX 2.1 bundles via TAXII 2.1

## Webhook Integration

NetMonitor can send alerts to webhooks for SIEM ingestion:

```json
POST /api/settings/webhooks
{
    "url": "https://siem.example.com/api/events",
    "events": ["alert.critical", "alert.warning"],
    "format": "json",
    "headers": {
        "Authorization": "Bearer <token>"
    }
}
```

## Field Mapping

| NetMonitor Field | CEF Field | Elastic Field |
|-----------------|-----------|---------------|
| source_ip | src | source.ip |
| destination_ip | dst | destination.ip |
| source_port | spt | source.port |
| destination_port | dpt | destination.port |
| protocol | proto | network.protocol |
| severity | severity | event.severity |
| rule_id | signatureId | rule.id |

## Sample Alert (JSON)

```json
{
    "id": "alert-12345",
    "severity": "critical",
    "title": "Port Scan Detected",
    "description": "Host 192.168.1.100 scanned 50 ports on 192.168.1.1",
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.1",
    "protocol": "TCP",
    "rule_id": "port_scan",
    "timestamp": "2025-01-24T12:00:00Z",
    "extra_data": {
        "ports_scanned": 50,
        "duration_seconds": 10
    }
}
```

## Future Enhancements

1. **CEF output** - Native CEF formatting for ArcSight/QRadar
2. **Syslog forwarding** - Real-time alert forwarding to syslog
3. **TAXII server** - Built-in TAXII 2.1 server for threat sharing
4. **Kafka output** - Stream alerts to Kafka topics
5. **S3 export** - Batch export to S3-compatible storage
"""


class SIEMExporter:
    """
    SIEM-compatible export functionality.
    
    Currently supports:
    - JSON (for Splunk, Elastic)
    
    Planned:
    - CEF (Common Event Format)
    - Syslog
    - STIX/TAXII
    """
    
    def __init__(self):
        self._json_exporter = JSONExporter()
    
    def export_alert_json(self, alert: Dict[str, Any]) -> str:
        """Export single alert as JSON (Splunk/Elastic compatible)."""
        return json.dumps(alert, default=str)
    
    def export_alerts_ndjson(self, alerts: List[Dict[str, Any]]) -> str:
        """Export alerts as newline-delimited JSON (Elastic bulk format)."""
        lines: List[str] = []
        for alert in alerts:
            lines.append(json.dumps(alert, default=str))
        return "\n".join(lines)
    
    def format_cef(self, alert: Dict[str, Any]) -> str:
        """
        Format alert as CEF (Common Event Format).
        
        Note: Basic implementation. Full CEF support planned.
        """
        severity_map = {
            "info": 1,
            "warning": 5,
            "critical": 10
        }
        
        cef_severity = severity_map.get(alert.get("severity", "info"), 1)
        
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef = (
            f"CEF:0|NetMonitor|IDS|1.0|"
            f"{alert.get('rule_id', 'unknown')}|"
            f"{alert.get('title', 'Alert')}|"
            f"{cef_severity}|"
            f"src={alert.get('source_ip', '')} "
            f"dst={alert.get('destination_ip', '')} "
            f"spt={alert.get('source_port', '')} "
            f"dpt={alert.get('destination_port', '')} "
            f"proto={alert.get('protocol', '')}"
        )
        
        return cef
    
    def get_compatibility_doc(self) -> str:
        """Get SIEM compatibility documentation."""
        return SIEM_COMPATIBILITY_DOC
