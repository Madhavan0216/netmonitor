"""
Database initialization script.
Creates tables and default data.
"""

import asyncio
import bcrypt
from sqlalchemy import select

from app.database.session import engine, Base, async_session_maker
from app.database.models import User, DetectionRule, AlertSeverity


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt directly."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# Default detection rules
DEFAULT_RULES = [
    {
        "rule_id": "PORT_SCAN_DETECTION",
        "name": "Port Scan Detection",
        "description": "Detects when a single source IP attempts to connect to multiple ports in a short time window",
        "category": "reconnaissance",
        "severity": AlertSeverity.WARNING,
        "conditions": {
            "type": "port_scan",
            "threshold": 10,
            "window_seconds": 60,
            "protocols": ["tcp", "udp"]
        },
        "is_builtin": True
    },
    {
        "rule_id": "ARP_SPOOF_DETECTION",
        "name": "ARP Spoofing Detection",
        "description": "Detects potential ARP spoofing attacks by monitoring for duplicate IP-MAC mappings",
        "category": "mitm",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "type": "arp_spoof",
            "duplicate_threshold": 2,
            "window_seconds": 300
        },
        "is_builtin": True
    },
    {
        "rule_id": "DNS_TUNNEL_DETECTION",
        "name": "DNS Tunneling Detection",
        "description": "Detects potential DNS tunneling by monitoring for unusually long DNS queries",
        "category": "exfiltration",
        "severity": AlertSeverity.WARNING,
        "conditions": {
            "type": "dns_tunnel",
            "query_length_threshold": 50,
            "frequency_threshold": 100,
            "window_seconds": 60
        },
        "is_builtin": True
    },
    {
        "rule_id": "PACKET_FLOOD_DETECTION",
        "name": "Packet Flood Detection",
        "description": "Detects potential DoS attacks by monitoring for high packet rates from single sources",
        "category": "dos",
        "severity": AlertSeverity.CRITICAL,
        "conditions": {
            "type": "packet_flood",
            "threshold": 1000,
            "window_seconds": 10
        },
        "is_builtin": True
    },
    {
        "rule_id": "FAILED_CONN_DETECTION",
        "name": "Failed Connection Detection",
        "description": "Detects repeated failed connection attempts which may indicate scanning or brute force",
        "category": "reconnaissance",
        "severity": AlertSeverity.INFO,
        "conditions": {
            "type": "failed_connections",
            "threshold": 20,
            "window_seconds": 60
        },
        "is_builtin": True
    },
    {
        "rule_id": "ICMP_SWEEP_DETECTION",
        "name": "ICMP Sweep Detection",
        "description": "Detects ICMP-based host discovery sweeps",
        "category": "reconnaissance",
        "severity": AlertSeverity.INFO,
        "conditions": {
            "type": "icmp_sweep",
            "threshold": 20,
            "window_seconds": 30
        },
        "is_builtin": True
    },
    {
        "rule_id": "SUSPICIOUS_OUTBOUND",
        "name": "Suspicious Outbound Traffic",
        "description": "Detects connections to known suspicious ports or unusual outbound traffic patterns",
        "category": "exfiltration",
        "severity": AlertSeverity.WARNING,
        "conditions": {
            "type": "suspicious_ports",
            "ports": [4444, 5555, 6666, 31337, 12345, 65535],
            "direction": "outbound"
        },
        "is_builtin": True
    }
]


async def init_database():
    """Initialize database with tables and default data."""
    print("Creating database tables...")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    print("Tables created successfully.")
    
    async with async_session_maker() as session:
        # Check if admin user exists
        result = await session.execute(
            select(User).where(User.username == "admin")
        )
        admin = result.scalar_one_or_none()
        
        if not admin:
            print("Creating default admin user...")
            admin = User(
                username="admin",
                email="admin@localhost",
                hashed_password=get_password_hash("changeme123"),
                is_active=True,
                is_admin=True
            )
            session.add(admin)
            print("Default admin user created (username: admin, password: changeme123)")
            print("⚠️  Please change the default password immediately!")
        
        # Create default detection rules
        for rule_data in DEFAULT_RULES:
            result = await session.execute(
                select(DetectionRule).where(DetectionRule.rule_id == rule_data["rule_id"])
            )
            existing_rule = result.scalar_one_or_none()
            
            if not existing_rule:
                rule = DetectionRule(**rule_data)
                session.add(rule)
                print(f"Created detection rule: {rule_data['name']}")
        
        await session.commit()
    
    print("Database initialization complete!")


if __name__ == "__main__":
    asyncio.run(init_database())
