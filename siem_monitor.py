#!/usr/bin/env python3
"""
SIEM Log Monitoring & Alert Report Generator
Ingests mock security logs, detects suspicious patterns, and generates reports.
"""

import json
import random
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
import re

# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    event_type: str   # login_failure, login_success, port_scan, file_access, etc.
    username: str
    port: int
    severity: str     # INFO, LOW, MEDIUM, HIGH, CRITICAL
    message: str
    raw: str = ""

@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    category: str        # BRUTE_FORCE, PORT_SCAN, OFF_HOURS_ACCESS, etc.
    severity: str
    source_ip: str
    username: str
    description: str
    evidence: List[str] = field(default_factory=list)
    mitre_tactic: str = ""
    recommended_action: str = ""

# ─────────────────────────────────────────────
# MOCK LOG GENERATOR
# ─────────────────────────────────────────────

USERNAMES = ["alice", "bob", "carol", "dave", "eve", "frank", "admin", "root", "svc_backup", "svc_db"]
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(10)]
ALL_IPS = INTERNAL_IPS + EXTERNAL_IPS
COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 3389, 21, 25]
SENSITIVE_FILES = ["/etc/passwd", "/etc/shadow", "/var/log/auth.log", "C:\\Windows\\SAM", "/root/.ssh/id_rsa"]

def random_ip(external_bias=False):
    if external_bias and random.random() < 0.7:
        return random.choice(EXTERNAL_IPS)
    return random.choice(ALL_IPS)

def generate_mock_logs(n=500) -> List[LogEntry]:
    """Generate a realistic mix of normal and malicious log entries."""
    logs = []
    base_time = datetime.now() - timedelta(hours=24)

    # Inject attack scenarios
    attack_source_brute = "45.152.67.88"
    attack_source_scan  = "178.23.45.99"
    off_hours_user      = "carol"
    off_hours_ip        = "192.168.1.37"

    for i in range(n):
        ts = base_time + timedelta(seconds=random.randint(0, 86400))
        hour = ts.hour

        # 80% normal traffic
        roll = random.random()

        if roll < 0.70:
            # Normal successful logins during business hours
            ts = base_time + timedelta(hours=random.randint(8, 17), minutes=random.randint(0,59))
            user = random.choice(USERNAMES[:-3])
            logs.append(LogEntry(
                timestamp=ts, source_ip=random.choice(INTERNAL_IPS),
                dest_ip="192.168.1.10", event_type="login_success",
                username=user, port=22, severity="INFO",
                message=f"Successful login for user {user}",
            ))

        elif roll < 0.80:
            # Occasional failed login (normal typos)
            user = random.choice(USERNAMES)
            logs.append(LogEntry(
                timestamp=ts, source_ip=random.choice(INTERNAL_IPS),
                dest_ip="192.168.1.10", event_type="login_failure",
                username=user, port=22, severity="LOW",
                message=f"Failed password for user {user}",
            ))

        elif roll < 0.87:
            # ATTACK: Brute force from single external IP
            user = random.choice(["admin", "root", "administrator"])
            ts_bf = base_time + timedelta(
                hours=random.randint(1, 4),
                seconds=random.randint(0, i * 10 % 3600)
            )
            logs.append(LogEntry(
                timestamp=ts_bf, source_ip=attack_source_brute,
                dest_ip="192.168.1.10", event_type="login_failure",
                username=user, port=22, severity="HIGH",
                message=f"Failed password for {user} from {attack_source_brute}",
            ))

        elif roll < 0.92:
            # ATTACK: Port scan
            port = random.choice(list(range(1, 1024)))
            ts_scan = base_time + timedelta(minutes=random.randint(60, 120), seconds=i % 60)
            logs.append(LogEntry(
                timestamp=ts_scan, source_ip=attack_source_scan,
                dest_ip="192.168.1.10", event_type="port_scan",
                username="", port=port, severity="MEDIUM",
                message=f"Connection attempt on port {port} from {attack_source_scan}",
            ))

        elif roll < 0.95:
            # ATTACK: Off-hours access
            ts_off = base_time + timedelta(hours=random.randint(23, 23), minutes=random.randint(0, 59))
            logs.append(LogEntry(
                timestamp=ts_off, source_ip=off_hours_ip,
                dest_ip="192.168.1.20", event_type="login_success",
                username=off_hours_user, port=443, severity="MEDIUM",
                message=f"Successful login for {off_hours_user} at unusual hour",
            ))

        elif roll < 0.97:
            # ATTACK: Sensitive file access
            f = random.choice(SENSITIVE_FILES)
            logs.append(LogEntry(
                timestamp=ts, source_ip=random.choice(EXTERNAL_IPS),
                dest_ip="192.168.1.15", event_type="file_access",
                username=random.choice(["eve", "root"]), port=22, severity="HIGH",
                message=f"Accessed sensitive file: {f}",
            ))

        else:
            # Normal web traffic
            logs.append(LogEntry(
                timestamp=ts, source_ip=random.choice(INTERNAL_IPS),
                dest_ip="192.168.1.1", event_type="http_request",
                username="", port=443, severity="INFO",
                message="HTTPS request to internal server",
            ))

    logs.sort(key=lambda x: x.timestamp)
    return logs

# ─────────────────────────────────────────────
# DETECTION ENGINE
# ─────────────────────────────────────────────

BUSINESS_HOURS = range(8, 18)  # 8 AM – 6 PM
BRUTE_FORCE_THRESHOLD = 5       # failures in window
BRUTE_FORCE_WINDOW_MIN = 10
PORT_SCAN_THRESHOLD = 15        # unique ports in window
PORT_SCAN_WINDOW_MIN = 5

def make_alert_id(category, ip):
    raw = f"{category}-{ip}-{datetime.now().isoformat()}"
    return "ALT-" + hashlib.md5(raw.encode()).hexdigest()[:8].upper()

def detect_brute_force(logs: List[LogEntry]) -> List[Alert]:
    alerts = []
    failures: Dict[str, List[LogEntry]] = defaultdict(list)

    for log in logs:
        if log.event_type == "login_failure":
            failures[log.source_ip].append(log)

    for ip, entries in failures.items():
        entries.sort(key=lambda x: x.timestamp)
        window_start = 0
        for i in range(len(entries)):
            while (entries[i].timestamp - entries[window_start].timestamp).seconds > BRUTE_FORCE_WINDOW_MIN * 60:
                window_start += 1
            count = i - window_start + 1
            if count >= BRUTE_FORCE_THRESHOLD:
                usernames = list({e.username for e in entries[window_start:i+1]})
                alerts.append(Alert(
                    alert_id=make_alert_id("BF", ip),
                    timestamp=entries[i].timestamp,
                    category="BRUTE_FORCE",
                    severity="HIGH" if count > 20 else "MEDIUM",
                    source_ip=ip,
                    username=", ".join(usernames),
                    description=f"{count} failed login attempts from {ip} within {BRUTE_FORCE_WINDOW_MIN} minutes.",
                    evidence=[e.message for e in entries[window_start:i+1]][:5],
                    mitre_tactic="T1110 – Brute Force",
                    recommended_action="Block IP at firewall. Review account lockout policy. Alert account owners.",
                ))
                break  # one alert per IP

    return alerts

def detect_port_scan(logs: List[LogEntry]) -> List[Alert]:
    alerts = []
    scan_attempts: Dict[str, List[LogEntry]] = defaultdict(list)

    for log in logs:
        if log.event_type == "port_scan":
            scan_attempts[log.source_ip].append(log)

    for ip, entries in scan_attempts.items():
        entries.sort(key=lambda x: x.timestamp)
        unique_ports = {e.port for e in entries}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(Alert(
                alert_id=make_alert_id("PS", ip),
                timestamp=entries[0].timestamp,
                category="PORT_SCAN",
                severity="HIGH",
                source_ip=ip,
                username="N/A",
                description=f"Port scan detected from {ip}: {len(unique_ports)} unique ports probed.",
                evidence=[f"Port {p}" for p in sorted(unique_ports)][:10],
                mitre_tactic="T1046 – Network Service Discovery",
                recommended_action="Block source IP. Check IDS/IPS rules. Review exposed services.",
            ))

    return alerts

def detect_off_hours_access(logs: List[LogEntry]) -> List[Alert]:
    alerts = []
    seen: set = set()

    for log in logs:
        if log.event_type == "login_success" and log.timestamp.hour not in BUSINESS_HOURS:
            key = (log.username, log.source_ip, log.timestamp.date())
            if key not in seen:
                seen.add(key)
                alerts.append(Alert(
                    alert_id=make_alert_id("OHA", log.source_ip),
                    timestamp=log.timestamp,
                    category="OFF_HOURS_ACCESS",
                    severity="MEDIUM",
                    source_ip=log.source_ip,
                    username=log.username,
                    description=f"User '{log.username}' logged in at {log.timestamp.strftime('%H:%M')} (outside business hours).",
                    evidence=[log.message],
                    mitre_tactic="T1078 – Valid Accounts",
                    recommended_action="Verify with user if access was authorized. Check for credential compromise.",
                ))

    return alerts

def detect_sensitive_file_access(logs: List[LogEntry]) -> List[Alert]:
    alerts = []
    for log in logs:
        if log.event_type == "file_access":
            alerts.append(Alert(
                alert_id=make_alert_id("SFA", log.source_ip),
                timestamp=log.timestamp,
                category="SENSITIVE_FILE_ACCESS",
                severity="HIGH",
                source_ip=log.source_ip,
                username=log.username,
                description=f"Sensitive file accessed by '{log.username}' from {log.source_ip}.",
                evidence=[log.message],
                mitre_tactic="T1005 – Data from Local System",
                recommended_action="Verify authorization. Check for data exfiltration. Review file permissions.",
            ))
    return alerts

def run_detection(logs: List[LogEntry]) -> List[Alert]:
    all_alerts = []
    all_alerts += detect_brute_force(logs)
    all_alerts += detect_port_scan(logs)
    all_alerts += detect_off_hours_access(logs)
    all_alerts += detect_sensitive_file_access(logs)
    all_alerts.sort(key=lambda a: ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}[a.severity], a.timestamp))
    return all_alerts

# ─────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",  # Yellow
    "LOW":      "\033[94m",  # Blue
    "INFO":     "\033[37m",  # White
}
RESET = "\033[0m"
BOLD  = "\033[1m"

def severity_badge(sev):
    c = SEVERITY_COLORS.get(sev, "")
    return f"{c}{BOLD}[{sev}]{RESET}"

def generate_report(logs: List[LogEntry], alerts: List[Alert]):
    now = datetime.now()
    counts = defaultdict(int)
    for a in alerts:
        counts[a.severity] += 1
    cat_counts = defaultdict(int)
    for a in alerts:
        cat_counts[a.category] += 1

    print(f"\n{'═'*70}")
    print(f"{BOLD}  SIEM SECURITY ALERT REPORT{RESET}")
    print(f"  Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}  |  Log window: Last 24 hours")
    print(f"{'═'*70}")

    print(f"\n{BOLD}📊 EXECUTIVE SUMMARY{RESET}")
    print(f"  Total log entries analysed : {len(logs):,}")
    print(f"  Total alerts triggered     : {len(alerts)}")
    print(f"  ├─ 🔴 HIGH/CRITICAL        : {counts.get('HIGH',0) + counts.get('CRITICAL',0)}")
    print(f"  ├─ 🟡 MEDIUM               : {counts.get('MEDIUM',0)}")
    print(f"  └─ 🔵 LOW/INFO             : {counts.get('LOW',0) + counts.get('INFO',0)}")

    print(f"\n{BOLD}📁 ALERTS BY CATEGORY{RESET}")
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(cnt * 2, 30)
        print(f"  {cat:<30} {bar} {cnt}")

    print(f"\n{'─'*70}")
    print(f"{BOLD}🚨 ALERT DETAILS{RESET}")
    print(f"{'─'*70}")

    for alert in alerts:
        print(f"\n  {severity_badge(alert.severity)}  {BOLD}{alert.category}{RESET}  │  {alert.alert_id}")
        print(f"  Time      : {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Source IP : {alert.source_ip}")
        if alert.username and alert.username != "N/A":
            print(f"  User      : {alert.username}")
        print(f"  MITRE ATT&CK: {alert.mitre_tactic}")
        print(f"  Description : {alert.description}")
        if alert.evidence:
            print(f"  Evidence (sample):")
            for ev in alert.evidence[:3]:
                print(f"    • {ev}")
        print(f"  ⚡ Action  : {alert.recommended_action}")
        print(f"  {'·'*66}")

    print(f"\n{'═'*70}")
    print(f"{BOLD}  END OF REPORT  |  Next scan in 15 minutes{RESET}")
    print(f"{'═'*70}\n")

    # Also export JSON
    report_data = {
        "generated_at": now.isoformat(),
        "log_count": len(logs),
        "alert_count": len(alerts),
        "severity_summary": dict(counts),
        "category_summary": dict(cat_counts),
        "alerts": [
            {
                "id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "category": a.category,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "username": a.username,
                "description": a.description,
                "mitre_tactic": a.mitre_tactic,
                "recommended_action": a.recommended_action,
                "evidence": a.evidence,
            }
            for a in alerts
        ]
    }
    with open("/home/claude/siem/alert_report.json", "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"  📄 JSON report saved → alert_report.json")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n[*] Generating mock security logs...")
    logs = generate_mock_logs(n=500)
    print(f"[*] {len(logs)} log entries generated.")

    print("[*] Running detection engine...")
    alerts = run_detection(logs)
    print(f"[*] {len(alerts)} alerts raised.")

    generate_report(logs, alerts)
