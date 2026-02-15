import json
import csv
import re
from io import StringIO
from datetime import datetime

def load_logs(file_path):
    """Load logs from a file path (for initial sample logs)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith('.json'):
                # Try standard JSON array first
                try:
                    data = json.load(f)
                    return normalize_logs(data)
                except json.JSONDecodeError as e:
                    # If that fails, try line-delimited JSON
                    f.seek(0)  # Reset file pointer
                    content = f.read()
                    if "Extra data" in str(e) or e.pos < len(content) - 10:
                        return parse_jsonl(content)
                    raise
            elif file_path.endswith('.csv'):
                reader = csv.DictReader(f)
                return normalize_logs(list(reader))
            else:
                # Try to parse as plain text logs
                content = f.read()
                return parse_text_logs(content)
    except Exception as e:
        print(f"Error loading logs: {e}")
        return []

def parse_uploaded_file(content, filename):
    """Parse uploaded file content based on file type"""
    try:
        # Decode content
        text_content = content.decode('utf-8')
        
        if filename.endswith('.json'):
            # Try standard JSON array first
            try:
                data = json.loads(text_content)
                return normalize_logs(data)
            except json.JSONDecodeError as e:
                # If that fails, try line-delimited JSON (JSONL/NDJSON)
                if "Extra data" in str(e) or e.pos < len(text_content) - 10:
                    return parse_jsonl(text_content)
                raise
        
        elif filename.endswith('.jsonl') or filename.endswith('.ndjson'):
            # Line-delimited JSON format
            return parse_jsonl(text_content)
        
        elif filename.endswith('.csv'):
            reader = csv.DictReader(StringIO(text_content))
            return normalize_logs(list(reader))
        
        elif filename.endswith('.log') or filename.endswith('.txt'):
            return parse_text_logs(text_content)
        
        else:
            # Try to auto-detect format
            # First try JSON
            try:
                data = json.loads(text_content)
                return normalize_logs(data)
            except:
                pass
            
            # Then try CSV
            try:
                reader = csv.DictReader(StringIO(text_content))
                logs = list(reader)
                if logs:
                    return normalize_logs(logs)
            except:
                pass
            
            # Fall back to text parsing
            return parse_text_logs(text_content)
    
    except Exception as e:
        raise Exception(f"Failed to parse log file: {str(e)}")

def parse_text_logs(content):
    """Parse plain text logs (syslog, Windows Event Log format, etc.)"""
    logs = []
    lines = content.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
        
        log_entry = parse_log_line(line)
        if log_entry:
            logs.append(log_entry)
    
    return logs

def parse_jsonl(content):
    """Parse line-delimited JSON (JSONL/NDJSON) format"""
    logs = []
    lines = content.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
        
        try:
            # Try to parse each line as JSON
            log_entry = json.loads(line.strip())
            logs.append(log_entry)
        except json.JSONDecodeError:
            # If it's not valid JSON, skip it
            continue
    
    return normalize_logs(logs)

def parse_log_line(line):
    """Parse a single log line - supports multiple formats"""
    
    # Syslog format: "Jan 1 12:00:00 hostname service[pid]: message"
    syslog_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)'
    match = re.match(syslog_pattern, line)
    if match:
        timestamp, host, service, message = match.groups()
        return {
            "timestamp": timestamp,
            "host": host,
            "user": "N/A",
            "event": f"{service}: {message[:50]}...",
            "severity": detect_severity(message),
            "status": "Pending",
            "raw": line
        }
    
    # Windows Event Log format: "timestamp,hostname,event_id,level,message"
    if ',' in line:
        parts = line.split(',', 4)
        if len(parts) >= 4:
            return {
                "timestamp": parts[0].strip(),
                "host": parts[1].strip() if len(parts) > 1 else "N/A",
                "user": "N/A",
                "event": parts[-1].strip()[:50] + "...",
                "severity": detect_severity(parts[-1]),
                "status": "Pending",
                "raw": line
            }
    
    # Generic format - just extract what we can
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": "Unknown",
        "user": "N/A",
        "event": line[:50] + "..." if len(line) > 50 else line,
        "severity": detect_severity(line),
        "status": "Pending",
        "raw": line
    }

def normalize_logs(data):
    """Normalize log data to consistent format"""
    if not data:
        return []
    
    # If data is a list of dicts, normalize each
    if isinstance(data, list):
        normalized = []
        for item in data:
            if isinstance(item, dict):
                normalized.append({
                    "timestamp": item.get("timestamp", item.get("time", item.get("date", "N/A"))),
                    "host": item.get("host", item.get("hostname", item.get("computer", "N/A"))),
                    "user": item.get("user", item.get("username", item.get("account", "N/A"))),
                    "event": item.get("event", item.get("message", item.get("description", "N/A"))),
                    "severity": item.get("severity", item.get("level", detect_severity(str(item)))),
                    "status": item.get("status", "Pending"),
                    "raw": str(item)
                })
        return normalized
    
    # If data is a single dict with a list inside
    elif isinstance(data, dict):
        # Try to find the list of logs
        for key in ["logs", "events", "entries", "data"]:
            if key in data and isinstance(data[key], list):
                return normalize_logs(data[key])
        
        # If it's a single log entry
        return [{
            "timestamp": data.get("timestamp", data.get("time", "N/A")),
            "host": data.get("host", data.get("hostname", "N/A")),
            "user": data.get("user", data.get("username", "N/A")),
            "event": data.get("event", data.get("message", "N/A")),
            "severity": data.get("severity", "Unknown"),
            "status": data.get("status", "Pending"),
            "raw": str(data)
        }]
    
    return []

def detect_severity(text):
    """Detect severity based on keywords in the text"""
    text_lower = str(text).lower()
    
    high_keywords = ["critical", "error", "failed", "failure", "unauthorized", "denied", "attack", "breach", "malware", "suspicious"]
    medium_keywords = ["warning", "warn", "alert", "unusual", "retry", "timeout"]
    
    for keyword in high_keywords:
        if keyword in text_lower:
            return "High"
    
    for keyword in medium_keywords:
        if keyword in text_lower:
            return "Medium"
    
    return "Low"
