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
                content = f.read()
                
                # Check if it's JSONL format (each line is a JSON object)
                # JSONL files start with { and have newlines between objects
                if content.strip().startswith('{') and '\n{' in content:
                    return parse_jsonl(content)
                
                # Otherwise try standard JSON array
                try:
                    data = json.loads(content)
                    return normalize_logs(data)
                except json.JSONDecodeError as e:
                    # Last resort: try JSONL
                    return parse_jsonl(content)
                    
            elif file_path.endswith('.csv'):
                reader = csv.DictReader(f)
                return normalize_logs(list(reader))
            else:
                # Try to parse as plain text logs
                content = f.read()
                return parse_text_logs(content)
    except Exception as e:
        print(f"Error loading logs: {e}")
        import traceback
        traceback.print_exc()
        return []

def parse_uploaded_file(content, filename):
    """Parse uploaded file content based on file type"""
    try:
        # Decode content
        text_content = content.decode('utf-8')
        
        if filename.endswith('.json'):
            # Check if it's JSONL format first
            if text_content.strip().startswith('{') and '\n{' in text_content:
                return parse_jsonl(text_content)
            
            # Try standard JSON array
            try:
                data = json.loads(text_content)
                return normalize_logs(data)
            except json.JSONDecodeError as e:
                # Last resort: try JSONL
                return parse_jsonl(text_content)
        
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
            # First check for JSONL
            if text_content.strip().startswith('{') and '\n{' in text_content:
                return parse_jsonl(text_content)
            
            # Then try JSON array
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
                # Extract fields with multiple possible names
                timestamp = (item.get("timestamp") or 
                           item.get("EventTime") or 
                           item.get("time") or 
                           item.get("date") or 
                           "N/A")
                
                host = (item.get("host") or 
                       item.get("Hostname") or 
                       item.get("hostname") or 
                       item.get("computer") or 
                       item.get("Computer") or 
                       "N/A")
                
                user = (item.get("user") or 
                       item.get("SubjectUserName") or 
                       item.get("TargetUserName") or 
                       item.get("username") or 
                       item.get("account") or 
                       "N/A")
                
                event = (item.get("event") or 
                        item.get("Message") or 
                        item.get("message") or 
                        item.get("description") or 
                        "N/A")
                
                # Get raw severity and normalize it
                raw_severity = (item.get("severity") or 
                              item.get("Severity") or 
                              item.get("level") or 
                              "Unknown")
                
                # Normalize severity - map Windows Event Log levels to our standard levels
                severity = normalize_severity(raw_severity, event, item)
                
                normalized.append({
                    "timestamp": timestamp,
                    "host": host,
                    "user": user,
                    "event": event,
                    "severity": severity,
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
        timestamp = (data.get("timestamp") or 
                   data.get("EventTime") or 
                   data.get("time") or 
                   "N/A")
        
        host = (data.get("host") or 
               data.get("Hostname") or 
               data.get("hostname") or 
               "N/A")
        
        user = (data.get("user") or 
               data.get("SubjectUserName") or 
               data.get("TargetUserName") or 
               data.get("username") or 
               "N/A")
        
        event = (data.get("event") or 
                data.get("Message") or 
                data.get("message") or 
                "N/A")
        
        raw_severity = (data.get("severity") or 
                      data.get("Severity") or 
                      data.get("level") or 
                      "Unknown")
        
        severity = normalize_severity(raw_severity, event, data)
        
        return [{
            "timestamp": timestamp,
            "host": host,
            "user": user,
            "event": event,
            "severity": severity,
            "status": data.get("status", "Pending"),
            "raw": str(data)
        }]
    
    return []

def normalize_severity(raw_severity, event_text, full_item):
    """
    Normalize severity from various formats to our standard: Low, Medium, High, Critical
    Maps Windows Event Log levels (INFO, WARNING, ERROR, etc.) and detects based on content
    """
    severity_str = str(raw_severity).upper()
    
    # Map Windows Event Log severity levels
    if severity_str in ['CRITICAL', 'FATAL', 'EMERGENCY']:
        return 'Critical'
    elif severity_str in ['ERROR', 'FAIL', 'FAILURE']:
        return 'High'
    elif severity_str in ['WARNING', 'WARN']:
        # Check if it's security-related - if so, escalate to High
        event_id = full_item.get('EventID')
        if event_id and int(event_id) >= 4000 and int(event_id) < 5000:
            return 'High'  # Windows Security events
        return 'Medium'
    elif severity_str in ['INFO', 'INFORMATION', 'INFORMATIONAL', 'NOTICE']:
        # INFO events can still be high severity based on content
        # Check event ID and content for suspicious activity
        event_id = full_item.get('EventID')
        
        # Critical Windows Event IDs (account/group changes)
        critical_event_ids = [
            4720,  # User account created
            4722,  # User account enabled
            4724,  # Password reset attempt
            4728,  # Member added to security group
            4732,  # Member added to local group
            4756,  # Member added to universal group
        ]
        
        # High severity Event IDs (authentication, privileges, sensitive operations)
        high_event_ids = [
            4625,  # Failed logon
            4648,  # Logon with explicit credentials
            4672,  # Special privileges assigned
            4673,  # Privileged service called
            4674,  # Operation attempted on privileged object
            4740,  # Account lockout
            4768,  # Kerberos TGT requested
            4769,  # Kerberos service ticket
            4776,  # Credential validation
            4670,  # Permissions changed
            4662,  # Operation performed on object
            4702,  # Scheduled task created
        ]
        
        # Medium severity Event IDs (process, network)
        medium_event_ids = [
            4624,  # Successful logon
            4634,  # Logoff
            4688,  # Process created
            5140,  # Network share accessed
            5156,  # Network connection
            5145,  # Network share checked
        ]
        
        if event_id in critical_event_ids:
            return 'High'  # Escalate to High for important events
        elif event_id in high_event_ids:
            return 'High'  # Also High for authentication/privilege events
        elif event_id in medium_event_ids:
            return 'Medium'
        
        # Check event content for suspicious keywords
        return detect_severity(str(event_text))
    elif severity_str in ['DEBUG', 'TRACE', 'VERBOSE']:
        return 'Low'
    elif severity_str in ['HIGH']:
        return 'High'
    elif severity_str in ['MEDIUM']:
        return 'Medium'
    elif severity_str in ['LOW']:
        return 'Low'
    else:
        # Unknown severity - detect from content
        return detect_severity(str(event_text))


def detect_severity(text):
    """Detect severity based on keywords in the text"""
    text_lower = str(text).lower()
    
    critical_keywords = ["critical", "breach", "compromised", "ransomware", "malware", "exploit", "backdoor"]
    high_keywords = ["error", "failed", "failure", "unauthorized", "denied", "attack", "suspicious", "violation"]
    medium_keywords = ["warning", "warn", "alert", "unusual", "retry", "timeout", "anomaly"]
    
    for keyword in critical_keywords:
        if keyword in text_lower:
            return "Critical"
    
    for keyword in high_keywords:
        if keyword in text_lower:
            return "High"
    
    for keyword in medium_keywords:
        if keyword in text_lower:
            return "Medium"
    
    return "Low"
