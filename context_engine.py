"""
Context Engine - Enriches logs with security context
Extracts structured data and adds business/security context
"""
import re
import yaml
from datetime import datetime
from pathlib import Path

class ContextEngine:
    def __init__(self, config_path="config.yaml"):
        """Initialize context engine with configuration"""
        self.config = self._load_config(config_path)
        self.critical_assets = self.config.get('critical_assets', [])
        self.privileged_users = self.config.get('privileged_users', [])
        self.business_hours = self.config.get('business_hours', {'start': 8, 'end': 18})
        self.internal_networks = self.config.get('internal_networks', ['10.', '172.16.', '192.168.'])
        
    def _load_config(self, config_path):
        """Load configuration file"""
        try:
            config_file = Path(config_path)
            if config_file.exists():
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f) or {}
            else:
                # Return sensible defaults
                return {
                    'critical_assets': ['dc', 'domain', 'sql', 'backup', 'prod'],
                    'privileged_users': ['admin', 'root', 'administrator', 'svc_'],
                    'business_hours': {'start': 8, 'end': 18},
                    'internal_networks': ['10.', '172.16.', '192.168.']
                }
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def enrich_log(self, log_entry):
        """
        Enrich a log entry with context signals
        Returns the log with added 'context' field
        """
        context = {
            'structured_data': self._extract_structured_data(log_entry),
            'asset_context': self._get_asset_context(log_entry),
            'user_context': self._get_user_context(log_entry),
            'time_context': self._get_time_context(log_entry),
            'network_context': self._get_network_context(log_entry),
            'event_category': self._categorize_event(log_entry)
        }
        
        # Add context to log entry
        log_entry['context'] = context
        
        return log_entry
    
    def _extract_structured_data(self, log_entry):
        """Extract structured data from log entry"""
        event_text = str(log_entry.get('event', '')) + ' ' + str(log_entry.get('raw', ''))
        
        structured = {
            'ips': self._extract_ips(event_text),
            'usernames': self._extract_usernames(event_text),
            'event_ids': self._extract_event_ids(event_text),
            'ports': self._extract_ports(event_text),
            'processes': self._extract_processes(event_text),
            'file_paths': self._extract_file_paths(event_text)
        }
        
        return structured
    
    def _extract_ips(self, text):
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        return list(set(ips))  # Remove duplicates
    
    def _extract_usernames(self, text):
        """Extract potential usernames"""
        # Common patterns: user=, account=, username:, etc.
        username_patterns = [
            r'(?:user|account|username|logon)[:=]\s*([a-zA-Z0-9_\-\.]+)',
            r'(?:by|for)\s+user\s+([a-zA-Z0-9_\-\.]+)'
        ]
        
        usernames = []
        for pattern in username_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            usernames.extend(matches)
        
        return list(set(usernames))
    
    def _extract_event_ids(self, text):
        """Extract Windows Event IDs or similar identifiers"""
        # Common patterns: EventID, Event ID, ID:, etc.
        patterns = [
            r'(?:event\s*id|eventid)[:=\s]+(\d+)',
            r'\bID[:=]\s*(\d+)',
            r'\b(\d{4})\b'  # 4-digit numbers (Windows Event IDs)
        ]
        
        event_ids = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            event_ids.extend(matches)
        
        return list(set(event_ids))[:3]  # Limit to top 3
    
    def _extract_ports(self, text):
        """Extract port numbers"""
        port_pattern = r'(?:port|:)(\d{1,5})\b'
        ports = re.findall(port_pattern, text, re.IGNORECASE)
        # Filter valid ports (1-65535)
        valid_ports = [p for p in ports if 1 <= int(p) <= 65535]
        return list(set(valid_ports))
    
    def _extract_processes(self, text):
        """Extract process names"""
        # Common patterns: .exe, process=, etc.
        process_patterns = [
            r'([a-zA-Z0-9_\-]+\.exe)',
            r'process[:=]\s*([a-zA-Z0-9_\-\.]+)',
            r'executable[:=]\s*([a-zA-Z0-9_\-\.]+)'
        ]
        
        processes = []
        for pattern in process_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            processes.extend(matches)
        
        return list(set(processes))
    
    def _extract_file_paths(self, text):
        """Extract file paths (Windows and Unix)"""
        path_patterns = [
            r'[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+',  # Windows paths
            r'/(?:[^\s/]+/)*[^\s/]+'  # Unix paths
        ]
        
        paths = []
        for pattern in path_patterns:
            matches = re.findall(pattern, text)
            paths.extend(matches)
        
        return list(set(paths))[:5]  # Limit to top 5
    
    def _get_asset_context(self, log_entry):
        """Determine if asset is critical"""
        host = str(log_entry.get('host', '')).lower()
        
        is_critical = any(asset_keyword in host for asset_keyword in self.critical_assets)
        
        asset_type = "Unknown"
        if any(x in host for x in ['dc', 'domain']):
            asset_type = "Domain Controller"
        elif any(x in host for x in ['sql', 'db', 'database']):
            asset_type = "Database Server"
        elif any(x in host for x in ['web', 'www', 'http']):
            asset_type = "Web Server"
        elif any(x in host for x in ['backup', 'bkup']):
            asset_type = "Backup Server"
        elif any(x in host for x in ['prod', 'production']):
            asset_type = "Production Server"
        elif any(x in host for x in ['dev', 'test']):
            asset_type = "Development/Test"
        elif any(x in host for x in ['ws', 'workstation', 'pc', 'laptop']):
            asset_type = "Workstation"
        
        return {
            'is_critical': is_critical,
            'asset_type': asset_type,
            'risk_multiplier': 2.0 if is_critical else 1.0
        }
    
    def _get_user_context(self, log_entry):
        """Determine if user is privileged"""
        user = str(log_entry.get('user', '')).lower()
        
        # Check structured data for extracted usernames
        structured = log_entry.get('context', {}).get('structured_data', {})
        extracted_users = structured.get('usernames', []) if structured else []
        all_users = [user] + [u.lower() for u in extracted_users]
        
        is_privileged = any(
            any(priv in u for priv in self.privileged_users)
            for u in all_users
        )
        
        account_type = "Standard"
        if any('admin' in u or 'root' in u for u in all_users):
            account_type = "Administrator"
        elif any('svc_' in u or 'service' in u for u in all_users):
            account_type = "Service Account"
        elif any('system' in u for u in all_users):
            account_type = "System Account"
        
        return {
            'is_privileged': is_privileged,
            'account_type': account_type,
            'risk_multiplier': 1.5 if is_privileged else 1.0
        }
    
    def _get_time_context(self, log_entry):
        """Analyze time-based context"""
        timestamp_str = log_entry.get('timestamp', '')
        
        try:
            # Try multiple timestamp formats
            timestamp = None
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%b %d %H:%M:%S',  # Syslog format
                '%m/%d/%Y %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    timestamp = datetime.strptime(timestamp_str, fmt)
                    break
                except:
                    continue
            
            if not timestamp:
                # If parsing fails, use current time (for demo purposes)
                timestamp = datetime.now()
            
            hour = timestamp.hour
            is_business_hours = self.business_hours['start'] <= hour < self.business_hours['end']
            is_weekend = timestamp.weekday() >= 5
            
            time_category = "Business Hours"
            if not is_business_hours:
                time_category = "After Hours"
            if is_weekend:
                time_category = "Weekend"
            
            return {
                'is_business_hours': is_business_hours,
                'is_weekend': is_weekend,
                'hour': hour,
                'time_category': time_category,
                'risk_multiplier': 1.0 if is_business_hours else 1.3
            }
            
        except Exception as e:
            return {
                'is_business_hours': True,
                'is_weekend': False,
                'hour': 12,
                'time_category': "Unknown",
                'risk_multiplier': 1.0
            }
    
    def _get_network_context(self, log_entry):
        """Analyze network-related context"""
        structured = log_entry.get('context', {}).get('structured_data', {})
        ips = structured.get('ips', []) if structured else []
        
        if not ips:
            # Try to extract from event/raw
            event_text = str(log_entry.get('event', '')) + ' ' + str(log_entry.get('raw', ''))
            ips = self._extract_ips(event_text)
        
        external_ips = []
        internal_ips = []
        
        for ip in ips:
            if any(ip.startswith(net) for net in self.internal_networks):
                internal_ips.append(ip)
            else:
                external_ips.append(ip)
        
        has_external = len(external_ips) > 0
        
        return {
            'has_external_ip': has_external,
            'external_ips': external_ips,
            'internal_ips': internal_ips,
            'total_ips': len(ips),
            'risk_multiplier': 1.5 if has_external else 1.0
        }
    
    def _categorize_event(self, log_entry):
        """Categorize the event type"""
        event_text = (str(log_entry.get('event', '')) + ' ' + 
                     str(log_entry.get('raw', ''))).lower()
        
        categories = {
            'authentication': ['login', 'logon', 'logoff', 'logout', 'auth', 'authentication', 
                             'password', '4624', '4625', '4634', '4648'],
            'privilege_escalation': ['privilege', 'elevation', 'sudo', 'runas', 'admin', 
                                    '4672', '4673', '4674'],
            'process_execution': ['process', 'execution', 'started', 'launch', '.exe', 
                                 '4688', '4689'],
            'network_connection': ['connection', 'network', 'socket', 'port', 'firewall',
                                  '5156', '5157', '5158'],
            'file_access': ['file', 'access', 'read', 'write', 'modify', 'delete',
                          '4656', '4663', '4660'],
            'account_management': ['account', 'user created', 'user deleted', 'group',
                                  '4720', '4726', '4728', '4732'],
            'system_event': ['service', 'system', 'boot', 'shutdown', 'restart',
                           '6005', '6006', '6008'],
            'security_alert': ['alert', 'suspicious', 'malware', 'threat', 'attack',
                             'breach', 'intrusion']
        }
        
        detected_categories = []
        for category, keywords in categories.items():
            if any(keyword in event_text for keyword in keywords):
                detected_categories.append(category)
        
        primary_category = detected_categories[0] if detected_categories else 'general'
        
        return {
            'primary': primary_category,
            'all_categories': detected_categories,
            'is_security_relevant': primary_category in ['authentication', 'privilege_escalation', 
                                                         'security_alert', 'network_connection']
        }
    
    def get_context_summary(self, log_entry):
        """
        Generate a human-readable context summary
        Returns list of context signals for display
        """
        if 'context' not in log_entry:
            log_entry = self.enrich_log(log_entry)
        
        context = log_entry['context']
        signals = []
        
        # Asset signals
        if context['asset_context']['is_critical']:
            signals.append({
                'type': 'critical',
                'icon': '🔴',
                'text': f"Critical Asset: {context['asset_context']['asset_type']}"
            })
        
        # User signals
        if context['user_context']['is_privileged']:
            signals.append({
                'type': 'warning',
                'icon': '👑',
                'text': f"Privileged Account: {context['user_context']['account_type']}"
            })
        
        # Time signals
        if not context['time_context']['is_business_hours']:
            signals.append({
                'type': 'warning',
                'icon': '🌙',
                'text': f"After Hours Activity ({context['time_context']['hour']}:00)"
            })
        
        if context['time_context']['is_weekend']:
            signals.append({
                'type': 'info',
                'icon': '📅',
                'text': "Weekend Activity"
            })
        
        # Network signals
        if context['network_context']['has_external_ip']:
            signals.append({
                'type': 'warning',
                'icon': '🌐',
                'text': f"External IP Detected: {', '.join(context['network_context']['external_ips'][:2])}"
            })
        
        # Event category
        if context['event_category']['is_security_relevant']:
            signals.append({
                'type': 'info',
                'icon': '🔍',
                'text': f"Category: {context['event_category']['primary'].replace('_', ' ').title()}"
            })
        
        # Structured data highlights
        structured = context['structured_data']
        if structured['event_ids']:
            signals.append({
                'type': 'info',
                'icon': '🆔',
                'text': f"Event ID: {', '.join(structured['event_ids'][:2])}"
            })
        
        if structured['processes']:
            signals.append({
                'type': 'info',
                'icon': '⚙️',
                'text': f"Process: {structured['processes'][0]}"
            })
        
        return signals
