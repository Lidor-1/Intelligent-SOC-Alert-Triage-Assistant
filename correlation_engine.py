"""
Correlation Engine - Find related events and detect attack patterns
Transforms single-event view into chain-of-activity analysis
"""
from datetime import datetime, timedelta

class CorrelationEngine:
    def __init__(self):
        """Initialize correlation engine"""
        self.correlation_window = 15  # minutes to look back
        self.all_logs = []  # Will be populated by main.py
    
    def set_logs(self, logs):
        """Set the current log dataset for correlation"""
        self.all_logs = logs
    
    def find_correlations(self, target_log):
        """
        Find events related to the target log
        
        Returns:
            dict with correlation findings
        """
        if not self.all_logs:
            return {
                'has_correlations': False,
                'related_events': [],
                'attack_chain': None,
                'summary': 'No correlation data available'
            }
        
        correlations = {
            'by_host': [],
            'by_user': [],
            'by_ip': [],
            'temporal': [],
            'attack_chain': None
        }
        
        target_time = self._parse_timestamp(target_log.get('timestamp'))
        if not target_time:
            return {
                'has_correlations': False,
                'related_events': [],
                'attack_chain': None,
                'summary': 'Cannot parse timestamp for correlation'
            }
        
        # Find related events
        for log in self.all_logs:
            if log == target_log:
                continue
            
            log_time = self._parse_timestamp(log.get('timestamp'))
            if not log_time:
                continue
            
            # Check if within time window
            time_diff = abs((target_time - log_time).total_seconds() / 60)
            if time_diff > self.correlation_window:
                continue
            
            # Correlate by host
            if log.get('host') == target_log.get('host') and log.get('host') != 'N/A':
                correlations['by_host'].append({
                    'log': log,
                    'time_diff_minutes': round(time_diff, 1)
                })
            
            # Correlate by user
            if log.get('user') == target_log.get('user') and log.get('user') != 'N/A':
                correlations['by_user'].append({
                    'log': log,
                    'time_diff_minutes': round(time_diff, 1)
                })
            
            # Correlate by IP
            target_ips = self._extract_ips(target_log)
            log_ips = self._extract_ips(log)
            common_ips = set(target_ips) & set(log_ips)
            if common_ips:
                correlations['by_ip'].append({
                    'log': log,
                    'common_ips': list(common_ips),
                    'time_diff_minutes': round(time_diff, 1)
                })
        
        # Detect attack chains
        attack_chain = self._detect_attack_chain(target_log, correlations)
        
        # Generate summary
        summary = self._generate_correlation_summary(correlations, attack_chain)
        
        return {
            'has_correlations': len(correlations['by_host']) > 0 or len(correlations['by_user']) > 0 or len(correlations['by_ip']) > 0,
            'correlations': correlations,
            'attack_chain': attack_chain,
            'summary': summary,
            'related_count': len(correlations['by_host']) + len(correlations['by_user']) + len(correlations['by_ip'])
        }
    
    def _extract_ips(self, log):
        """Extract IP addresses from log entry"""
        ips = []
        
        # From context
        context = log.get('context', {})
        network_ctx = context.get('network_context', {})
        ips.extend(network_ctx.get('external_ips', []))
        ips.extend(network_ctx.get('internal_ips', []))
        
        # From structured data
        structured = context.get('structured_data', {})
        ips.extend(structured.get('ips', []))
        
        return list(set(ips))  # Remove duplicates
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object"""
        if not timestamp_str or timestamp_str == 'N/A':
            return None
        
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%m/%d/%Y %H:%M:%S',
            '%b %d %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except:
                continue
        
        return None
    
    def _detect_attack_chain(self, target_log, correlations):
        """
        Detect if events form a known attack chain
        """
        patterns = []
        
        # Pattern 1: Failed logins followed by success (brute force)
        if 'failed' in str(target_log.get('event', '')).lower() and 'login' in str(target_log.get('event', '')).lower():
            # Check for success after failures
            for related in correlations['by_host'] + correlations['by_user']:
                related_event = str(related['log'].get('event', '')).lower()
                if 'success' in related_event and 'login' in related_event:
                    patterns.append({
                        'name': 'Possible Password Spray / Brute Force',
                        'description': 'Failed authentication attempts followed by successful logon',
                        'severity': 'High',
                        'mitre': 'T1110 - Brute Force',
                        'evidence': f"Failed attempts followed by success within {related['time_diff_minutes']} minutes"
                    })
                    break
        
        # Pattern 2: Logon followed by privilege escalation (privilege abuse)
        if 'logon' in str(target_log.get('event', '')).lower() or 'login' in str(target_log.get('event', '')).lower():
            for related in correlations['by_host']:
                related_event = str(related['log'].get('event', '')).lower()
                if 'privilege' in related_event or '4672' in related_event:
                    patterns.append({
                        'name': 'Logon with Immediate Privilege Escalation',
                        'description': 'User logged in and immediately elevated privileges',
                        'severity': 'Medium',
                        'mitre': 'T1078 + T1068',
                        'evidence': f"Privilege escalation {related['time_diff_minutes']} minutes after logon"
                    })
                    break
        
        # Pattern 3: Multiple hosts accessed by same user (lateral movement)
        if len(correlations['by_user']) > 2:
            unique_hosts = set()
            for related in correlations['by_user']:
                unique_hosts.add(related['log'].get('host'))
            
            if len(unique_hosts) > 2:
                patterns.append({
                    'name': 'Possible Lateral Movement',
                    'description': f'Same user active on {len(unique_hosts)} different hosts in {self.correlation_window} minutes',
                    'severity': 'High',
                    'mitre': 'T1021 - Remote Services',
                    'evidence': f"User activity on hosts: {', '.join(list(unique_hosts)[:3])}"
                })
        
        # Pattern 4: Process creation after authentication (execution)
        if 'process' in str(target_log.get('event', '')).lower() or '4688' in str(target_log.get('event', '')):
            for related in correlations['by_host']:
                related_event = str(related['log'].get('event', '')).lower()
                if 'login' in related_event or 'logon' in related_event:
                    # Check if suspicious process
                    if any(word in str(target_log.get('event', '')).lower() for word in ['powershell', 'cmd', 'wscript', 'rundll']):
                        patterns.append({
                            'name': 'Suspicious Process After Authentication',
                            'description': 'Potentially malicious process created shortly after logon',
                            'severity': 'Medium',
                            'mitre': 'T1059 - Command and Scripting Interpreter',
                            'evidence': f"Process created {related['time_diff_minutes']} minutes after authentication"
                        })
                    break
        
        # Pattern 5: Multiple failed logins from same IP (scanning/enumeration)
        if len(correlations['by_ip']) > 3:
            failed_count = sum(1 for r in correlations['by_ip'] if 'failed' in str(r['log'].get('event', '')).lower())
            if failed_count > 3:
                common_ip = correlations['by_ip'][0].get('common_ips', ['unknown'])[0]
                patterns.append({
                    'name': 'Credential Scanning from Single Source',
                    'description': f'Multiple failed authentication attempts from {common_ip}',
                    'severity': 'High',
                    'mitre': 'T1110.003 - Password Spraying',
                    'evidence': f"{failed_count} failed attempts from same IP in {self.correlation_window} minutes"
                })
        
        if patterns:
            return {
                'detected': True,
                'patterns': patterns,
                'confidence': 'High' if len(patterns) > 1 else 'Medium'
            }
        
        return None
    
    def _generate_correlation_summary(self, correlations, attack_chain):
        """Generate human-readable correlation summary"""
        summaries = []
        
        # Host correlations
        if correlations['by_host']:
            count = len(correlations['by_host'])
            summaries.append(f"📍 {count} related event(s) on same host")
        
        # User correlations
        if correlations['by_user']:
            count = len(correlations['by_user'])
            summaries.append(f"👤 {count} event(s) by same user")
        
        # IP correlations
        if correlations['by_ip']:
            count = len(correlations['by_ip'])
            summaries.append(f"🌐 {count} event(s) from same IP")
        
        # Attack chain
        if attack_chain and attack_chain['detected']:
            pattern_names = [p['name'] for p in attack_chain['patterns']]
            summaries.append(f"⚠️ ATTACK PATTERN: {', '.join(pattern_names)}")
        
        if not summaries:
            return f"No related events found in last {self.correlation_window} minutes"
        
        return " | ".join(summaries)
    
    def get_related_events_summary(self, target_log):
        """
        Get a quick summary of related events for display
        """
        correlation_result = self.find_correlations(target_log)
        
        if not correlation_result['has_correlations']:
            return []
        
        summaries = []
        corr = correlation_result['correlations']
        
        # Most significant correlations
        if corr['by_host']:
            # Get most recent
            most_recent = sorted(corr['by_host'], key=lambda x: x['time_diff_minutes'])[0]
            summaries.append({
                'icon': '📍',
                'text': f"Same host: {most_recent['log'].get('event', 'event')[:50]}... ({most_recent['time_diff_minutes']}m ago)",
                'type': 'host'
            })
        
        if corr['by_user']:
            most_recent = sorted(corr['by_user'], key=lambda x: x['time_diff_minutes'])[0]
            summaries.append({
                'icon': '👤',
                'text': f"Same user: {most_recent['log'].get('event', 'event')[:50]}... ({most_recent['time_diff_minutes']}m ago)",
                'type': 'user'
            })
        
        if corr['by_ip']:
            most_recent = sorted(corr['by_ip'], key=lambda x: x['time_diff_minutes'])[0]
            ip = most_recent['common_ips'][0] if most_recent['common_ips'] else 'unknown'
            summaries.append({
                'icon': '🌐',
                'text': f"Same IP ({ip}): {most_recent['log'].get('event', 'event')[:50]}... ({most_recent['time_diff_minutes']}m ago)",
                'type': 'ip'
            })
        
        # Attack chain warning
        if correlation_result['attack_chain']:
            for pattern in correlation_result['attack_chain']['patterns'][:1]:  # Show first pattern
                summaries.append({
                    'icon': '⚠️',
                    'text': f"ATTACK CHAIN: {pattern['name']}",
                    'type': 'attack_chain',
                    'severity': pattern['severity']
                })
        
        return summaries[:3]  # Limit to top 3
