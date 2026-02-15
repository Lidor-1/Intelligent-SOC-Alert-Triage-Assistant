"""
Anomaly Detector - Detect rare events and baseline deviations
Real anomaly detection, not just keyword matching
"""
from collections import defaultdict
from datetime import datetime

class AnomalyDetector:
    def __init__(self, memory_store=None):
        """Initialize anomaly detector"""
        self.memory_store = memory_store
        self.all_logs = []
        self.baselines = {}
    
    def set_logs(self, logs):
        """Set current log dataset for baseline analysis"""
        self.all_logs = logs
        self._calculate_baselines()
    
    def _calculate_baselines(self):
        """Calculate baseline metrics from current log set"""
        if not self.all_logs:
            return
        
        # Group by host
        by_host = defaultdict(list)
        by_user = defaultdict(list)
        by_event_type = defaultdict(int)
        
        for log in self.all_logs:
            host = log.get('host', 'unknown')
            user = log.get('user', 'unknown')
            event = log.get('event', '')
            
            if host != 'N/A':
                by_host[host].append(log)
            
            if user != 'N/A':
                by_user[user].append(log)
            
            # Count event types
            event_lower = event.lower()
            if 'failed' in event_lower and 'login' in event_lower:
                by_event_type['failed_login'] += 1
            elif 'success' in event_lower and 'login' in event_lower:
                by_event_type['successful_login'] += 1
            elif 'privilege' in event_lower:
                by_event_type['privilege_change'] += 1
            elif 'process' in event_lower:
                by_event_type['process_creation'] += 1
        
        self.baselines = {
            'by_host': {host: len(events) for host, events in by_host.items()},
            'by_user': {user: len(events) for user, events in by_user.items()},
            'by_event_type': dict(by_event_type),
            'total_events': len(self.all_logs)
        }
    
    def detect_anomalies(self, target_log):
        """
        Detect anomalies for a given log entry
        
        Returns:
            dict with anomaly findings
        """
        anomalies = []
        
        # 1. Host activity anomaly
        host_anomaly = self._check_host_anomaly(target_log)
        if host_anomaly:
            anomalies.append(host_anomaly)
        
        # 2. User behavior anomaly
        user_anomaly = self._check_user_anomaly(target_log)
        if user_anomaly:
            anomalies.append(user_anomaly)
        
        # 3. First-time occurrence
        first_time = self._check_first_occurrence(target_log)
        if first_time:
            anomalies.append(first_time)
        
        # 4. Frequency anomaly
        frequency = self._check_frequency_anomaly(target_log)
        if frequency:
            anomalies.append(frequency)
        
        # 5. Time-based anomaly (beyond just business hours)
        time_anomaly = self._check_time_pattern_anomaly(target_log)
        if time_anomaly:
            anomalies.append(time_anomaly)
        
        # 6. IP geolocation anomaly (if we have IP history)
        ip_anomaly = self._check_ip_anomaly(target_log)
        if ip_anomaly:
            anomalies.append(ip_anomaly)
        
        return {
            'has_anomalies': len(anomalies) > 0,
            'anomalies': anomalies,
            'anomaly_count': len(anomalies),
            'risk_adjustment': self._calculate_risk_adjustment(anomalies)
        }
    
    def _check_host_anomaly(self, target_log):
        """Check if host activity is anomalous"""
        host = target_log.get('host')
        if not host or host == 'N/A':
            return None
        
        # Get baseline for this host
        baseline_count = self.baselines.get('by_host', {}).get(host, 0)
        
        # Count current events for this host
        current_count = sum(1 for log in self.all_logs if log.get('host') == host)
        
        # If this host has way more activity than average
        avg_per_host = sum(self.baselines.get('by_host', {}).values()) / max(len(self.baselines.get('by_host', {})), 1)
        
        if current_count > avg_per_host * 3:
            return {
                'type': 'Host Activity Spike',
                'severity': 'Medium',
                'description': f'Host "{host}" has {current_count} events (average: {int(avg_per_host)})',
                'reason': f'{int((current_count / avg_per_host) * 100)}% above normal',
                'risk_impact': +15
            }
        
        # If this is the first time seeing this host
        if baseline_count == 1:  # Only this event
            return {
                'type': 'New Host',
                'severity': 'Low',
                'description': f'First event from host "{host}"',
                'reason': 'No historical baseline for this host',
                'risk_impact': +10
            }
        
        return None
    
    def _check_user_anomaly(self, target_log):
        """Check if user behavior is anomalous"""
        user = target_log.get('user')
        if not user or user == 'N/A':
            return None
        
        # Get baseline for this user
        baseline_count = self.baselines.get('by_user', {}).get(user, 0)
        
        # First time seeing this user
        if baseline_count == 1:
            return {
                'type': 'New User Activity',
                'severity': 'Low',
                'description': f'First event from user "{user}"',
                'reason': 'No historical activity for this user',
                'risk_impact': +10
            }
        
        # Check if user is active on unusual host
        user_hosts = set()
        for log in self.all_logs:
            if log.get('user') == user:
                user_hosts.add(log.get('host'))
        
        if len(user_hosts) > 3:
            return {
                'type': 'User Multi-Host Activity',
                'severity': 'Medium',
                'description': f'User "{user}" active on {len(user_hosts)} different hosts',
                'reason': 'Possible lateral movement or normal admin activity',
                'risk_impact': +10
            }
        
        return None
    
    def _check_first_occurrence(self, target_log):
        """Check if this is the first time seeing this pattern"""
        # Use memory store if available
        if self.memory_store:
            pattern_hash, _ = self.memory_store.generate_pattern_hash(target_log)
            history = self.memory_store.get_pattern_history(target_log)
            
            if not history['has_history']:
                return {
                    'type': 'First Occurrence',
                    'severity': 'Medium',
                    'description': 'This event pattern has never been seen before',
                    'reason': 'No historical record of similar events',
                    'risk_impact': +20
                }
        
        return None
    
    def _check_frequency_anomaly(self, target_log):
        """Check if event type is occurring too frequently"""
        event = str(target_log.get('event', '')).lower()
        
        # Detect event type
        event_type = None
        if 'failed' in event and 'login' in event:
            event_type = 'failed_login'
        elif 'success' in event and 'login' in event:
            event_type = 'successful_login'
        elif 'privilege' in event:
            event_type = 'privilege_change'
        
        if not event_type:
            return None
        
        # Get baseline count
        baseline_count = self.baselines.get('by_event_type', {}).get(event_type, 0)
        
        # If this event type is very common (happens a lot)
        total = self.baselines.get('total_events', 1)
        frequency_rate = (baseline_count / total) * 100
        
        if frequency_rate > 30:  # More than 30% of all events
            return {
                'type': 'High Frequency Event',
                'severity': 'Low',
                'description': f'This event type occurs frequently ({int(frequency_rate)}% of all events)',
                'reason': 'Likely benign operational noise',
                'risk_impact': -15  # REDUCE risk for common events
            }
        
        # If this event type is rare
        if frequency_rate < 5 and baseline_count < 3:
            return {
                'type': 'Rare Event Type',
                'severity': 'Medium',
                'description': f'This event type is uncommon (only {baseline_count} occurrence(s))',
                'reason': 'Rare events warrant closer inspection',
                'risk_impact': +15
            }
        
        return None
    
    def _check_time_pattern_anomaly(self, target_log):
        """Check for time-based anomalies beyond business hours"""
        context = target_log.get('context', {})
        time_ctx = context.get('time_context', {})
        
        # Already flagged by context engine, but let's add detail
        if not time_ctx.get('is_business_hours'):
            # Check how many other events are also after hours
            after_hours_count = sum(1 for log in self.all_logs 
                                   if not log.get('context', {}).get('time_context', {}).get('is_business_hours', True))
            
            if after_hours_count < len(self.all_logs) * 0.1:  # Less than 10% are after hours
                return {
                    'type': 'Unusual Time Pattern',
                    'severity': 'Medium',
                    'description': f'Only {after_hours_count} of {len(self.all_logs)} events occur after hours',
                    'reason': 'After-hours activity is uncommon in this dataset',
                    'risk_impact': +10
                }
        
        return None
    
    def _check_ip_anomaly(self, target_log):
        """Check for IP-based anomalies"""
        context = target_log.get('context', {})
        network_ctx = context.get('network_context', {})
        external_ips = network_ctx.get('external_ips', [])
        
        if not external_ips:
            return None
        
        # Count how many events involve external IPs
        external_ip_events = sum(1 for log in self.all_logs
                                if log.get('context', {}).get('network_context', {}).get('has_external_ip'))
        
        if external_ip_events < len(self.all_logs) * 0.2:  # Less than 20% external
            return {
                'type': 'Rare External Communication',
                'severity': 'Medium',
                'description': f'Only {external_ip_events} of {len(self.all_logs)} events involve external IPs',
                'reason': 'External communication is uncommon in this environment',
                'risk_impact': +15
            }
        
        return None
    
    def _calculate_risk_adjustment(self, anomalies):
        """Calculate total risk adjustment from anomalies"""
        if not anomalies:
            return 0
        
        total_adjustment = sum(a.get('risk_impact', 0) for a in anomalies)
        
        # Cap adjustment
        return max(-30, min(30, total_adjustment))
    
    def get_anomaly_summary(self, target_log):
        """Get quick summary of anomalies for display"""
        result = self.detect_anomalies(target_log)
        
        if not result['has_anomalies']:
            return None
        
        # Return most significant anomalies
        significant = [a for a in result['anomalies'] if a.get('severity') in ['High', 'Medium']]
        
        if not significant:
            return None
        
        return {
            'count': len(significant),
            'types': [a['type'] for a in significant],
            'risk_adjustment': result['risk_adjustment'],
            'summary': f"{len(significant)} anomaly(ies) detected: {', '.join([a['type'] for a in significant[:2]])}"
        }
