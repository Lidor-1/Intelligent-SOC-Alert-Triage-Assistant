"""
Investigation Playbooks - Event-specific investigation guidance
No generic AI slop - real SOC analyst workflows
"""

class InvestigationPlaybooks:
    def __init__(self):
        """Initialize playbooks for different event types"""
        self.playbooks = self._load_playbooks()
    
    def _load_playbooks(self):
        """Define investigation playbooks for specific event types"""
        return {
            # Windows Authentication Events
            '4624': {  # Successful Logon
                'event_name': 'Successful Logon',
                'why_matters': [
                    'Tracks user access to systems',
                    'Can indicate compromised credentials if unusual',
                    'Critical for detecting lateral movement'
                ],
                'checklist': [
                    'Verify source IP is expected for this user',
                    'Check if logon type matches user role (2=Interactive, 3=Network, 10=RDP)',
                    'Confirm if this is a service account with scheduled task',
                    'Review failed attempts from same IP in last 30 minutes',
                    'Validate if user typically accesses this host',
                    'Check for privilege escalation attempts after logon'
                ],
                'suspicious_if': [
                    'Logon from geographically impossible location',
                    'Multiple failed attempts followed by success',
                    'Service account used interactively',
                    'Logon outside normal working hours for this user',
                    'First time this user accessed this host'
                ],
                'mitre_tactics': ['T1078 - Valid Accounts'],
                'follow_up_events': ['4672', '4688', '5140']
            },
            
            '4625': {  # Failed Logon
                'event_name': 'Failed Logon Attempt',
                'why_matters': [
                    'Could indicate brute force attack',
                    'May reveal reconnaissance activity',
                    'Precursor to account lockout (4740)'
                ],
                'checklist': [
                    'Count total failures from this IP in last hour',
                    'Check if multiple usernames tried from same IP (password spray)',
                    'Verify if source IP is internal or external',
                    'Look for successful logon after failures',
                    'Check if account is now locked (EventID 4740)',
                    'Review threat intelligence for source IP'
                ],
                'suspicious_if': [
                    '5+ failures in 10 minutes',
                    'Multiple different usernames from same IP',
                    'Failures targeting admin accounts',
                    'External IP attempting internal authentication',
                    'Success immediately after multiple failures'
                ],
                'mitre_tactics': ['T1110 - Brute Force', 'T1110.003 - Password Spraying'],
                'follow_up_events': ['4624', '4740', '4767']
            },
            
            '4672': {  # Special Privileges Assigned
                'event_name': 'Privileged Logon',
                'why_matters': [
                    'Tracks elevation to admin rights',
                    'Critical for detecting privilege abuse',
                    'Required for compliance auditing'
                ],
                'checklist': [
                    'Verify user is authorized administrator',
                    'Check if elevation matches approved change window',
                    'Review what actions user performed with privileges',
                    'Confirm if this is expected scheduled maintenance',
                    'Validate MFA was used if required by policy',
                    'Check for suspicious processes launched after elevation'
                ],
                'suspicious_if': [
                    'Non-admin user receiving privileged token',
                    'Elevation outside change control window',
                    'Multiple privilege escalations in short time',
                    'Privileges assigned to service account interactively',
                    'No corresponding ticket/approval'
                ],
                'mitre_tactics': ['T1078.002 - Domain Accounts', 'T1068 - Exploitation for Privilege Escalation'],
                'follow_up_events': ['4688', '4673', '4674']
            },
            
            '4688': {  # Process Creation
                'event_name': 'New Process Created',
                'why_matters': [
                    'Detects execution of malicious tools',
                    'Tracks command-line execution',
                    'Critical for threat hunting'
                ],
                'checklist': [
                    'Review full command-line arguments',
                    'Check parent process (what spawned this)',
                    'Verify process hash against VirusTotal/threat intel',
                    'Validate if process is expected on this host',
                    'Check if running from unusual location (temp dirs, user folders)',
                    'Look for obfuscation (base64, encoded commands)'
                ],
                'suspicious_if': [
                    'PowerShell with -enc (encoded commands)',
                    'cmd.exe spawned by Office applications',
                    'Processes from user temp directories',
                    'Unsigned binaries on critical servers',
                    'Mimikatz, PsExec, or known tools',
                    'Parent process is unusual (e.g., Excel spawning cmd.exe)'
                ],
                'mitre_tactics': ['T1059 - Command and Scripting Interpreter', 'T1218 - System Binary Proxy Execution'],
                'follow_up_events': ['4689', '5156', '4663']
            },
            
            '4740': {  # Account Lockout
                'event_name': 'Account Locked Out',
                'why_matters': [
                    'Result of repeated failed logons',
                    'Could indicate brute force attack',
                    'May be user forgetting password'
                ],
                'checklist': [
                    'Identify source of failed attempts (which DC/system)',
                    'Count how many lockouts for this user in last 24h',
                    'Check if automated service causing lockout',
                    'Review failed logon events (4625) leading to lockout',
                    'Verify if user reports password issues',
                    'Check for lockouts across multiple accounts (pattern)'
                ],
                'suspicious_if': [
                    'Multiple accounts locked simultaneously',
                    'Lockouts from external IP addresses',
                    'High-privilege accounts being locked',
                    'Lockout with no user report of issues',
                    'Pattern of lockouts across different users'
                ],
                'mitre_tactics': ['T1110 - Brute Force'],
                'follow_up_events': ['4625', '4767', '4768']
            },
            
            '4720': {  # User Account Created
                'event_name': 'User Account Created',
                'why_matters': [
                    'Tracks new account creation',
                    'Critical for detecting persistence',
                    'Required for compliance'
                ],
                'checklist': [
                    'Verify who created the account (check Subject field)',
                    'Confirm account creation was approved',
                    'Check if account naming follows policy',
                    'Review if account added to privileged groups immediately',
                    'Validate if creation matches HR onboarding',
                    'Check for suspicious account names (admin2, test, backup)'
                ],
                'suspicious_if': [
                    'Account created outside business hours',
                    'Name resembles existing admin account',
                    'Created by non-HR/non-IT account',
                    'Immediately added to Domain Admins',
                    'Account name is generic (test, admin, temp)'
                ],
                'mitre_tactics': ['T1136.001 - Create Account: Local Account', 'T1136.002 - Create Account: Domain Account'],
                'follow_up_events': ['4728', '4732', '4624']
            },
            
            '4728': {  # Member Added to Security Group
                'event_name': 'User Added to Security Group',
                'why_matters': [
                    'Tracks privilege elevation',
                    'Detects unauthorized admin access',
                    'Critical for detecting persistence'
                ],
                'checklist': [
                    'Identify which group (Domain Admins, Enterprise Admins, etc)',
                    'Verify who performed the addition',
                    'Check if change was approved via ticket',
                    'Review if addition matches access request',
                    'Confirm if temporary access has expiration',
                    'Check for multiple adds to different groups'
                ],
                'suspicious_if': [
                    'Addition to Domain Admins or Enterprise Admins',
                    'Performed outside change window',
                    'Done by non-admin account',
                    'User added to multiple privileged groups rapidly',
                    'No corresponding change ticket'
                ],
                'mitre_tactics': ['T1098 - Account Manipulation'],
                'follow_up_events': ['4672', '4624', '4732']
            },
            
            '5156': {  # Network Connection
                'event_name': 'Windows Filtering Platform Connection',
                'why_matters': [
                    'Tracks network connections',
                    'Detects C2 communication',
                    'Shows data exfiltration attempts'
                ],
                'checklist': [
                    'Identify destination IP and port',
                    'Check if destination is internal or external',
                    'Verify if application typically makes network connections',
                    'Review threat intelligence for destination IP',
                    'Check for beaconing behavior (regular intervals)',
                    'Validate if port is expected for this service'
                ],
                'suspicious_if': [
                    'Connection to known malicious IP',
                    'Unusual ports (non-standard services)',
                    'Office applications connecting externally',
                    'Connections to TOR exit nodes',
                    'Regular beaconing patterns',
                    'Large data transfers to unknown IPs'
                ],
                'mitre_tactics': ['T1071 - Application Layer Protocol', 'T1041 - Exfiltration Over C2 Channel'],
                'follow_up_events': ['3', '5158', '5157']
            },
            
            'unknown': {
                'event_name': 'Security Event',
                'why_matters': [
                    'Security-relevant system activity detected',
                    'Requires analysis for potential threats'
                ],
                'checklist': [
                    'Review event details and context',
                    'Check frequency of this event type',
                    'Correlate with other events from same source',
                    'Validate if this matches normal baseline',
                    'Document findings for future reference'
                ],
                'suspicious_if': [
                    'Event occurs outside normal patterns',
                    'Associated with known malicious activity',
                    'Triggered on critical asset'
                ],
                'mitre_tactics': [],
                'follow_up_events': []
            }
        }
    
    def get_playbook(self, log_entry):
        """Get investigation playbook for a log entry"""
        event_id = self._extract_event_id(log_entry)
        playbook = self.playbooks.get(event_id, self.playbooks['unknown'])
        contextualized = self._contextualize_playbook(playbook, log_entry)
        return contextualized
    
    def _extract_event_id(self, log_entry):
        """Extract Windows Event ID from log entry"""
        context = log_entry.get('context', {})
        structured = context.get('structured_data', {})
        event_ids = structured.get('event_ids', [])
        
        if event_ids:
            return event_ids[0]
        
        event_text = str(log_entry.get('event', ''))
        patterns = [
            r'EventID[:\s]+(\d+)',
            r'Event ID[:\s]+(\d+)',
            r'ID[:\s]+(\d+)',
            r'\b(\d{4})\b'
        ]
        
        import re
        for pattern in patterns:
            match = re.search(pattern, event_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def _contextualize_playbook(self, playbook, log_entry):
        """Add context-specific details to the playbook"""
        context = log_entry.get('context', {})
        contextualized = playbook.copy()
        additional_checks = []
        
        if context.get('asset_context', {}).get('is_critical'):
            additional_checks.append('⚠️ CRITICAL ASSET - Escalate if suspicious')
        
        if context.get('user_context', {}).get('is_privileged'):
            additional_checks.append('⚠️ PRIVILEGED ACCOUNT - Verify authorization')
        
        if not context.get('time_context', {}).get('is_business_hours'):
            additional_checks.append('⚠️ AFTER HOURS - Confirm if expected maintenance')
        
        if context.get('network_context', {}).get('has_external_ip'):
            additional_checks.append('⚠️ EXTERNAL IP - Check threat intelligence feeds')
        
        if additional_checks:
            contextualized['checklist'] = additional_checks + contextualized['checklist']
        
        return contextualized
    
    def get_why_suspicious(self, log_entry, analysis):
        """Generate structured 'why suspicious' section"""
        indicators = []
        context = log_entry.get('context', {})
        
        if context.get('asset_context', {}).get('is_critical'):
            asset_type = context['asset_context'].get('asset_type', 'critical system')
            indicators.append(f"Occurred on {asset_type}")
        
        if context.get('user_context', {}).get('is_privileged'):
            account_type = context['user_context'].get('account_type', 'privileged account')
            indicators.append(f"Involves {account_type}")
        
        if not context.get('time_context', {}).get('is_business_hours'):
            hour = context['time_context'].get('hour', 'unknown')
            indicators.append(f"Occurred outside business hours ({hour}:00)")
        
        if context.get('time_context', {}).get('is_weekend'):
            indicators.append("Activity on weekend")
        
        if context.get('network_context', {}).get('has_external_ip'):
            external_ips = context['network_context'].get('external_ips', [])
            if external_ips:
                indicators.append(f"External IP communication: {external_ips[0]}")
        
        event_cat = context.get('event_category', {}).get('primary', '')
        if event_cat == 'authentication':
            if 'failed' in str(log_entry.get('event', '')).lower():
                indicators.append("Failed authentication attempt")
        
        if event_cat == 'privilege_escalation':
            indicators.append("Privilege escalation detected")
        
        if analysis.get('severity') in ['Critical', 'High']:
            indicators.append(f"{analysis['severity']} severity classification")
        
        if not indicators:
            indicators.append("Security-relevant event detected")
        
        return indicators
