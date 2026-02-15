"""
AI Threat Analyzer - Enhanced with evidence-based reasoning
"""
import os
import json

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
USE_REAL_AI = bool(ANTHROPIC_API_KEY)

def analyze_log_entry(log_entry):
    """Analyze log entry - returns structured analysis with proper metrics"""
    
    if USE_REAL_AI:
        return analyze_with_claude(log_entry)
    else:
        return analyze_with_rules(log_entry)


def analyze_with_claude(log_entry):
    """Enhanced Claude analysis with full context"""
    try:
        import anthropic
        
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        
        context = log_entry.get('context', {})
        
        # Build enriched context
        context_str = ""
        if context:
            asset_ctx = context.get('asset_context', {})
            user_ctx = context.get('user_context', {})
            time_ctx = context.get('time_context', {})
            network_ctx = context.get('network_context', {})
            event_cat = context.get('event_category', {})
            structured = context.get('structured_data', {})
            
            context_str = f"""

SECURITY CONTEXT:
Asset: {asset_ctx.get('asset_type', 'Unknown')} {'(CRITICAL)' if asset_ctx.get('is_critical') else ''}
User: {user_ctx.get('account_type', 'Unknown')} {'(PRIVILEGED)' if user_ctx.get('is_privileged') else ''}
Time: {time_ctx.get('time_category', 'Unknown')} (Hour: {time_ctx.get('hour', 'N/A')})
Network: {'External IP detected: ' + ', '.join(network_ctx.get('external_ips', [])) if network_ctx.get('has_external_ip') else 'Internal traffic'}
Category: {event_cat.get('primary', 'unknown')}

Extracted Indicators:
- Event IDs: {', '.join(structured.get('event_ids', [])) or 'None'}
- Processes: {', '.join(structured.get('processes', [])) or 'None'}
- IPs: {', '.join(structured.get('ips', [])) or 'None'}"""
        
        prompt = f"""You are a senior SOC analyst. Analyze this security event with provided context.

Event Details:
- Timestamp: {log_entry.get('timestamp', 'N/A')}
- Host: {log_entry.get('host', 'N/A')}
- User: {log_entry.get('user', 'N/A')}
- Event: {log_entry.get('event', 'N/A')}
- Severity: {log_entry.get('severity', 'Unknown')}
{context_str}

Provide analysis in JSON format:
{{
  "severity": "Low/Medium/High/Critical",
  "recommended_action": "specific action",
  "reasoning": "explain assessment with evidence",
  "indicators": ["specific indicators found"],
  "next_steps": ["actionable investigation steps"],
  "mitre_tactics": ["MITRE ATT&CK tactics if applicable"]
}}

Requirements:
1. Reference specific evidence from the context
2. Explain WHY this is suspicious (or not)
3. Be specific in next steps - use actual host/user/IP names
4. Map to MITRE ATT&CK where relevant"""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text
        
        # Extract JSON
        start = response_text.find('{')
        end = response_text.rfind('}') + 1
        
        if start >= 0 and end > start:
            json_str = response_text[start:end]
            analysis = json.loads(json_str)
            return analysis
        else:
            return analyze_with_rules(log_entry)
            
    except Exception as e:
        print(f"Error calling Claude API: {e}")
        return analyze_with_rules(log_entry)


def analyze_with_rules(log_entry):
    """Enhanced rule-based analysis with context awareness"""
    
    event = str(log_entry.get('event', '')).lower()
    severity = log_entry.get('severity', 'Unknown')
    context = log_entry.get('context', {})
    
    # Base severity from keywords
    critical_keywords = ['breach', 'compromised', 'ransomware', 'malware', 'exploit']
    high_keywords = ['failed', 'unauthorized', 'denied', 'suspicious', 'attack']
    medium_keywords = ['warning', 'warn', 'alert', 'retry', 'timeout']
    
    if any(kw in event for kw in critical_keywords):
        assessed_severity = "Critical"
    elif any(kw in event for kw in high_keywords):
        assessed_severity = "High"
    elif any(kw in event for kw in medium_keywords):
        assessed_severity = "Medium"
    else:
        assessed_severity = "Low"
    
    # Context-based adjustments
    if context:
        asset_ctx = context.get('asset_context', {})
        user_ctx = context.get('user_context', {})
        time_ctx = context.get('time_context', {})
        network_ctx = context.get('network_context', {})
        
        # Escalate if critical factors present
        if asset_ctx.get('is_critical') and assessed_severity == "Medium":
            assessed_severity = "High"
        
        if user_ctx.get('is_privileged') and assessed_severity == "Low":
            assessed_severity = "Medium"
        
        if not time_ctx.get('is_business_hours') and network_ctx.get('has_external_ip'):
            if assessed_severity == "Medium":
                assessed_severity = "High"
    
    # Action based on final severity
    actions = {
        'Critical': "Immediate incident response - isolate affected systems and investigate",
        'High': "Priority investigation - validate threat indicators within 1 hour",
        'Medium': "Review and assess - investigate within 4 hours",
        'Low': "Monitor and log - review during routine security checks"
    }
    action = actions.get(assessed_severity, "Review as needed")
    
    # Build evidence-based reasoning
    reasoning_parts = []
    
    # Event-specific reasoning
    if 'failed' in event and 'login' in event:
        reasoning_parts.append("Failed authentication detected - possible brute force or credential attack")
    elif 'success' in event and 'login' in event:
        reasoning_parts.append("Successful authentication logged")
    
    if 'privilege' in event:
        reasoning_parts.append("Privilege escalation activity detected")
    
    # Context-based reasoning
    if context:
        if asset_ctx.get('is_critical'):
            reasoning_parts.append(f"Activity on critical asset: {asset_ctx.get('asset_type')}")
        
        if user_ctx.get('is_privileged'):
            reasoning_parts.append(f"Privileged account involved: {user_ctx.get('account_type')}")
        
        if not time_ctx.get('is_business_hours'):
            reasoning_parts.append(f"After-hours activity at {time_ctx.get('hour')}:00")
        
        if network_ctx.get('has_external_ip'):
            external_ips = network_ctx.get('external_ips', [])
            if external_ips:
                reasoning_parts.append(f"External IP communication: {external_ips[0]}")
    
    reasoning = ". ".join(reasoning_parts) if reasoning_parts else f"Event classified as {assessed_severity} based on content analysis"
    
    # Indicators
    indicators = []
    if context:
        structured = context.get('structured_data', {})
        if structured.get('event_ids'):
            indicators.append(f"Event ID: {structured['event_ids'][0]}")
        if structured.get('processes'):
            indicators.append(f"Process: {structured['processes'][0]}")
        if network_ctx.get('has_external_ip'):
            indicators.append("External network communication")
        if asset_ctx.get('is_critical'):
            indicators.append("Critical asset involved")
    
    if not indicators:
        indicators = ["Security event detected"]
    
    # Next steps
    if assessed_severity in ['Critical', 'High']:
        next_steps = [
            f"Check for related events from {log_entry.get('host', 'this host')} in last hour",
            f"Review activity from {log_entry.get('user', 'this user')} across all systems",
            "Verify if activity matches approved change window",
            "Check threat intelligence for any referenced IPs",
            "Correlate with authentication logs and privilege changes"
        ]
    else:
        next_steps = [
            "Monitor for pattern repetition",
            "Document for trend analysis",
            "Review during next security audit"
        ]
    
    # MITRE mapping
    mitre_tactics = []
    if 'failed' in event and 'login' in event:
        mitre_tactics.append("T1110 - Brute Force")
    if 'privilege' in event:
        mitre_tactics.append("T1068 - Privilege Escalation")
    if 'process' in event:
        mitre_tactics.append("T1059 - Command Execution")
    
    return {
        "severity": assessed_severity,
        "recommended_action": action,
        "reasoning": reasoning,
        "indicators": indicators,
        "next_steps": next_steps,
        "mitre_tactics": mitre_tactics if mitre_tactics else ["No specific tactics identified"]
    }


def answer_question(log_entry, question):
    """Answer questions with evidence from the log"""
    
    if USE_REAL_AI:
        return answer_with_claude(log_entry, question)
    else:
        return answer_with_rules(log_entry, question)


def answer_with_claude(log_entry, question):
    """Claude-powered Q&A with evidence"""
    try:
        import anthropic
        
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        
        context = log_entry.get('context', {})
        context_str = ""
        
        if context:
            asset_ctx = context.get('asset_context', {})
            user_ctx = context.get('user_context', {})
            time_ctx = context.get('time_context', {})
            network_ctx = context.get('network_context', {})
            
            context_str = f"""

Context:
- Asset: {asset_ctx.get('asset_type', 'Unknown')} {'(Critical)' if asset_ctx.get('is_critical') else ''}
- User: {user_ctx.get('account_type', 'Unknown')} {'(Privileged)' if user_ctx.get('is_privileged') else ''}
- Time: {time_ctx.get('time_category', 'Unknown')}
- Network: {'External' if network_ctx.get('has_external_ip') else 'Internal'}"""
        
        prompt = f"""You are a SOC analyst assistant. Answer this question about the log entry.

Log Entry:
- Timestamp: {log_entry.get('timestamp', 'N/A')}
- Host: {log_entry.get('host', 'N/A')}
- User: {log_entry.get('user', 'N/A')}
- Event: {log_entry.get('event', 'N/A')}
{context_str}

Question: {question}

Provide a concise, evidence-based answer. Reference specific details from the log and context."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return message.content[0].text
        
    except Exception as e:
        print(f"Error calling Claude API: {e}")
        return answer_with_rules(log_entry, question)


def answer_with_rules(log_entry, question):
    """Rule-based Q&A with evidence"""
    
    question_lower = question.lower()
    event = str(log_entry.get('event', '')).lower()
    context = log_entry.get('context', {})
    
    # Evidence-based responses
    if 'false positive' in question_lower:
        if 'backup' in event or 'success' in event:
            return f"Evidence suggests likely false positive:\n- Event type: {log_entry.get('event', 'routine operation')}\n- Recommendation: Verify against scheduled maintenance"
        else:
            severity = log_entry.get('severity', 'Unknown')
            return f"Evidence for threat assessment:\n- Severity: {severity}\n- Recommendation: Review context and baseline behavior before dismissing"
    
    elif 'next' in question_lower or 'investigate' in question_lower:
        steps = f"Investigation steps for {log_entry.get('host', 'this host')}:\n"
        steps += f"1. Check related events from {log_entry.get('user', 'this user')}\n"
        steps += "2. Review authentication logs\n"
        steps += "3. Verify against approved change windows\n"
        
        if context and context.get('network_context', {}).get('has_external_ip'):
            external_ips = context['network_context'].get('external_ips', [])
            if external_ips:
                steps += f"4. Check IP reputation for {external_ips[0]}"
        
        return steps
    
    elif 'threat' in question_lower or 'serious' in question_lower:
        severity = log_entry.get('severity', 'Unknown')
        
        threat_assessment = f"Threat Assessment:\n"
        threat_assessment += f"- Severity: {severity}\n"
        
        if context:
            if context.get('asset_context', {}).get('is_critical'):
                threat_assessment += f"- Critical asset involved: {context['asset_context'].get('asset_type')}\n"
            if context.get('user_context', {}).get('is_privileged'):
                threat_assessment += "- Privileged account activity\n"
            if not context.get('time_context', {}).get('is_business_hours'):
                threat_assessment += "- After-hours activity\n"
        
        if severity in ['High', 'Critical']:
            threat_assessment += "\nRecommendation: Immediate investigation warranted"
        else:
            threat_assessment += "\nRecommendation: Monitor and assess"
        
        return threat_assessment
    
    elif 'mitre' in question_lower:
        if 'failed' in event and 'login' in event:
            return "MITRE ATT&CK Mapping:\n- T1110: Brute Force (Credential Access)\n\nThis technique involves automated attempts to guess passwords or crack credentials."
        elif 'privilege' in event:
            return "MITRE ATT&CK Mapping:\n- T1068: Privilege Escalation\n\nAttacker attempting to gain higher-level permissions."
        else:
            return "Review MITRE ATT&CK framework to map this activity. Consider:\n- Tactics observed\n- Techniques employed\n- Tools detected"
    
    else:
        return f"Analysis for {log_entry.get('severity', 'Unknown')} severity event:\n- Host: {log_entry.get('host', 'N/A')}\n- Event: {log_entry.get('event', 'N/A')}\n\nRecommendation: Follow standard {log_entry.get('severity', 'security').lower()} severity procedures"
