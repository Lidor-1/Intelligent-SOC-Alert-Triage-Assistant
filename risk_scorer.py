"""
Risk Scorer - Fixed to properly escalate based on context
"""

class RiskScorer:
    def __init__(self):
        """Initialize risk scorer"""
        self.severity_values = {
            'Critical': 40,
            'High': 30,
            'Medium': 15,
            'Low': 5,
            'Unknown': 10
        }
    
    def calculate_risk_score(self, log_entry, analysis=None, history=None, anomalies=None, correlations=None):
        """Calculate risk score with proper escalation logic"""
        
        context = log_entry.get('context', {})
        
        # Get base severity
        severity = log_entry.get('severity', 'Unknown')
        if analysis and 'severity' in analysis:
            severity = analysis['severity']
        
        base_score = self.severity_values.get(severity, 10)
        
        components = [{
            'factor': 'Base Severity',
            'score': base_score,
            'reason': f"Event classified as {severity}",
            'category': 'severity'
        }]
        
        total_score = base_score
        
        # CONTEXT MULTIPLIERS - These should ADD, not multiply for clearer scoring
        asset_ctx = context.get('asset_context', {})
        if asset_ctx.get('is_critical'):
            asset_score = 30  # CRITICAL ASSET = BIG DEAL
            components.append({
                'factor': 'Critical Asset',
                'score': asset_score,
                'reason': f"Occurred on {asset_ctx.get('asset_type', 'critical system')}",
                'category': 'context'
            })
            total_score += asset_score
        
        user_ctx = context.get('user_context', {})
        if user_ctx.get('is_privileged'):
            user_score = 20
            components.append({
                'factor': 'Privileged Account',
                'score': user_score,
                'reason': f"{user_ctx.get('account_type', 'Privileged')} account involved",
                'category': 'context'
            })
            total_score += user_score
        
        time_ctx = context.get('time_context', {})
        if not time_ctx.get('is_business_hours') or time_ctx.get('is_weekend'):
            time_score = 15
            reason = "Weekend activity" if time_ctx.get('is_weekend') else "After business hours"
            components.append({
                'factor': 'Unusual Time',
                'score': time_score,
                'reason': reason,
                'category': 'temporal'
            })
            total_score += time_score
        
        network_ctx = context.get('network_context', {})
        if network_ctx.get('has_external_ip'):
            network_score = 20
            external_ips = network_ctx.get('external_ips', [])
            components.append({
                'factor': 'External Connection',
                'score': network_score,
                'reason': f"External IP: {external_ips[0] if external_ips else 'detected'}",
                'category': 'network'
            })
            total_score += network_score
        
        # EVENT CATEGORY BONUSES
        event_cat = context.get('event_category', {})
        primary_cat = event_cat.get('primary', '')
        event_text = str(log_entry.get('event', '')).lower()
        
        if primary_cat == 'authentication' and any(word in event_text for word in ['failed', 'failure', 'denied']):
            auth_score = 25
            components.append({
                'factor': 'Failed Authentication',
                'score': auth_score,
                'reason': "Authentication attempt failed",
                'category': 'behavior'
            })
            total_score += auth_score
        
        if primary_cat == 'privilege_escalation':
            priv_score = 35
            components.append({
                'factor': 'Privilege Escalation',
                'score': priv_score,
                'reason': "Privilege elevation detected",
                'category': 'behavior'
            })
            total_score += priv_score
        
        suspicious_keywords = [
            'attack', 'breach', 'compromise', 'malware', 'ransomware',
            'injection', 'exploit', 'backdoor', 'suspicious', 'unauthorized'
        ]
        found_keywords = [kw for kw in suspicious_keywords if kw in event_text]
        if found_keywords:
            keyword_score = 20
            components.append({
                'factor': 'Suspicious Keywords',
                'score': keyword_score,
                'reason': f"Keywords: {', '.join(found_keywords[:2])}",
                'category': 'content'
            })
            total_score += keyword_score
        
        # ANOMALY ADJUSTMENTS
        if anomalies and anomalies.get('has_anomalies'):
            anomaly_adjustment = anomalies.get('risk_adjustment', 0)
            if anomaly_adjustment != 0:
                anomaly_types = [a['type'] for a in anomalies['anomalies'][:2]]
                components.append({
                    'factor': 'Anomaly Detection',
                    'score': anomaly_adjustment,
                    'reason': f"Anomalies: {', '.join(anomaly_types)}",
                    'category': 'anomaly'
                })
                total_score += anomaly_adjustment
        
        # CORRELATION ADJUSTMENTS
        if correlations and correlations.get('attack_chain') and correlations['attack_chain'].get('detected'):
            chain_score = 30  # Attack chains are SERIOUS
            patterns = correlations['attack_chain'].get('patterns', [])
            pattern_names = [p['name'] for p in patterns[:1]]
            components.append({
                'factor': 'Attack Chain Detected',
                'score': chain_score,
                'reason': f"Pattern: {pattern_names[0] if pattern_names else 'Correlation found'}",
                'category': 'correlation'
            })
            total_score += chain_score
        
        # HISTORICAL ADJUSTMENTS
        if history and history.get('has_history'):
            seen_count = history.get('seen_count', 0)
            fp_count = history.get('false_positive_count', 0)
            tp_count = history.get('true_positive_count', 0)
            
            if seen_count > 5:
                if fp_count > (seen_count * 0.7):
                    history_adjustment = -30  # Strong FP history
                    components.append({
                        'factor': 'Known False Positive',
                        'score': history_adjustment,
                        'reason': f"Marked benign {fp_count}/{seen_count} times",
                        'category': 'historical'
                    })
                    total_score += history_adjustment
                
                elif tp_count > (seen_count * 0.6):
                    history_adjustment = 25  # Known threat
                    components.append({
                        'factor': 'Known Threat Pattern',
                        'score': history_adjustment,
                        'reason': f"Confirmed malicious {tp_count}/{seen_count} times",
                        'category': 'historical'
                    })
                    total_score += history_adjustment
        
        # NORMALIZE (0-100)
        final_score = max(0, min(100, int(total_score)))
        
        # DETERMINE RISK LEVEL
        risk_level = self._get_risk_level(final_score)
        
        # CALCULATE CONFIDENCE & FP PROBABILITY
        confidence_score = self._calculate_confidence(
            final_score, 
            context, 
            history, 
            anomalies,
            components
        )
        
        fp_probability = self._calculate_fp_probability(
            final_score,
            history,
            context,
            confidence_score
        )
        
        return {
            'score': final_score,
            'risk_level': risk_level,
            'components': components,
            'total_factors': len(components),
            'recommendation': self._get_recommendation(risk_level),
            'confidence': f"{int(confidence_score * 100)}%",
            'confidence_raw': confidence_score,
            'false_positive_probability': f"{int(fp_probability * 100)}%",
            'fp_probability_raw': fp_probability
        }
    
    def _get_risk_level(self, score):
        """Risk level from score"""
        if score >= 75:
            return 'Critical'
        elif score >= 55:
            return 'High'
        elif score >= 35:
            return 'Medium'
        elif score >= 15:
            return 'Low'
        else:
            return 'Minimal'
    
    def _calculate_confidence(self, risk_score, context, history, anomalies, components):
        """Calculate confidence (0.0-1.0)"""
        confidence = 0.5
        
        # More factors = higher confidence
        factor_count = len(components)
        confidence += min(0.25, factor_count * 0.04)
        
        # Historical data = higher confidence
        if history and history.get('has_history'):
            seen_count = history.get('seen_count', 0)
            if seen_count > 10:
                confidence += 0.15
            elif seen_count > 5:
                confidence += 0.10
            else:
                confidence += 0.05
        
        # Context signals = higher confidence
        context_signals = 0
        if context.get('asset_context', {}).get('is_critical'):
            context_signals += 1
        if context.get('user_context', {}).get('is_privileged'):
            context_signals += 1
        if not context.get('time_context', {}).get('is_business_hours'):
            context_signals += 1
        if context.get('network_context', {}).get('has_external_ip'):
            context_signals += 1
        
        confidence += context_signals * 0.05
        
        # Anomalies = higher confidence
        if anomalies and anomalies.get('has_anomalies'):
            confidence += 0.10
        
        return min(0.95, confidence)
    
    def _calculate_fp_probability(self, risk_score, history, context, confidence):
        """Calculate false positive probability (0.0-1.0)"""
        # Base: inverse of risk score
        base_fp = 1.0 - (risk_score / 100)
        
        # Historical override
        if history and history.get('has_history'):
            seen_count = history.get('seen_count', 0)
            fp_count = history.get('false_positive_count', 0)
            
            if seen_count > 3:
                historical_fp_rate = fp_count / seen_count
                # Weight historical heavily
                base_fp = (base_fp * 0.3) + (historical_fp_rate * 0.7)
        
        # Context reduces FP probability
        context_signals = 0
        if context.get('asset_context', {}).get('is_critical'):
            context_signals += 1
        if context.get('user_context', {}).get('is_privileged'):
            context_signals += 1
        if not context.get('time_context', {}).get('is_business_hours'):
            context_signals += 1
        if context.get('network_context', {}).get('has_external_ip'):
            context_signals += 1
        
        # Each suspicious signal reduces FP by 10%
        adjusted_fp = max(0.05, base_fp - (context_signals * 0.10))
        
        return max(0.05, min(0.95, adjusted_fp))
    
    def _get_recommendation(self, risk_level):
        """Recommendation based on risk level"""
        recommendations = {
            'Critical': 'Immediate investigation required - potential active threat',
            'High': 'Priority investigation - validate and respond within 1 hour',
            'Medium': 'Review and assess - investigate within 4 hours',
            'Low': 'Monitor and document - review during routine checks',
            'Minimal': 'Informational - log for baseline analysis'
        }
        return recommendations.get(risk_level, 'Review as needed')
