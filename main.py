from flask import Flask, render_template, request, jsonify
import os
from log_parser import load_logs, parse_uploaded_file
from ai_analyzer import analyze_log_entry, answer_question
from context_engine import ContextEngine
from risk_scorer import RiskScorer
from memory_store import MemoryStore
from investigation_playbooks import InvestigationPlaybooks
from correlation_engine import CorrelationEngine
from anomaly_detector import AnomalyDetector

template_dir = os.path.join(os.path.dirname(__file__), "templates")
app = Flask(__name__, template_folder=template_dir)

context_engine = ContextEngine()
risk_scorer = RiskScorer()
memory_store = MemoryStore()
playbooks = InvestigationPlaybooks()
correlation_engine = CorrelationEngine()
anomaly_detector = AnomalyDetector(memory_store)

current_logs = []

file_path = "sample_logs/WindowsEventLogs.json"
try:
    logs = load_logs(file_path)
except:
    logs = []

@app.route("/")
def index():
    return render_template("index.html", detections=logs)

@app.route("/upload_logs", methods=["POST"])
def upload_logs():
    global current_logs
    try:
        if "logfile" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files["logfile"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        content = file.read()
        parsed_logs = parse_uploaded_file(content, file.filename)
        
        enriched_logs = []
        for log in parsed_logs:
            enriched_log = context_engine.enrich_log(log)
            enriched_logs.append(enriched_log)
        
        current_logs = enriched_logs
        correlation_engine.set_logs(enriched_logs)
        anomaly_detector.set_logs(enriched_logs)
        
        return jsonify(enriched_logs)
    
    except Exception as e:
        import traceback
        print(f"Error in upload_logs: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/analyze_log", methods=["POST"])
def analyze_log():
    try:
        log_entry = request.json
        
        if not log_entry:
            return jsonify({"error": "No log entry provided"}), 400
        
        if 'context' not in log_entry:
            log_entry = context_engine.enrich_log(log_entry)
        
        anomalies = anomaly_detector.detect_anomalies(log_entry)
        correlations = correlation_engine.find_correlations(log_entry)
        history = memory_store.get_pattern_history(log_entry)
        analysis = analyze_log_entry(log_entry)
        
        risk_result = risk_scorer.calculate_risk_score(
            log_entry, 
            analysis, 
            history,
            anomalies,
            correlations
        )
        
        playbook = playbooks.get_playbook(log_entry)
        context_signals = context_engine.get_context_summary(log_entry)
        why_suspicious = playbooks.get_why_suspicious(log_entry, analysis)
        correlation_summary = correlation_engine.get_related_events_summary(log_entry)
        
        print(f"=== DEBUG ===")
        print(f"Risk Score: {risk_result['score']}")
        print(f"Risk Level: {risk_result['risk_level']}")
        print(f"Confidence: {risk_result['confidence']}")
        print(f"FP Prob: {risk_result['false_positive_probability']}")
        
        response = {
            'severity': analysis.get('severity', 'Unknown'),
            'recommended_action': analysis.get('recommended_action', 'Review event'),
            'reasoning': analysis.get('reasoning', 'Event requires analysis'),
            'indicators': analysis.get('indicators', []),
            'next_steps': analysis.get('next_steps', []),
            'mitre_tactics': analysis.get('mitre_tactics', []),
            'risk_score': int(risk_result['score']),
            'risk_level': str(risk_result['risk_level']),
            'risk_components': risk_result['components'],
            'risk_recommendation': str(risk_result['recommendation']),
            'confidence': str(risk_result['confidence']),
            'false_positive_probability': str(risk_result['false_positive_probability']),
            'context_signals': context_signals,
            'why_suspicious': why_suspicious,
            'history': history if history.get('has_history') else None,
            'pattern_hash': history.get('pattern_hash'),
            'playbook': {
                'event_name': playbook.get('event_name', 'Unknown Event'),
                'checklist': playbook.get('checklist', []),
                'suspicious_if': playbook.get('suspicious_if', []),
                'mitre_tactics': playbook.get('mitre_tactics', []),
                'follow_up_events': playbook.get('follow_up_events', [])
            },
            'correlations': {
                'has_correlations': correlations.get('has_correlations', False),
                'summary': correlations.get('summary', ''),
                'related_count': correlations.get('related_count', 0),
                'related_events': correlation_summary,
                'attack_chain': correlations.get('attack_chain')
            },
            'anomalies': {
                'has_anomalies': anomalies.get('has_anomalies', False),
                'anomaly_count': anomalies.get('anomaly_count', 0),
                'anomalies': anomalies.get('anomalies', [])
            }
        }
        
        return jsonify(response)
    
    except Exception as e:
        import traceback
        print(f"ERROR: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/ask_question", methods=["POST"])
def ask_question_endpoint():
    try:
        data = request.json
        log_entry = data.get("log_entry")
        question = data.get("question")
        
        if not log_entry or not question:
            return jsonify({"error": "Missing log_entry or question"}), 400
        
        if 'context' not in log_entry:
            log_entry = context_engine.enrich_log(log_entry)
        
        answer = answer_question(log_entry, question)
        
        return jsonify({"answer": answer})
    
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/record_feedback", methods=["POST"])
def record_feedback():
    try:
        data = request.json
        log_entry = data.get("log_entry")
        feedback_type = data.get("feedback_type")
        notes = data.get("notes", "")
        analyst_name = data.get("analyst_name", "analyst")
        
        if not log_entry or not feedback_type:
            return jsonify({"error": "Missing log_entry or feedback_type"}), 400
        
        valid_types = ['true_positive', 'false_positive', 'benign', 'escalated']
        if feedback_type not in valid_types:
            return jsonify({"error": "Invalid feedback_type"}), 400
        
        if 'context' not in log_entry:
            log_entry = context_engine.enrich_log(log_entry)
        
        pattern_hash = memory_store.record_feedback(log_entry, feedback_type, notes, analyst_name)
        
        return jsonify({
            "success": True,
            "pattern_hash": pattern_hash,
            "message": f"Feedback recorded: {feedback_type}"
        })
    
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/get_statistics", methods=["GET"])
def get_statistics():
    try:
        stats = memory_store.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "components": {
            "context_engine": "active",
            "risk_scorer": "active",
            "memory_store": "active",
            "playbooks": "active",
            "correlation_engine": "active",
            "anomaly_detector": "active"
        }
    })

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
