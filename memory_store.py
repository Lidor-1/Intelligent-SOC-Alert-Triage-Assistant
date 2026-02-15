"""
Memory Store - SQLite-based feedback and pattern tracking
Enhanced with analyst notes and better tracking
"""
import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path

class MemoryStore:
    def __init__(self, db_path="soc_memory.db"):
        """Initialize memory store with SQLite database"""
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Create database tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Feedback table with notes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_hash TEXT NOT NULL,
                log_entry TEXT NOT NULL,
                feedback_type TEXT NOT NULL,
                severity TEXT,
                confidence TEXT,
                notes TEXT,
                analyst_name TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (pattern_hash) REFERENCES patterns(pattern_hash)
            )
        ''')
        
        # Patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                pattern_hash TEXT PRIMARY KEY,
                pattern_signature TEXT NOT NULL,
                event_category TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                seen_count INTEGER DEFAULT 1,
                true_positive_count INTEGER DEFAULT 0,
                false_positive_count INTEGER DEFAULT 0,
                benign_count INTEGER DEFAULT 0,
                escalated_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_pattern_hash 
            ON feedback(pattern_hash)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON feedback(timestamp)
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_pattern_hash(self, log_entry):
        """Generate a hash representing the pattern of this log entry"""
        context = log_entry.get('context', {})
        
        signature_parts = [
            str(context.get('event_category', {}).get('primary', 'unknown')),
            str(context.get('asset_context', {}).get('asset_type', 'unknown')),
            str(log_entry.get('severity', 'unknown')).lower(),
        ]
        
        event_text = str(log_entry.get('event', '')).lower()
        keywords = ['failed', 'success', 'login', 'logout', 'denied', 'allowed', 
                   'created', 'deleted', 'modified', 'error', 'warning']
        found_keywords = [kw for kw in keywords if kw in event_text]
        signature_parts.extend(sorted(found_keywords))
        
        signature = '|'.join(signature_parts)
        pattern_hash = hashlib.md5(signature.encode()).hexdigest()[:16]
        
        return pattern_hash, signature
    
    def record_feedback(self, log_entry, feedback_type, notes="", analyst_name="analyst"):
        """Record analyst feedback on a log entry"""
        pattern_hash, signature = self.generate_pattern_hash(log_entry)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO feedback 
            (pattern_hash, log_entry, feedback_type, severity, confidence, notes, analyst_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            pattern_hash,
            json.dumps(log_entry),
            feedback_type,
            log_entry.get('severity'),
            log_entry.get('context', {}).get('ai_analysis', {}).get('confidence', 'N/A'),
            notes,
            analyst_name
        ))
        
        cursor.execute('''
            INSERT INTO patterns 
            (pattern_hash, pattern_signature, event_category, seen_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(pattern_hash) DO UPDATE SET
                last_seen = CURRENT_TIMESTAMP,
                seen_count = seen_count + 1
        ''', (
            pattern_hash,
            signature,
            log_entry.get('context', {}).get('event_category', {}).get('primary', 'unknown')
        ))
        
        if feedback_type == 'true_positive':
            cursor.execute('''
                UPDATE patterns 
                SET true_positive_count = true_positive_count + 1
                WHERE pattern_hash = ?
            ''', (pattern_hash,))
        elif feedback_type == 'false_positive':
            cursor.execute('''
                UPDATE patterns 
                SET false_positive_count = false_positive_count + 1
                WHERE pattern_hash = ?
            ''', (pattern_hash,))
        elif feedback_type == 'benign':
            cursor.execute('''
                UPDATE patterns 
                SET benign_count = benign_count + 1
                WHERE pattern_hash = ?
            ''', (pattern_hash,))
        elif feedback_type == 'escalated':
            cursor.execute('''
                UPDATE patterns 
                SET escalated_count = escalated_count + 1
                WHERE pattern_hash = ?
            ''', (pattern_hash,))
        
        conn.commit()
        conn.close()
        
        return pattern_hash
    
    def get_pattern_history(self, log_entry):
        """Retrieve historical data about this pattern"""
        pattern_hash, _ = self.generate_pattern_hash(log_entry)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                pattern_signature,
                event_category,
                seen_count,
                true_positive_count,
                false_positive_count,
                benign_count,
                escalated_count,
                first_seen,
                last_seen
            FROM patterns
            WHERE pattern_hash = ?
        ''', (pattern_hash,))
        
        row = cursor.fetchone()
        
        if row:
            history = {
                'pattern_hash': pattern_hash,
                'signature': row[0],
                'event_category': row[1],
                'seen_count': row[2],
                'true_positive_count': row[3],
                'false_positive_count': row[4],
                'benign_count': row[5],
                'escalated_count': row[6],
                'first_seen': row[7],
                'last_seen': row[8],
                'has_history': True
            }
            
            total = history['seen_count']
            if total > 0:
                history['false_positive_rate'] = round((history['false_positive_count'] / total) * 100, 1)
                history['true_positive_rate'] = round((history['true_positive_count'] / total) * 100, 1)
                history['benign_rate'] = round((history['benign_count'] / total) * 100, 1)
            
            cursor.execute('''
                SELECT feedback_type, notes, analyst_name, timestamp
                FROM feedback
                WHERE pattern_hash = ?
                ORDER BY timestamp DESC
                LIMIT 5
            ''', (pattern_hash,))
            
            recent_feedback = []
            for fb_row in cursor.fetchall():
                recent_feedback.append({
                    'type': fb_row[0],
                    'notes': fb_row[1],
                    'analyst': fb_row[2],
                    'timestamp': fb_row[3]
                })
            
            history['recent_feedback'] = recent_feedback
            history['recommendation'] = self._generate_recommendation(history)
            
            conn.close()
            return history
        else:
            conn.close()
            return {
                'pattern_hash': pattern_hash,
                'has_history': False,
                'seen_count': 0,
                'recommendation': 'First time seeing this pattern - treat as new'
            }
    
    def _generate_recommendation(self, history):
        """Generate recommendation based on historical data"""
        seen = history['seen_count']
        fp_count = history['false_positive_count']
        tp_count = history['true_positive_count']
        benign_count = history['benign_count']
        
        if seen < 3:
            return "Limited history - proceed with standard analysis"
        
        if fp_count > (seen * 0.7):
            return f"⚠️ Likely False Positive - marked benign {fp_count}/{seen} times before"
        
        if benign_count > (seen * 0.8):
            return f"✓ Likely Benign - normal operational activity ({benign_count}/{seen} times)"
        
        if tp_count > (seen * 0.6):
            return f"🚨 Known Threat Pattern - confirmed malicious {tp_count}/{seen} times"
        
        return f"⚡ Mixed History - review carefully (seen {seen} times)"
    
    def get_statistics(self):
        """Get overall statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM patterns')
        total_patterns = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM feedback')
        total_feedback = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT feedback_type, COUNT(*) 
            FROM feedback 
            GROUP BY feedback_type
        ''')
        feedback_breakdown = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT pattern_signature, event_category, seen_count, false_positive_count
            FROM patterns
            ORDER BY seen_count DESC
            LIMIT 10
        ''')
        top_patterns = []
        for row in cursor.fetchall():
            top_patterns.append({
                'signature': row[0],
                'category': row[1],
                'count': row[2],
                'fp_count': row[3]
            })
        
        conn.close()
        
        return {
            'total_patterns': total_patterns,
            'total_feedback': total_feedback,
            'feedback_breakdown': feedback_breakdown,
            'top_patterns': top_patterns
        }
    
    def clear_old_data(self, days=90):
        """Clear feedback older than specified days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM feedback
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted
