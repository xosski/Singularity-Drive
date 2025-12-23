"""
HadesAI - Self-Learning Pentesting & Code Analysis AI
A reinforcement-learning based AI with GUI that improves through experience.
"""

import os
import sys
import json
import hashlib
import sqlite3
import numpy as np
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import re
import threading
import logging

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QProgressBar, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QComboBox, QLineEdit, QPlainTextEdit,
    QGroupBox, QFormLayout, QSpinBox, QDoubleSpinBox, QCheckBox,
    QSplitter, QFrame, QStatusBar, QMenuBar, QMenu, QFileDialog,
    QMessageBox, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QFont, QColor, QTextCharFormat, QSyntaxHighlighter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HadesAI")


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Experience:
    id: str
    input_data: str
    action_taken: str
    result: str
    reward: float
    timestamp: datetime
    category: str
    metadata: Dict = field(default_factory=dict)


@dataclass
class SecurityPattern:
    pattern_id: str
    pattern_type: str
    signature: str
    confidence: float
    occurrences: int
    examples: List[str]
    countermeasures: List[str]
    cwe_ids: List[str]
    cvss_score: Optional[float] = None


# ============================================================================
# SYNTAX HIGHLIGHTER
# ============================================================================

class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#cc7832"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        keywords = [
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def',
            'del', 'elif', 'else', 'except', 'finally', 'for', 'from',
            'global', 'if', 'import', 'in', 'is', 'lambda', 'not', 'or',
            'pass', 'raise', 'return', 'try', 'while', 'with', 'yield'
        ]
        for word in keywords:
            self.highlighting_rules.append((
                re.compile(rf'\b{word}\b'),
                keyword_format
            ))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#6a8759"))
        self.highlighting_rules.append((re.compile(r'"[^"\\]*(\\.[^"\\]*)*"'), string_format))
        self.highlighting_rules.append((re.compile(r"'[^'\\]*(\\.[^'\\]*)*'"), string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#808080"))
        self.highlighting_rules.append((re.compile(r'#.*'), comment_format))
        
        # Functions
        func_format = QTextCharFormat()
        func_format.setForeground(QColor("#ffc66d"))
        self.highlighting_rules.append((re.compile(r'\bdef\s+(\w+)'), func_format))
        
        # Classes
        class_format = QTextCharFormat()
        class_format.setForeground(QColor("#a9b7c6"))
        class_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((re.compile(r'\bclass\s+(\w+)'), class_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


# ============================================================================
# KNOWLEDGE BASE
# ============================================================================

class KnowledgeBase:
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()
        
    def _init_db(self):
        cursor = self.conn.cursor()
        
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS q_values (
                state_hash TEXT,
                action TEXT,
                q_value REAL,
                update_count INTEGER,
                PRIMARY KEY (state_hash, action)
            )
        ''')
        
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
            
    def get_experiences(self, limit: int = 100) -> List[Experience]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM experiences ORDER BY timestamp DESC LIMIT ?', (limit,))
        
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
            
    def get_patterns(self) -> List[SecurityPattern]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM security_patterns')
        patterns = []
        for row in cursor.fetchall():
            patterns.append(SecurityPattern(
                pattern_id=row[0], pattern_type=row[1], signature=row[2],
                confidence=row[3], occurrences=row[4],
                examples=json.loads(row[5]), countermeasures=json.loads(row[6]),
                cwe_ids=json.loads(row[7]), cvss_score=row[8]
            ))
        return patterns


# ============================================================================
# VULNERABILITY DETECTOR
# ============================================================================

class VulnerabilityDetector:
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
        cursor = self.kb.conn.cursor()
        cursor.execute('SELECT pattern_type, signature FROM security_patterns WHERE confidence > 0.7')
        for row in cursor.fetchall():
            self.learned_patterns[row[0]].append(row[1])
            
    def analyze_code(self, code: str, language: str = "python") -> List[Dict[str, Any]]:
        findings = []
        
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


# ============================================================================
# EXPLOIT GENERATOR
# ============================================================================

class ExploitGenerator:
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
        exploits = []
        
        if vuln_type not in self.EXPLOIT_TEMPLATES:
            return exploits
            
        templates = self.EXPLOIT_TEMPLATES[vuln_type]
        
        for technique, template in templates.items():
            try:
                payload = template.format(**context)
            except KeyError:
                payload = template
                
            exploits.append({
                'technique': technique,
                'payload': payload,
                'success_rate': self.success_rates[vuln_type][technique],
                'notes': f"Auto-generated {technique} exploit for {vuln_type}"
            })
                
        return sorted(exploits, key=lambda x: x['success_rate'], reverse=True)
    
    def record_exploit_result(self, vuln_type: str, technique: str, success: bool):
        current_rate = self.success_rates[vuln_type][technique]
        alpha = 0.1
        new_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * current_rate
        self.success_rates[vuln_type][technique] = new_rate


# ============================================================================
# REINFORCEMENT LEARNER
# ============================================================================

class ReinforcementLearner:
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
        state_str = json.dumps(state, sort_keys=True)
        return hashlib.sha256(state_str.encode()).hexdigest()[:16]
    
    def choose_action(self, state: Dict[str, Any]) -> str:
        if np.random.random() < self.epsilon:
            return np.random.choice(self.actions)
        else:
            state_hash = self._state_to_hash(state)
            q_values = {a: self.kb.get_q_value(state_hash, a) for a in self.actions}
            return max(q_values, key=q_values.get)
    
    def learn(self, state: Dict, action: str, reward: float, next_state: Dict):
        state_hash = self._state_to_hash(state)
        next_state_hash = self._state_to_hash(next_state)
        
        current_q = self.kb.get_q_value(state_hash, action)
        next_q_values = [self.kb.get_q_value(next_state_hash, a) for a in self.actions]
        max_next_q = max(next_q_values) if next_q_values else 0.0
        
        new_q = current_q + self.lr * (reward + self.gamma * max_next_q - current_q)
        self.kb.update_q_value(state_hash, action, new_q)
        
    def decay_exploration(self, min_epsilon: float = 0.05, decay_rate: float = 0.995):
        self.epsilon = max(min_epsilon, self.epsilon * decay_rate)


# ============================================================================
# CODE GENERATOR
# ============================================================================

class CodeGenerator:
    PENTEST_TEMPLATES = {
        'port_scanner': '''import socket
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

# Usage: scan_ports("target.com", range(1, 1025))
''',
        'directory_bruteforce': '''import requests
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

# Usage: bruteforce_dirs("http://target.com", ["admin", "login", "api"])
''',
        'hash_cracker': '''import hashlib
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

# Usage: crack_hash("5d41402abc4b2a76b9719d911017c592", "md5")
''',
        'subdomain_enum': '''import socket
import concurrent.futures

def check_subdomain(domain: str, subdomain: str) -> str:
    full_domain = f"{subdomain}.{domain}"
    try:
        socket.gethostbyname(full_domain)
        return full_domain
    except socket.gaierror:
        return None

def enumerate_subdomains(domain: str, wordlist: list, threads: int = 20):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_subdomain, domain, w) for w in wordlist]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found

# Usage: enumerate_subdomains("target.com", ["www", "mail", "api", "dev"])
''',
        'password_generator': '''import secrets
import string

def generate_password(length: int = 16, 
                     use_upper: bool = True,
                     use_lower: bool = True, 
                     use_digits: bool = True,
                     use_special: bool = True) -> str:
    chars = ""
    if use_upper: chars += string.ascii_uppercase
    if use_lower: chars += string.ascii_lowercase
    if use_digits: chars += string.digits
    if use_special: chars += "!@#$%^&*"
    
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_wordlist(base_words: list, mutations: bool = True) -> list:
    wordlist = base_words.copy()
    if mutations:
        for word in base_words:
            wordlist.append(word.upper())
            wordlist.append(word.capitalize())
            wordlist.append(word + "123")
            wordlist.append(word + "!")
            wordlist.append(word.replace('a', '@').replace('e', '3'))
    return wordlist

# Usage: generate_password(20)
''',
        'banner_grabber': '''import socket

def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b"HEAD / HTTP/1.1\\r\\nHost: " + host.encode() + b"\\r\\n\\r\\n")
            return s.recv(1024).decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {e}"

def scan_common_ports(host: str):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080]
    results = {}
    for port in common_ports:
        banner = grab_banner(host, port)
        if not banner.startswith("Error"):
            results[port] = banner
    return results

# Usage: grab_banner("target.com", 80)
''',
        'network_scanner': '''import socket
import struct
import concurrent.futures

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, 80))
        s.close()
        return result == 0
    except:
        return False

def scan_network(network: str, prefix: int = 24, threads: int = 50):
    base_ip = '.'.join(network.split('.')[:3])
    hosts = [f"{base_ip}.{i}" for i in range(1, 255)]
    
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            if future.result():
                alive.append(ip)
    return sorted(alive, key=lambda x: int(x.split('.')[-1]))

# Usage: scan_network("192.168.1.0")
'''
    }
    
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        
    def generate_tool(self, tool_type: str) -> str:
        return self.PENTEST_TEMPLATES.get(tool_type, f"# No template for: {tool_type}")
    
    def list_available_tools(self) -> List[str]:
        return list(self.PENTEST_TEMPLATES.keys())


# ============================================================================
# MAIN AI CLASS
# ============================================================================

class HadesAI:
    def __init__(self, knowledge_path: str = "hades_knowledge.db"):
        self.kb = KnowledgeBase(knowledge_path)
        self.vuln_detector = VulnerabilityDetector(self.kb)
        self.exploit_gen = ExploitGenerator(self.kb)
        self.learner = ReinforcementLearner(self.kb)
        self.code_gen = CodeGenerator(self.kb)
        
        self.session_experiences: List[Experience] = []
        self.current_state: Dict[str, Any] = {}
        
    def analyze(self, code: str, language: str = "python") -> Dict[str, Any]:
        findings = self.vuln_detector.analyze_code(code, language)
        
        result = {
            'vulnerabilities': findings,
            'risk_level': self._calculate_risk_level(findings),
            'recommendations': self._generate_recommendations(findings),
            'exploit_suggestions': []
        }
        
        for finding in findings:
            vuln_type = finding['type']
            exploits = self.exploit_gen.generate_exploit(vuln_type, {})
            result['exploit_suggestions'].extend(exploits[:2])
            
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
        
        rec_map = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'xss': 'Sanitize and escape all user input before rendering',
            'command_injection': 'Avoid shell=True, use subprocess with list args',
            'path_traversal': 'Validate and sanitize file paths, use allowlists',
            'hardcoded_secrets': 'Use environment variables or secret management',
            'insecure_deserialization': 'Use safe serialization formats like JSON',
            'buffer_overflow': 'Use safe string functions (strncpy, snprintf)',
        }
        
        for finding in findings:
            vuln_type = finding['type']
            if vuln_type not in seen_types and vuln_type in rec_map:
                seen_types.add(vuln_type)
                recs.append(f"[{vuln_type.upper()}] {rec_map[vuln_type]}")
                
        return recs
    
    def provide_feedback(self, action: str, success: bool, details: str = ""):
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
        
        new_state = {**self.current_state, 'last_action': action, 'last_success': success}
        self.learner.learn(self.current_state, action, reward, new_state)
        self.current_state = new_state
        self.learner.decay_exploration()
        
    def get_stats(self) -> Dict[str, Any]:
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


# ============================================================================
# GUI COMPONENTS
# ============================================================================

class AnalysisWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int)
    
    def __init__(self, ai: HadesAI, code: str):
        super().__init__()
        self.ai = ai
        self.code = code
        
    def run(self):
        self.progress.emit(50)
        result = self.ai.analyze(self.code)
        self.progress.emit(100)
        self.finished.emit(result)


class HadesGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ai = HadesAI()
        self.init_ui()
        self.setup_timers()
        
    def init_ui(self):
        self.setWindowTitle("HADES AI - Self-Learning Pentesting Assistant")
        self.setMinimumSize(1200, 800)
        self.setStyleSheet(self._get_dark_style())
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Add tabs
        self.tabs.addTab(self._create_analysis_tab(), "🔍 Code Analysis")
        self.tabs.addTab(self._create_exploit_tab(), "💉 Exploit Generator")
        self.tabs.addTab(self._create_tools_tab(), "🛠️ Pentest Tools")
        self.tabs.addTab(self._create_learning_tab(), "🧠 Learning & Feedback")
        self.tabs.addTab(self._create_patterns_tab(), "📚 Patterns Database")
        self.tabs.addTab(self._create_stats_tab(), "📊 Statistics")
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Progress bar in status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.hide()
        self.status_bar.addPermanentWidget(self.progress_bar)
        
    def _get_dark_style(self) -> str:
        return """
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
            }
            QTabWidget::pane {
                border: 1px solid #3c3c3c;
                background-color: #252526;
            }
            QTabBar::tab {
                background-color: #2d2d2d;
                color: #d4d4d4;
                padding: 8px 16px;
                border: 1px solid #3c3c3c;
            }
            QTabBar::tab:selected {
                background-color: #1e1e1e;
                border-bottom: 2px solid #007acc;
            }
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #0d5a8c;
            }
            QPushButton:disabled {
                background-color: #3c3c3c;
                color: #6c6c6c;
            }
            QTextEdit, QPlainTextEdit, QLineEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 4px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QTreeWidget, QTableWidget, QListWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                alternate-background-color: #252526;
            }
            QTreeWidget::item:selected, QTableWidget::item:selected, QListWidget::item:selected {
                background-color: #094771;
            }
            QHeaderView::section {
                background-color: #2d2d2d;
                color: #d4d4d4;
                padding: 6px;
                border: 1px solid #3c3c3c;
            }
            QComboBox {
                background-color: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                padding: 4px;
                border-radius: 4px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QGroupBox {
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 12px;
            }
            QGroupBox::title {
                color: #569cd6;
                subcontrol-origin: margin;
                left: 10px;
            }
            QProgressBar {
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #007acc;
            }
            QMenuBar {
                background-color: #2d2d2d;
                color: #d4d4d4;
            }
            QMenuBar::item:selected {
                background-color: #094771;
            }
            QMenu {
                background-color: #2d2d2d;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
            }
            QMenu::item:selected {
                background-color: #094771;
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
            }
            QSplitter::handle {
                background-color: #3c3c3c;
            }
        """
        
    def _create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        open_action = QAction("Open File", self)
        open_action.triggered.connect(self._open_file)
        file_menu.addAction(open_action)
        
        save_action = QAction("Save Results", self)
        save_action.triggered.connect(self._save_results)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
    def _create_analysis_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Splitter for input/output
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Code input
        input_group = QGroupBox("Code Input")
        input_layout = QVBoxLayout(input_group)
        
        self.code_input = QPlainTextEdit()
        self.code_input.setPlaceholderText("Paste code here to analyze for vulnerabilities...")
        self.code_input.setFont(QFont("Consolas", 10))
        self.highlighter = PythonHighlighter(self.code_input.document())
        input_layout.addWidget(self.code_input)
        
        btn_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("🔍 Analyze Code")
        self.analyze_btn.clicked.connect(self._analyze_code)
        btn_layout.addWidget(self.analyze_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(lambda: self.code_input.clear())
        btn_layout.addWidget(self.clear_btn)
        
        input_layout.addLayout(btn_layout)
        splitter.addWidget(input_group)
        
        # Right: Results
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout(results_group)
        
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Type", "Severity", "Line", "Details"])
        self.results_tree.setAlternatingRowColors(True)
        self.results_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        results_layout.addWidget(self.results_tree)
        
        # Recommendations
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setMaximumHeight(150)
        self.recommendations_text.setPlaceholderText("Recommendations will appear here...")
        results_layout.addWidget(QLabel("Recommendations:"))
        results_layout.addWidget(self.recommendations_text)
        
        splitter.addWidget(results_group)
        splitter.setSizes([600, 600])
        
        layout.addWidget(splitter)
        return widget
        
    def _create_exploit_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Vulnerability type selector
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Vulnerability Type:"))
        
        self.vuln_type_combo = QComboBox()
        self.vuln_type_combo.addItems([
            'sql_injection', 'xss', 'command_injection', 'path_traversal'
        ])
        selector_layout.addWidget(self.vuln_type_combo)
        
        self.generate_exploit_btn = QPushButton("Generate Exploits")
        self.generate_exploit_btn.clicked.connect(self._generate_exploits)
        selector_layout.addWidget(self.generate_exploit_btn)
        
        selector_layout.addStretch()
        layout.addLayout(selector_layout)
        
        # Exploits table
        self.exploits_table = QTableWidget()
        self.exploits_table.setColumnCount(4)
        self.exploits_table.setHorizontalHeaderLabels(["Technique", "Payload", "Success Rate", "Notes"])
        self.exploits_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.exploits_table.setAlternatingRowColors(True)
        layout.addWidget(self.exploits_table)
        
        # Feedback section
        feedback_group = QGroupBox("Exploit Feedback (helps AI learn)")
        feedback_layout = QHBoxLayout(feedback_group)
        
        self.exploit_success_btn = QPushButton("✓ Exploit Worked")
        self.exploit_success_btn.setStyleSheet("background-color: #2ea043;")
        self.exploit_success_btn.clicked.connect(lambda: self._record_exploit_feedback(True))
        feedback_layout.addWidget(self.exploit_success_btn)
        
        self.exploit_fail_btn = QPushButton("✗ Exploit Failed")
        self.exploit_fail_btn.setStyleSheet("background-color: #da3633;")
        self.exploit_fail_btn.clicked.connect(lambda: self._record_exploit_feedback(False))
        feedback_layout.addWidget(self.exploit_fail_btn)
        
        layout.addWidget(feedback_group)
        
        return widget
        
    def _create_tools_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        
        # Left: Tool selector
        selector_group = QGroupBox("Available Tools")
        selector_layout = QVBoxLayout(selector_group)
        
        self.tools_list = QListWidget()
        for tool in self.ai.code_gen.list_available_tools():
            item = QListWidgetItem(tool.replace('_', ' ').title())
            item.setData(Qt.ItemDataRole.UserRole, tool)
            self.tools_list.addItem(item)
        self.tools_list.itemClicked.connect(self._show_tool)
        selector_layout.addWidget(self.tools_list)
        
        layout.addWidget(selector_group, 1)
        
        # Right: Tool code
        code_group = QGroupBox("Generated Code")
        code_layout = QVBoxLayout(code_group)
        
        self.tool_code = QPlainTextEdit()
        self.tool_code.setFont(QFont("Consolas", 10))
        self.tool_code.setReadOnly(True)
        self.tool_highlighter = PythonHighlighter(self.tool_code.document())
        code_layout.addWidget(self.tool_code)
        
        btn_layout = QHBoxLayout()
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.clicked.connect(self._copy_tool_code)
        btn_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("💾 Save to File")
        save_btn.clicked.connect(self._save_tool_code)
        btn_layout.addWidget(save_btn)
        
        code_layout.addLayout(btn_layout)
        layout.addWidget(code_group, 2)
        
        return widget
        
    def _create_learning_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # AI Decision section
        decision_group = QGroupBox("AI Decision Making")
        decision_layout = QVBoxLayout(decision_group)
        
        context_layout = QHBoxLayout()
        context_layout.addWidget(QLabel("Current Context:"))
        self.context_input = QLineEdit()
        self.context_input.setPlaceholderText('{"target": "example.com", "phase": "recon"}')
        context_layout.addWidget(self.context_input)
        decision_layout.addLayout(context_layout)
        
        self.decide_btn = QPushButton("🤖 Get AI Recommendation")
        self.decide_btn.clicked.connect(self._get_ai_decision)
        decision_layout.addWidget(self.decide_btn)
        
        self.decision_label = QLabel("Recommended action will appear here...")
        self.decision_label.setStyleSheet("font-size: 14px; padding: 10px;")
        decision_layout.addWidget(self.decision_label)
        
        layout.addWidget(decision_group)
        
        # Feedback section
        feedback_group = QGroupBox("Provide Feedback (Train the AI)")
        feedback_layout = QFormLayout(feedback_group)
        
        self.feedback_action = QComboBox()
        self.feedback_action.addItems(self.ai.learner.actions)
        feedback_layout.addRow("Action:", self.feedback_action)
        
        self.feedback_details = QLineEdit()
        self.feedback_details.setPlaceholderText("Details about what happened...")
        feedback_layout.addRow("Details:", self.feedback_details)
        
        feedback_btn_layout = QHBoxLayout()
        success_btn = QPushButton("✓ Success")
        success_btn.setStyleSheet("background-color: #2ea043;")
        success_btn.clicked.connect(lambda: self._submit_feedback(True))
        feedback_btn_layout.addWidget(success_btn)
        
        fail_btn = QPushButton("✗ Failed")
        fail_btn.setStyleSheet("background-color: #da3633;")
        fail_btn.clicked.connect(lambda: self._submit_feedback(False))
        feedback_btn_layout.addWidget(fail_btn)
        
        feedback_layout.addRow("Result:", feedback_btn_layout)
        layout.addWidget(feedback_group)
        
        # Learn new pattern section
        pattern_group = QGroupBox("Teach New Vulnerability Pattern")
        pattern_layout = QFormLayout(pattern_group)
        
        self.new_pattern_type = QComboBox()
        self.new_pattern_type.addItems([
            'sql_injection', 'xss', 'command_injection', 'path_traversal',
            'hardcoded_secrets', 'insecure_deserialization', 'buffer_overflow', 'custom'
        ])
        pattern_layout.addRow("Vulnerability Type:", self.new_pattern_type)
        
        self.new_pattern_regex = QLineEdit()
        self.new_pattern_regex.setPlaceholderText("Regex pattern to detect vulnerability...")
        pattern_layout.addRow("Pattern (Regex):", self.new_pattern_regex)
        
        learn_btn = QPushButton("📚 Teach Pattern")
        learn_btn.clicked.connect(self._learn_pattern)
        pattern_layout.addRow("", learn_btn)
        
        layout.addWidget(pattern_group)
        layout.addStretch()
        
        return widget
        
    def _create_patterns_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Patterns")
        refresh_btn.clicked.connect(self._refresh_patterns)
        layout.addWidget(refresh_btn)
        
        # Patterns table
        self.patterns_table = QTableWidget()
        self.patterns_table.setColumnCount(5)
        self.patterns_table.setHorizontalHeaderLabels([
            "Type", "Signature", "Confidence", "Occurrences", "Source"
        ])
        self.patterns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.patterns_table.setAlternatingRowColors(True)
        layout.addWidget(self.patterns_table)
        
        self._refresh_patterns()
        return widget
        
    def _create_stats_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Stats display
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setFont(QFont("Consolas", 11))
        layout.addWidget(self.stats_text)
        
        # Experience history
        history_group = QGroupBox("Recent Experiences")
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([
            "Timestamp", "Action", "Reward", "Category", "Result"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.setAlternatingRowColors(True)
        history_layout.addWidget(self.history_table)
        
        layout.addWidget(history_group)
        
        self._refresh_stats()
        return widget
        
    def setup_timers(self):
        # Auto-refresh stats every 10 seconds
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._refresh_stats)
        self.stats_timer.start(10000)
        
    # ========== Action Methods ==========
    
    def _analyze_code(self):
        code = self.code_input.toPlainText()
        if not code.strip():
            QMessageBox.warning(self, "Warning", "Please enter code to analyze")
            return
            
        self.progress_bar.show()
        self.progress_bar.setValue(0)
        self.analyze_btn.setEnabled(False)
        self.status_bar.showMessage("Analyzing code...")
        
        self.worker = AnalysisWorker(self.ai, code)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self._display_analysis_results)
        self.worker.start()
        
    def _display_analysis_results(self, result: Dict):
        self.results_tree.clear()
        self.progress_bar.hide()
        self.analyze_btn.setEnabled(True)
        
        # Add vulnerabilities to tree
        for vuln in result['vulnerabilities']:
            item = QTreeWidgetItem([
                vuln['type'],
                vuln['severity'],
                str(vuln['line']),
                vuln['match'][:50]
            ])
            
            # Color by severity
            severity_colors = {
                'CRITICAL': QColor("#ff6b6b"),
                'HIGH': QColor("#ffa94d"),
                'MEDIUM': QColor("#ffd43b"),
                'LOW': QColor("#69db7c")
            }
            color = severity_colors.get(vuln['severity'], QColor("#d4d4d4"))
            for i in range(4):
                item.setForeground(i, color)
                
            self.results_tree.addTopLevelItem(item)
            
        # Display recommendations
        recs = "\n".join(result['recommendations']) if result['recommendations'] else "No issues found!"
        self.recommendations_text.setText(recs)
        
        # Update status
        risk = result['risk_level']
        self.status_bar.showMessage(f"Analysis complete - Risk Level: {risk}")
        
    def _generate_exploits(self):
        vuln_type = self.vuln_type_combo.currentText()
        exploits = self.ai.exploit_gen.generate_exploit(vuln_type, {})
        
        self.exploits_table.setRowCount(len(exploits))
        for i, exploit in enumerate(exploits):
            self.exploits_table.setItem(i, 0, QTableWidgetItem(exploit['technique']))
            self.exploits_table.setItem(i, 1, QTableWidgetItem(exploit['payload']))
            self.exploits_table.setItem(i, 2, QTableWidgetItem(f"{exploit['success_rate']:.1%}"))
            self.exploits_table.setItem(i, 3, QTableWidgetItem(exploit['notes']))
            
    def _record_exploit_feedback(self, success: bool):
        row = self.exploits_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Select an exploit first")
            return
            
        vuln_type = self.vuln_type_combo.currentText()
        technique = self.exploits_table.item(row, 0).text()
        self.ai.exploit_gen.record_exploit_result(vuln_type, technique, success)
        
        QMessageBox.information(self, "Learned", f"Recorded {'success' if success else 'failure'} for {technique}")
        self._generate_exploits()  # Refresh to show updated success rates
        
    def _show_tool(self, item: QListWidgetItem):
        tool_name = item.data(Qt.ItemDataRole.UserRole)
        code = self.ai.code_gen.generate_tool(tool_name)
        self.tool_code.setPlainText(code)
        
    def _copy_tool_code(self):
        code = self.tool_code.toPlainText()
        if code:
            QApplication.clipboard().setText(code)
            self.status_bar.showMessage("Code copied to clipboard", 3000)
            
    def _save_tool_code(self):
        code = self.tool_code.toPlainText()
        if not code:
            return
            
        filename, _ = QFileDialog.getSaveFileName(self, "Save Tool", "", "Python Files (*.py)")
        if filename:
            with open(filename, 'w') as f:
                f.write(code)
            self.status_bar.showMessage(f"Saved to {filename}", 3000)
            
    def _get_ai_decision(self):
        try:
            context = json.loads(self.context_input.text()) if self.context_input.text() else {}
        except json.JSONDecodeError:
            context = {}
            
        self.ai.current_state = context
        action = self.ai.learner.choose_action(context)
        self.decision_label.setText(f"🎯 Recommended Action: {action.replace('_', ' ').title()}")
        self.decision_label.setStyleSheet("font-size: 16px; padding: 10px; color: #4ec9b0;")
        
    def _submit_feedback(self, success: bool):
        action = self.feedback_action.currentText()
        details = self.feedback_details.text()
        self.ai.provide_feedback(action, success, details)
        
        self.feedback_details.clear()
        self._refresh_stats()
        QMessageBox.information(self, "Learned", f"Feedback recorded for '{action}'")
        
    def _learn_pattern(self):
        vuln_type = self.new_pattern_type.currentText()
        pattern = self.new_pattern_regex.text()
        
        if not pattern:
            QMessageBox.warning(self, "Warning", "Please enter a regex pattern")
            return
            
        try:
            re.compile(pattern)
        except re.error as e:
            QMessageBox.critical(self, "Invalid Regex", str(e))
            return
            
        self.ai.vuln_detector.learn_pattern(vuln_type, pattern)
        self.new_pattern_regex.clear()
        self._refresh_patterns()
        QMessageBox.information(self, "Learned", f"New pattern added for {vuln_type}")
        
    def _refresh_patterns(self):
        patterns = self.ai.kb.get_patterns()
        
        # Add built-in patterns count
        builtin_count = sum(len(p) for p in self.ai.vuln_detector.VULN_PATTERNS.values())
        
        self.patterns_table.setRowCount(len(patterns) + builtin_count)
        
        row = 0
        # Built-in patterns
        for vuln_type, pats in self.ai.vuln_detector.VULN_PATTERNS.items():
            for pat in pats:
                self.patterns_table.setItem(row, 0, QTableWidgetItem(vuln_type))
                self.patterns_table.setItem(row, 1, QTableWidgetItem(pat[:50]))
                self.patterns_table.setItem(row, 2, QTableWidgetItem("1.0"))
                self.patterns_table.setItem(row, 3, QTableWidgetItem("-"))
                self.patterns_table.setItem(row, 4, QTableWidgetItem("Built-in"))
                row += 1
                
        # Learned patterns
        for pattern in patterns:
            self.patterns_table.setItem(row, 0, QTableWidgetItem(pattern.pattern_type))
            self.patterns_table.setItem(row, 1, QTableWidgetItem(pattern.signature[:50]))
            self.patterns_table.setItem(row, 2, QTableWidgetItem(f"{pattern.confidence:.2f}"))
            self.patterns_table.setItem(row, 3, QTableWidgetItem(str(pattern.occurrences)))
            self.patterns_table.setItem(row, 4, QTableWidgetItem("Learned"))
            row += 1
            
    def _refresh_stats(self):
        stats = self.ai.get_stats()
        
        stats_text = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    HADES AI LEARNING STATISTICS                   ║
╠══════════════════════════════════════════════════════════════════╣
║  Total Experiences:     {stats['total_experiences']:>8}                              ║
║  Patterns Learned:      {stats['patterns_learned']:>8}                              ║
║  Average Reward:        {stats['average_reward']:>8.3f}                              ║
║  Exploration Rate:      {stats['exploration_rate']:>8.1%}                              ║
║  Session Experiences:   {stats['session_experiences']:>8}                              ║
╠══════════════════════════════════════════════════════════════════╣
║  Experiences by Category:                                         ║"""
        
        for cat, count in stats.get('experiences_by_category', {}).items():
            stats_text += f"\n║    {cat:<20} {count:>6}                                  ║"
            
        stats_text += """
╚══════════════════════════════════════════════════════════════════╝
"""
        self.stats_text.setText(stats_text)
        
        # Update history table
        experiences = self.ai.kb.get_experiences(50)
        self.history_table.setRowCount(len(experiences))
        for i, exp in enumerate(experiences):
            self.history_table.setItem(i, 0, QTableWidgetItem(exp.timestamp.strftime("%Y-%m-%d %H:%M")))
            self.history_table.setItem(i, 1, QTableWidgetItem(exp.action_taken))
            
            reward_item = QTableWidgetItem(f"{exp.reward:+.2f}")
            reward_item.setForeground(QColor("#4ec9b0" if exp.reward > 0 else "#f14c4c"))
            self.history_table.setItem(i, 2, reward_item)
            
            self.history_table.setItem(i, 3, QTableWidgetItem(exp.category))
            self.history_table.setItem(i, 4, QTableWidgetItem(exp.result[:30] if exp.result else ""))
            
    def _open_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if filename:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                self.code_input.setPlainText(f.read())
            self.tabs.setCurrentIndex(0)
            
    def _save_results(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "JSON Files (*.json)")
        if filename:
            results = {
                'stats': self.ai.get_stats(),
                'patterns': len(self.ai.kb.get_patterns())
            }
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.status_bar.showMessage(f"Results saved to {filename}", 3000)
            
    def _show_about(self):
        QMessageBox.about(self, "About HADES AI", 
            "HADES AI - Self-Learning Pentesting Assistant\n\n"
            "A reinforcement learning-based AI that improves through experience.\n\n"
            "Features:\n"
            "• Code vulnerability analysis\n"
            "• Exploit generation with learning\n"
            "• Pentesting tool generation\n"
            "• Pattern learning from feedback\n"
            "• Q-learning based decision making\n\n"
            "For ethical/authorized use only."
        )


# ============================================================================
# MAIN ENTRY
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = HadesGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
