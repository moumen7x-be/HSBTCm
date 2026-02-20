#!/usr/bin/env python3
"""
?? HSBTCm ULTIMATE PRO - Advanced Binary Security Analyzer
Base de données complète + Analyses réelles 1600+ lignes
Analyse dynamique avancée avec strace, ltrace, gdb, radare2
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import os
import threading
import hashlib
import re
import tempfile
import json
import time
import psutil
import socket
import signal
from datetime import datetime
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib
matplotlib.use('Agg')

class HSBTCmPRO:
    def __init__(self, root):
        self.root = root
        self.setup_root()
        self.setup_styles()
        self.create_header()
        self.create_main_layout()
        self.current_file = None
        self.scanning = False
        self.dynamic_process = None
        self.analysis_thread = None
        
        # Bases de données complètes
        self.vulnerability_db = self.load_complete_vulnerability_database()
        self.memory_patterns = self.load_memory_patterns()
        self.code_patterns = self.load_code_patterns()
        self.dynamic_patterns = self.load_dynamic_patterns()
        self.suspicious_patterns = self.load_suspicious_patterns()
        self.detected_vulnerabilities = set()
        
    def setup_root(self):
        """Configure la fenêtre principale"""
        self.root.title("?? HSBTCm ULTIMATE PRO - Advanced Binary Security Analyzer")
        self.root.geometry("1000x800")
        self.root.configure(bg='#0a0a0a')
        self.root.minsize(900, 700)
        
    def setup_styles(self):
        """Configure les styles"""
        self.style = ttk.Style()
        
        self.colors = {
            'bg_dark': '#0a0a0a',
            'bg_panel': '#111111',
            'bg_darker': '#050505',
            'accent_green': '#00ff00',
            'accent_cyan': '#00ffff',
            'accent_red': '#ff0033',
            'accent_orange': '#ff6600',
            'accent_yellow': '#ffff00',
            'accent_purple': '#ff00ff',
            'text_primary': '#ffffff',
            'text_secondary': '#cccccc',
        }
        
        self.style.configure('Hacker.TFrame', background=self.colors['bg_dark'])
        self.style.configure('Panel.TFrame', background=self.colors['bg_panel'])
        self.style.configure('Dark.TLabelframe', 
                           background=self.colors['bg_panel'],
                           foreground=self.colors['accent_green'])
    
    def load_complete_vulnerability_database(self):
        """Charge une base de données complète de vulnérabilités"""
        return {
            # === VULNÉRABILITÉS STACK ===
            'stack_buffer_overflow': {
                'category': 'Stack',
                'severity': 'CRITICAL',
                'functions': ['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf'],
                'patterns': [r'buffer\[.*\]', r'char.*\[.*\]', r'alloca\('],
                'description': 'Buffer overflow on stack due to unsafe copy operations',
                'impact': 'Arbitrary code execution, control flow hijacking',
                'fix': 'Use strncpy, snprintf with bounds checking, avoid gets()',
                'cwe': 'CWE-121',
                'tools': ['objdump', 'gdb', 'valgrind']
            },
            'stack_overflow': {
                'category': 'Stack',
                'severity': 'HIGH', 
                'functions': ['recursive_function', 'large_local_arrays'],
                'patterns': [r'add.*esp.*0x', r'sub.*esp.*0x'],
                'description': 'Stack exhaustion through deep recursion or large allocations',
                'impact': 'Stack overflow, program crash',
                'fix': 'Limit recursion depth, use heap for large allocations',
                'cwe': 'CWE-674',
                'tools': ['gdb', 'strace']
            },
            
            # === VULNÉRABILITÉS HEAP ===
            'heap_buffer_overflow': {
                'category': 'Heap',
                'severity': 'HIGH',
                'functions': ['malloc', 'calloc', 'realloc', 'memcpy', 'strcpy'],
                'patterns': [r'malloc.*sizeof', r'memcpy', r'strcpy'],
                'description': 'Buffer overflow in heap-allocated memory',
                'impact': 'Memory corruption, arbitrary code execution',
                'fix': 'Bounds checking, use safe string functions',
                'cwe': 'CWE-122',
                'tools': ['valgrind', 'address-sanitizer']
            },
            'use_after_free': {
                'category': 'Heap', 
                'severity': 'HIGH',
                'functions': ['free', 'delete'],
                'patterns': [r'free.*use', r'dangling pointer'],
                'description': 'Use of memory after it has been freed',
                'impact': 'Memory corruption, code execution',
                'fix': 'Set pointers to NULL after free, use static analysis',
                'cwe': 'CWE-416',
                'tools': ['valgrind', 'address-sanitizer']
            },
            'double_free': {
                'category': 'Heap',
                'severity': 'HIGH',
                'functions': ['free'],
                'patterns': [r'free.*free', r'double free'],
                'description': 'Freeing memory that has already been freed',
                'impact': 'Heap corruption, arbitrary code execution',
                'fix': 'Track allocations, avoid double frees',
                'cwe': 'CWE-415',
                'tools': ['valgrind', 'address-sanitizer']
            },
            
            # === VULNÉRABILITÉS FORMAT STRING ===
            'format_string': {
                'category': 'Format String',
                'severity': 'CRITICAL',
                'functions': ['printf', 'sprintf', 'fprintf', 'snprintf', 'syslog'],
                'patterns': [r'printf\(.*\)', r'sprintf\(.*\)', r'%s%s%s'],
                'description': 'Format string vulnerability allowing memory access',
                'impact': 'Memory read/write, arbitrary code execution',
                'fix': 'Use constant format strings, validate input',
                'cwe': 'CWE-134',
                'tools': ['gdb', 'static-analysis']
            },
            
            # === VULNÉRABILITÉS INJECTION ===
            'code_injection': {
                'category': 'Injection',
                'severity': 'CRITICAL',
                'functions': ['system', 'popen', 'execve', 'execl', 'execvp'],
                'patterns': [r'system\(.*\)', r'popen\(.*\)', r'eval\(.*\)'],
                'description': 'Code injection through unsafe function calls',
                'impact': 'Arbitrary command execution',
                'fix': 'Avoid system calls with user input, use secure APIs',
                'cwe': 'CWE-78',
                'tools': ['strings', 'ltrace']
            },
            'command_injection': {
                'category': 'Injection',
                'severity': 'CRITICAL',
                'functions': ['system', 'popen'],
                'patterns': [r'system\(.*\)', r'popen\(.*\)'],
                'description': 'Command injection through user input',
                'impact': 'Arbitrary command execution',
                'fix': 'Input validation, use parameterized commands',
                'cwe': 'CWE-77',
                'tools': ['strings', 'static-analysis']
            },
            
            # === VULNÉRABILITÉS INTEGER ===
            'integer_overflow': {
                'category': 'Integer',
                'severity': 'HIGH',
                'functions': ['malloc', 'calloc', 'memcpy', 'strncpy'],
                'patterns': [r'size_t.*int', r'integer overflow'],
                'description': 'Integer operations causing unexpected behavior',
                'impact': 'Buffer overflow, memory corruption',
                'fix': 'Use safe integer operations, bounds checking',
                'cwe': 'CWE-190',
                'tools': ['static-analysis', 'sanitizers']
            },
            
            # === VULNÉRABILITÉS MÉMOIRE ===
            'null_pointer_dereference': {
                'category': 'Memory',
                'severity': 'HIGH',
                'functions': ['pointer_dereference'],
                'patterns': [r'null pointer', r'dereference'],
                'description': 'Dereferencing a null pointer',
                'impact': 'Segmentation fault, program crash',
                'fix': 'Validate pointers before use',
                'cwe': 'CWE-476',
                'tools': ['gdb', 'valgrind']
            },
            
            # === VULNÉRABILITÉS SÉCURITÉ ===
            'hardcoded_credentials': {
                'category': 'Security',
                'severity': 'HIGH',
                'functions': [],
                'patterns': [r'password', r'secret', r'api_key', r'token'],
                'description': 'Hardcoded passwords or credentials',
                'impact': 'Authentication bypass, information disclosure',
                'fix': 'Use secure credential storage, environment variables',
                'cwe': 'CWE-798',
                'tools': ['strings', 'binwalk']
            },
            'information_disclosure': {
                'category': 'Security',
                'severity': 'MEDIUM',
                'functions': ['printf', 'puts', 'fprintf'],
                'patterns': [r'debug information', r'error messages'],
                'description': 'Sensitive information disclosure in error messages',
                'impact': 'Information leakage, reconnaissance',
                'fix': 'Sanitize error messages, use production logging',
                'cwe': 'CWE-209',
                'tools': ['strings', 'ltrace']
            }
        }
    
    def load_memory_patterns(self):
        """Patterns spécifiques pour l'analyse mémoire"""
        return {
            'stack_frames': [r'push.*ebp', r'mov.*ebp,esp', r'sub.*esp,0x'],
            'heap_operations': [r'call.*malloc', r'call.*free', r'call.*realloc'],
            'memory_copy': [r'movsb', r'movsw', r'movsd', r'rep movs'],
            'buffer_access': [r'lea.*\[ebp-', r'lea.*\[esp+'],
            'return_ops': [r'ret', r'leave', r'pop.*ebp']
        }
    
    def load_code_patterns(self):
        """Patterns spécifiques pour l'analyse code"""
        return {
            'dangerous_calls': [r'call.*gets', r'call.*strcpy', r'call.*sprintf', r'call.*system'],
            'format_strings': [r'call.*printf', r'call.*fprintf', r'call.*sprintf'],
            'system_calls': [r'int 0x80', r'syscall', r'sysenter'],
            'injection_signs': [r'/bin/sh', r'execve', r'popen', r'system']
        }

    def load_dynamic_patterns(self):
        """Patterns pour l'analyse dynamique"""
        return {
            'suspicious_syscalls': ['ptrace', 'execve', 'fork', 'clone', 'kill', 'signal'],
            'network_operations': ['socket', 'bind', 'connect', 'listen', 'accept'],
            'file_operations': ['open', 'creat', 'unlink', 'chmod', 'chown'],
            'memory_operations': ['mprotect', 'mmap', 'brk', 'mremap']
        }

    def load_suspicious_patterns(self):
        """Patterns suspects pour l'analyse avancée"""
        return {
            'malicious_strings': [
                r'/bin/bash', r'/bin/sh', r'bash -i', r'nc -l', r'netcat',
                r'chmod 777', r'chmod +x', r'wget', r'curl', r'ssh',
                r'passwd', r'shadow', r'/etc/', r'/var/log', r'/tmp/',
                r'backdoor', r'rootkit', r'malware', r'virus', r'trojan'
            ],
            'crypto_patterns': [
                r'MD5', r'SHA1', r'RC4', r'DES', r'base64',
                r'crypto', r'encrypt', r'decrypt', r'key', r'iv'
            ],
            'obfuscation_patterns': [
                r'xor.*eax', r'rol', r'ror', r'shr', r'shl',
                r'magic', r'junk', r'garbage', r'obfuscate'
            ],
            'anti_debugging': [
                r'ptrace', r'fork', r'getpid', r'getppid',
                r'isatty', r'ttyname', r'ptrace.*PTRACE_TRACEME'
            ]
        }

    def create_header(self):
        """Crée l'en-tête optimisé"""
        header_frame = ttk.Frame(self.root, style='Hacker.TFrame', height=80)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        header_frame.pack_propagate(False)
        
        # Logo et titre
        title_frame = ttk.Frame(header_frame, style='Hacker.TFrame')
        title_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        main_title = tk.Label(title_frame,
                            text="HSBTCm ULTIMATE PRO",
                            font=('Courier New', 18, 'bold'),
                            fg=self.colors['accent_green'],
                            bg=self.colors['bg_dark'])
        main_title.pack()
        
        subtitle = tk.Label(title_frame,
                          text="Advanced Dynamic & Static Analysis - Real Results",
                          font=('Courier New', 10),
                          fg=self.colors['text_secondary'],
                          bg=self.colors['bg_dark'])
        subtitle.pack()
        
        # Status
        status_frame = ttk.Frame(header_frame, style='Hacker.TFrame')
        status_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        
        self.status_label = tk.Label(status_frame,
                                   text="?? READY",
                                   font=('Courier New', 12, 'bold'),
                                   fg=self.colors['accent_green'],
                                   bg=self.colors['bg_dark'])
        self.status_label.pack()

    def create_main_layout(self):
        """Crée le layout principal"""
        main_container = ttk.Frame(self.root, style='Hacker.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Configuration en deux colonnes
        main_container.columnconfigure(0, weight=3)
        main_container.columnconfigure(1, weight=2)
        main_container.rowconfigure(0, weight=1)
        
        # Panel gauche - Résultats
        left_frame = ttk.Frame(main_container, style='Panel.TFrame')
        left_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        self.setup_results_panel(left_frame)
        
        # Panel droit - Contrôles
        right_frame = ttk.Frame(main_container, style='Panel.TFrame')
        right_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))
        self.setup_control_panel(right_frame)

    def setup_results_panel(self, parent):
        """Configure le panel des résultats"""
        self.results_notebook = ttk.Notebook(parent)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Onglets principaux
        tabs = [
            ("?? Vulnerabilities", self.setup_vulnerabilities_tab),
            ("?? Static Analysis", self.setup_static_tab),
            ("?? Dynamic Analysis", self.setup_dynamic_tab),
            ("??? Advanced Scan", self.setup_advanced_tab),
            ("?? Full Report", self.setup_report_tab)
        ]
        
        for tab_name, setup_func in tabs:
            tab_frame = ttk.Frame(self.results_notebook, style='Panel.TFrame')
            self.results_notebook.add(tab_frame, text=tab_name)
            setup_func(tab_frame)

    def setup_vulnerabilities_tab(self, parent):
        """Onglet vulnérabilités détaillé"""
        # Treeview avec colonnes complètes
        columns = ('Severity', 'Category', 'Type', 'CWE', 'Description', 'Location')
        self.vuln_tree = ttk.Treeview(parent, columns=columns, show='headings', height=15)
        
        # Configuration des colonnes
        column_config = {
            'Severity': ('SEVERITY', 80),
            'Category': ('CATEGORY', 100),
            'Type': ('TYPE', 120),
            'CWE': ('CWE', 70),
            'Description': ('DESCRIPTION', 200),
            'Location': ('LOCATION', 150)
        }
        
        for col, (text, width) in column_config.items():
            self.vuln_tree.heading(col, text=text)
            self.vuln_tree.column(col, width=width)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_static_tab(self, parent):
        """Onglet analyse statique complet"""
        static_notebook = ttk.Notebook(parent)
        static_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sous-onglets statiques
        static_sections = [
            ("File Info", "file_info_text"),
            ("Strings", "strings_text"),
            ("Functions", "functions_text"),
            ("Security", "security_text"),
            ("Assembly", "assembly_text")
        ]
        
        for section_name, attr_name in static_sections:
            frame = ttk.Frame(static_notebook, style='Panel.TFrame')
            static_notebook.add(frame, text=section_name)
            text_widget = self.create_analysis_text(frame)
            setattr(self, attr_name, text_widget)

    def setup_dynamic_tab(self, parent):
        """Onglet analyse dynamique avancée"""
        dynamic_notebook = ttk.Notebook(parent)
        dynamic_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sous-onglets dynamiques
        dynamic_sections = [
            ("System Calls", "strace_text"),
            ("Library Calls", "ltrace_text"),
            ("Process Monitor", "process_text"),
            ("Network Analysis", "network_text"),
            ("GDB Analysis", "gdb_text"),
            ("Radare2", "radare_text")
        ]
        
        for section_name, attr_name in dynamic_sections:
            frame = ttk.Frame(dynamic_notebook, style='Panel.TFrame')
            dynamic_notebook.add(frame, text=section_name)
            text_widget = self.create_analysis_text(frame)
            setattr(self, attr_name, text_widget)
        
        # Contrôles d'analyse dynamique
        control_frame = ttk.Frame(parent, style='Panel.TFrame')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="?? Start Dynamic Analysis", 
                  command=self.start_dynamic_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="?? Stop Dynamic", 
                  command=self.stop_dynamic_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="?? Analyze Behavior", 
                  command=self.analyze_behavior).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="?? Real-time Monitor", 
                  command=self.start_realtime_monitor).pack(side=tk.LEFT, padx=2)

    def setup_advanced_tab(self, parent):
        """Onglet scan avancé"""
        advanced_notebook = ttk.Notebook(parent)
        advanced_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sous-onglets avancés
        advanced_sections = [
            ("Suspicious Patterns", "suspicious_text"),
            ("Memory Analysis", "memory_analysis_text"),
            ("Code Patterns", "code_patterns_text"),
            ("Entropy Analysis", "entropy_text"),
            ("YARA Rules", "yara_text")
        ]
        
        for section_name, attr_name in advanced_sections:
            frame = ttk.Frame(advanced_notebook, style='Panel.TFrame')
            advanced_notebook.add(frame, text=section_name)
            text_widget = self.create_analysis_text(frame)
            setattr(self, attr_name, text_widget)

    def setup_report_tab(self, parent):
        """Onglet rapport de sécurité"""
        self.report_text = scrolledtext.ScrolledText(parent,
                                                   wrap=tk.WORD,
                                                   bg=self.colors['bg_darker'],
                                                   fg=self.colors['text_primary'],
                                                   font=('Courier New', 9),
                                                   height=20)
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def create_analysis_text(self, parent):
        """Crée un widget texte pour l'analyse"""
        text_widget = scrolledtext.ScrolledText(parent,
                                              wrap=tk.WORD,
                                              bg=self.colors['bg_darker'],
                                              fg=self.colors['text_primary'],
                                              font=('Courier New', 8),
                                              height=8)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        return text_widget

    def setup_control_panel(self, parent):
        """Configure le panel de contrôle"""
        # === SECTION FICHIER ===
        file_frame = ttk.LabelFrame(parent, text="?? File Selection", 
                                  style='Dark.TLabelframe')
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Chemin fichier
        path_frame = ttk.Frame(file_frame, style='Panel.TFrame')
        path_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.file_var = tk.StringVar()
        file_entry = tk.Entry(path_frame, 
                             textvariable=self.file_var,
                             font=('Courier New', 9),
                             bg=self.colors['bg_darker'],
                             fg=self.colors['text_primary'])
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(path_frame, text="Browse", 
                  command=self.browse_file).pack(side=tk.RIGHT)
        
        # === SECTION ANALYSE ===
        analysis_frame = ttk.LabelFrame(parent, text="?? Analysis Options", 
                                      style='Dark.TLabelframe')
        analysis_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.analysis_options = {
            'Static Analysis': tk.BooleanVar(value=True),
            'Dynamic Analysis': tk.BooleanVar(value=True),
            'Advanced Scan': tk.BooleanVar(value=True),
            'Vulnerability Scan': tk.BooleanVar(value=True),
            'Real-time Monitoring': tk.BooleanVar(value=False),
            'Deep Binary Analysis': tk.BooleanVar(value=False)
        }
        
        for option, var in self.analysis_options.items():
            ttk.Checkbutton(analysis_frame, text=option,
                          variable=var).pack(anchor=tk.W, pady=2, padx=5)
        
        # === SECTION ACTIONS ===
        action_frame = ttk.LabelFrame(parent, text="? Actions", 
                                    style='Dark.TLabelframe')
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(action_frame, text="?? Start Complete Analysis", 
                  command=self.start_complete_analysis).pack(fill=tk.X, pady=2)
        
        ttk.Button(action_frame, text="?? Stop Analysis", 
                  command=self.stop_analysis).pack(fill=tk.X, pady=2)
        
        ttk.Button(action_frame, text="?? Export Full Report", 
                  command=self.export_results).pack(fill=tk.X, pady=2)
        
        ttk.Button(action_frame, text="?? Clear All", 
                  command=self.clear_results).pack(fill=tk.X, pady=2)
        
        # Barre de progression
        self.progress = ttk.Progressbar(action_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        self.scan_status = tk.StringVar(value="Ready for analysis")
        status_label = tk.Label(action_frame, textvariable=self.scan_status,
                              font=('Courier New', 8),
                              fg=self.colors['accent_green'],
                              bg=self.colors['bg_panel'])
        status_label.pack()
        
        # === SECTION INFORMATIONS ===
        info_frame = ttk.LabelFrame(parent, text="?? File Information", 
                                  style='Dark.TLabelframe')
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.info_text = scrolledtext.ScrolledText(info_frame,
                                                 wrap=tk.WORD,
                                                 bg=self.colors['bg_darker'],
                                                 fg=self.colors['text_secondary'],
                                                 font=('Courier New', 8),
                                                 height=8)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # ==================== ANALYSES RÉELLES AVANCÉES ====================

    def browse_file(self):
        """Sélection du fichier"""
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[("Executables", "*"), ("All files", "*.*")]
        )
        
        if filename:
            self.file_var.set(filename)
            self.current_file = filename
            self.update_status("?? File selected - Ready for real analysis")
            self.show_file_info()

    def show_file_info(self):
        """Affiche les informations réelles du fichier"""
        if not self.current_file:
            return
            
        try:
            file_size = os.path.getsize(self.current_file)
            file_type = self.get_file_type()
            file_hash = self.calculate_hashes()
            permissions = self.get_file_permissions()
            entropy = self.calculate_entropy()
            
            info = f"""?? REAL FILE INFORMATION - DETAILED ANALYSIS

File: {os.path.basename(self.current_file)}
Path: {self.current_file}
Size: {file_size:,} bytes
Type: {file_type}
Permissions: {permissions}
Entropy: {entropy:.2f} (Higher = potential packed/encrypted)
MD5: {file_hash.get('MD5', 'N/A')}
SHA256: {file_hash.get('SHA256', 'N/A')}

?? Ready for comprehensive real binary analysis
with advanced dynamic and static techniques."""

            self.info_text.config(state=tk.NORMAL)
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(1.0, info)
            self.info_text.config(state=tk.DISABLED)
            
        except Exception as e:
            self.show_error("File Info Error", str(e))

    def get_file_type(self):
        """Détection réelle du type de fichier"""
        try:
            result = subprocess.run(['file', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def get_file_permissions(self):
        """Récupère les permissions réelles du fichier"""
        try:
            stat_info = os.stat(self.current_file)
            permissions = oct(stat_info.st_mode)[-3:]
            return permissions
        except:
            return "Unknown"

    def calculate_entropy(self):
        """Calcule l'entropie du fichier pour détection de packing"""
        try:
            with open(self.current_file, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0
                
            entropy = 0
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * (p_x.bit_length() - 1)
            
            return entropy
        except:
            return 0

    def calculate_hashes(self):
        """Calcule les hashs réels du fichier"""
        hashers = {
            'MD5': hashlib.md5(),
            'SHA256': hashlib.sha256()
        }
        
        try:
            with open(self.current_file, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            
            return {name: hasher.hexdigest() for name, hasher in hashers.items()}
        except Exception as e:
            return {'MD5': f'Error: {str(e)}', 'SHA256': f'Error: {str(e)}'}

    def start_complete_analysis(self):
        """Démarre l'analyse complète réelle"""
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a binary file")
            return
            
        if not os.path.exists(self.current_file):
            messagebox.showerror("Error", "Selected file does not exist")
            return
            
        self.scanning = True
        self.analysis_thread = threading.Thread(target=self._perform_real_analysis)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()

    def _perform_real_analysis(self):
        """Exécute l'analyse réelle complète"""
        try:
            start_time = datetime.now()
            self.progress.start()
            
            # Réinitialiser les résultats
            self.clear_results()
            all_vulnerabilities = []
            
            # 1. Analyse statique avancée
            if self.analysis_options['Static Analysis'].get():
                self.scan_status.set("?? Starting advanced static analysis...")
                static_results = self.perform_advanced_static_analysis()
                all_vulnerabilities.extend(static_results['vulnerabilities'])
                self.update_static_views(static_results)
            
            # 2. Scan de vulnérabilités
            if self.analysis_options['Vulnerability Scan'].get():
                self.scan_status.set("?? Scanning for vulnerabilities with database...")
                vuln_results = self.perform_advanced_vulnerability_scan()
                all_vulnerabilities.extend(vuln_results)
            
            # 3. Analyse dynamique avancée
            if self.analysis_options['Dynamic Analysis'].get():
                self.scan_status.set("?? Starting advanced dynamic analysis...")
                dynamic_results = self.perform_advanced_dynamic_analysis()
                all_vulnerabilities.extend(dynamic_results['vulnerabilities'])
                self.update_dynamic_views(dynamic_results)
            
            # 4. Scan avancé
            if self.analysis_options['Advanced Scan'].get():
                self.scan_status.set("??? Performing advanced pattern analysis...")
                advanced_results = self.perform_advanced_scan()
                all_vulnerabilities.extend(advanced_results['vulnerabilities'])
                self.update_advanced_views(advanced_results)
            
            # 5. Analyse binaire profonde
            if self.analysis_options['Deep Binary Analysis'].get():
                self.scan_status.set("?? Deep binary analysis...")
                deep_results = self.perform_deep_binary_analysis()
                all_vulnerabilities.extend(deep_results)
            
            # Éliminer les doublons
            unique_vulnerabilities = self.remove_duplicate_vulnerabilities(all_vulnerabilities)
            
            # Calcul des métriques
            analysis_time = (datetime.now() - start_time).total_seconds()
            metrics = self.calculate_comprehensive_metrics(unique_vulnerabilities, analysis_time)
            
            # Mise à jour finale
            self.root.after(0, self._update_final_results, unique_vulnerabilities, metrics)
            self.scan_status.set(f"? Complete analysis finished in {analysis_time:.1f}s")
            
        except Exception as e:
            self.scan_status.set(f"? Analysis failed: {str(e)}")
            self.show_error("Analysis Error", str(e))
        finally:
            self.progress.stop()
            self.scanning = False

    def perform_advanced_static_analysis(self):
        """Analyse statique avancée réelle"""
        results = {
            'file_info': "",
            'strings': "",
            'functions': "", 
            'security': "",
            'assembly': "",
            'vulnerabilities': []
        }
        
        try:
            # Informations fichier détaillées
            results['file_info'] = self.get_detailed_file_info()
            
            # Analyse des strings avancée
            results['strings'] = self.analyze_strings_advanced()
            
            # Analyse des fonctions détaillée
            results['functions'] = self.analyze_functions_detailed()
            
            # Analyse de sécurité complète
            results['security'] = self.analyze_security_comprehensive()
            
            # Analyse assembleur
            results['assembly'] = self.analyze_assembly()
            
        except Exception as e:
            results['file_info'] = f"Static analysis error: {str(e)}"
        
        return results

    def get_detailed_file_info(self):
        """Informations détaillées du fichier - RÉEL"""
        info = "?? DETAILED FILE ANALYSIS - REAL RESULTS\n"
        info += "=" * 60 + "\n\n"
        
        try:
            # Command file détaillée
            result = subprocess.run(['file', '-b', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            info += f"File Type: {result.stdout.strip()}\n"
            
            # Size avec analyse
            size = os.path.getsize(self.current_file)
            info += f"File Size: {size:,} bytes\n"
            
            # Readelf header complet
            result = subprocess.run(['readelf', '-h', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            info += f"\nELF Header Analysis:\n{result.stdout}\n"
            
            # Sections détaillées
            result = subprocess.run(['readelf', '-S', '--wide', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            info += f"Sections Analysis:\n{result.stdout}\n"
            
            # Segments
            result = subprocess.run(['readelf', '-l', '--wide', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            info += f"Program Headers:\n{result.stdout}\n"
            
        except Exception as e:
            info += f"Error in detailed analysis: {str(e)}\n"
        
        return info

    def analyze_strings_advanced(self):
        """Analyse réelle avancée des strings"""
        strings_info = "?? ADVANCED STRINGS ANALYSIS - REAL RESULTS\n"
        strings_info += "=" * 60 + "\n\n"
        
        try:
            # Strings avec différentes longueurs minimales
            for min_len in [4, 8, 12]:
                result = subprocess.run(['strings', f'-n{min_len}', '-a', self.current_file], 
                                      capture_output=True, text=True, timeout=20)
                lines = [line for line in result.stdout.split('\n') if line.strip()]
                strings_info += f"Strings (min {min_len} chars): {len(lines)} found\n"
                
                # Analyse des strings suspects
                suspicious_categories = {
                    'Command Injection': ['/bin/sh', 'bash', 'system', 'execve', 'popen'],
                    'Network': ['socket', 'bind', 'connect', '127.0.0.1', '0.0.0.0'],
                    'File System': ['/etc/passwd', '/etc/shadow', '/tmp/', '/dev/'],
                    'Suspicious': ['backdoor', 'rootkit', 'malware', 'virus', 'trojan'],
                    'Crypto': ['md5', 'sha1', 'base64', 'crypto', 'encrypt']
                }
                
                for category, patterns in suspicious_categories.items():
                    found = []
                    for line in lines:
                        if any(pattern in line.lower() for pattern in patterns):
                            found.append(line)
                    
                    if found:
                        strings_info += f"\n{category} ({len(found)}):\n"
                        for s in found[:5]:  # Premier 5 seulement
                            strings_info += f"  - {s}\n"
                
                strings_info += "\n" + "-" * 40 + "\n"
                
        except Exception as e:
            strings_info += f"Error in strings analysis: {str(e)}\n"
        
        return strings_info

    def analyze_functions_detailed(self):
        """Analyse réelle détaillée des fonctions"""
        functions_info = "?? DETAILED FUNCTIONS ANALYSIS - REAL RESULTS\n"
        functions_info += "=" * 60 + "\n\n"
        
        try:
            # Symbols avec nm
            result = subprocess.run(['nm', '-D', '--defined-only', self.current_file], 
                                  capture_output=True, text=True, timeout=15)
            symbols = result.stdout
            functions_info += f"Dynamic Symbols:\n{symbols}\n"
            
            # Objdump des fonctions détaillé
            result = subprocess.run(['objdump', '-t', '--demangle', self.current_file], 
                                  capture_output=True, text=True, timeout=20)
            functions_info += f"Functions from objdump (first 50):\n"
            functions_info += '\n'.join(result.stdout.split('\n')[:50]) + "\n...\n"
            
            # Fonctions importées
            result = subprocess.run(['objdump', '-T', self.current_file], 
                                  capture_output=True, text=True, timeout=15)
            functions_info += f"Imported Functions:\n{result.stdout}\n"
            
        except Exception as e:
            functions_info += f"Error in functions analysis: {str(e)}\n"
        
        return functions_info

    def analyze_security_comprehensive(self):
        """Analyse de sécurité complète réelle"""
        security_info = "??? COMPREHENSIVE SECURITY ANALYSIS - REAL RESULTS\n"
        security_info += "=" * 60 + "\n\n"
        
        try:
            # Checksec-like analysis manuelle
            result = subprocess.run(['readelf', '-l', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            segments = result.stdout
            
            # Vérifications de sécurité avancées
            security_checks = {
                'PIE/ASLR': 'DYN' in segments,
                'NX/DEP': 'GNU_STACK' in segments and 'RWE' not in segments,
                'RELRO Full': 'BIND_NOW' in segments,
                'RELRO Partial': 'RELRO' in segments and 'BIND_NOW' not in segments,
                'Stack Canary': self.check_stack_canary(),
                'Fortify Source': self.check_fortify_source(),
                'RPATH/RUNPATH': self.check_rpath()
            }
            
            security_info += "SECURITY PROTECTIONS STATUS:\n"
            for check, result in security_checks.items():
                status = "? ENABLED" if result else "? DISABLED"
                color = self.colors['accent_green'] if result else self.colors['accent_red']
                security_info += f"{check}: {status}\n"
            
            security_info += f"\nDetailed Segment Analysis:\n{segments}\n"
            
            # Analyse des protections manquantes
            if not security_checks['PIE/ASLR']:
                security_info += "\n??  WARNING: PIE/ASLR not enabled - Memory addresses predictable\n"
            if not security_checks['NX/DEP']:
                security_info += "??  WARNING: NX/DEP not enabled - Code execution on stack/heap possible\n"
            if not security_checks['Stack Canary']:
                security_info += "??  WARNING: Stack canary not found - Buffer overflow protection missing\n"
                
        except Exception as e:
            security_info += f"Error in security analysis: {str(e)}\n"
        
        return security_info

    def check_stack_canary(self):
        """Vérifie la présence de stack canary"""
        try:
            result = subprocess.run(['readelf', '-s', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            symbols = result.stdout
            return any(x in symbols for x in ['__stack_chk_fail', '__stack_chk_guard'])
        except:
            return False

    def check_fortify_source(self):
        """Vérifie Fortify Source"""
        try:
            result = subprocess.run(['readelf', '-s', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            symbols = result.stdout
            return any('_chk' in symbol for symbol in symbols.split('\n'))
        except:
            return False

    def check_rpath(self):
        """Vérifie RPATH/RUNPATH"""
        try:
            result = subprocess.run(['readelf', '-d', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            dynamic = result.stdout
            return 'RPATH' in dynamic or 'RUNPATH' in dynamic
        except:
            return False

    def analyze_assembly(self):
        """Analyse assembleur réelle"""
        assembly_info = "?? ASSEMBLY CODE ANALYSIS - REAL RESULTS\n"
        assembly_info += "=" * 60 + "\n\n"
        
        try:
            # Objdump désassemblage
            result = subprocess.run(['objdump', '-d', '--no-show-raw-insn', 
                                   '--visualize-jumps=extended-color', self.current_file],
                                  capture_output=True, text=True, timeout=30)
            assembly_info += "Disassembly (first 200 lines):\n"
            assembly_info += '\n'.join(result.stdout.split('\n')[:200]) + "\n...\n"
            
        except Exception as e:
            assembly_info += f"Error in assembly analysis: {str(e)}\n"
        
        return assembly_info

    def perform_advanced_vulnerability_scan(self):
        """Scan de vulnérabilités avancé avec base de données"""
        vulnerabilities = []
        
        try:
            # Analyse avec objdump pour le code
            result = subprocess.run(['objdump', '-d', self.current_file], 
                                  capture_output=True, text=True, timeout=45)
            assembly_code = result.stdout
            
            # Recherche dans la base de données de vulnérabilités
            for vuln_id, vuln_data in self.vulnerability_db.items():
                # Vérifier les fonctions dangereuses dans le code
                for func in vuln_data['functions']:
                    if f'call' in assembly_code and func in assembly_code:
                        vulnerabilities.append(self.create_vulnerability_entry(
                            vuln_data['category'],
                            f'Unsafe {func}',
                            vuln_data['severity'],
                            vuln_data['cwe'],
                            vuln_data['description'],
                            'Code section',
                            vuln_data['fix']
                        ))
                
                # Vérifier les patterns dans le code
                for pattern in vuln_data['patterns']:
                    if re.search(pattern, assembly_code, re.IGNORECASE):
                        vulnerabilities.append(self.create_vulnerability_entry(
                            vuln_data['category'],
                            vuln_id.replace('_', ' ').title(),
                            vuln_data['severity'],
                            vuln_data['cwe'],
                            vuln_data['description'],
                            'Code pattern',
                            vuln_data['fix']
                        ))
            
            # Analyse des strings pour vulnérabilités
            result = subprocess.run(['strings', '-a', self.current_file], 
                                  capture_output=True, text=True, timeout=20)
            strings_output = result.stdout
            
            # Recherche de patterns suspects dans les strings
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, strings_output, re.IGNORECASE):
                        vulnerabilities.append(self.create_vulnerability_entry(
                            'Security',
                            f'Suspicious {category}',
                            'MEDIUM' if category == 'crypto_patterns' else 'HIGH',
                            'CWE-798',
                            f'Potential {category} detected in binary',
                            'Strings section',
                            'Remove or obfuscate sensitive strings'
                        ))
                    
        except Exception as e:
            vulnerabilities.append(self.create_vulnerability_entry(
                'Analysis Error',
                'Vulnerability Scan Failed',
                'LOW',
                'N/A',
                f'Vulnerability scan error: {str(e)}',
                'Scanning process',
                'Check binary accessibility'
            ))
        
        return vulnerabilities

    def perform_advanced_dynamic_analysis(self):
        """Analyse dynamique avancée réelle"""
        results = {
            'strace': "",
            'ltrace': "",
            'process': "",
            'network': "",
            'gdb': "",
            'radare': "",
            'vulnerabilities': []
        }
        
        try:
            # Strace avancé - appels système
            self.scan_status.set("?? Running advanced strace...")
            result = subprocess.run(['timeout', '10', 'strace', '-f', '-e', 'trace=all', 
                                   self.current_file], 
                                  capture_output=True, text=True, timeout=15)
            results['strace'] = f"Advanced System Calls Analysis:\n{result.stderr}"
            results['vulnerabilities'].extend(self.analyze_strace_results(result.stderr))
            
            # Ltrace avancé - appels bibliothèque
            self.scan_status.set("?? Running advanced ltrace...")
            result = subprocess.run(['timeout', '10', 'ltrace', '-f', '-C', self.current_file], 
                                  capture_output=True, text=True, timeout=15)
            results['ltrace'] = f"Advanced Library Calls Analysis:\n{result.stderr}"
            results['vulnerabilities'].extend(self.analyze_ltrace_results(result.stderr))
            
            # Analyse processus avancée
            results['process'] = self.analyze_process_advanced()
            
            # Analyse réseau
            results['network'] = self.analyze_network_behavior()
            
            # Analyse GDB
            results['gdb'] = self.perform_gdb_analysis()
            
            # Analyse Radare2
            results['radare'] = self.perform_radare2_analysis()
            
        except Exception as e:
            results['strace'] = f"Dynamic analysis error: {str(e)}"
        
        return results

    def analyze_strace_results(self, strace_output):
        """Analyse les résultats strace pour vulnérabilités"""
        vulnerabilities = []
        
        suspicious_syscalls = {
            'ptrace': 'Potential anti-debugging detected',
            'execve': 'Process execution detected',
            'fork': 'Process forking detected',
            'chmod': 'File permission modification',
            'unlink': 'File deletion operation'
        }
        
        for syscall, description in suspicious_syscalls.items():
            if syscall in strace_output:
                vulnerabilities.append(self.create_vulnerability_entry(
                    'Dynamic Analysis',
                    f'Suspicious syscall: {syscall}',
                    'MEDIUM',
                    'CWE-749',
                    description,
                    'Runtime behavior',
                    'Review program behavior'
                ))
        
        return vulnerabilities

    def analyze_ltrace_results(self, ltrace_output):
        """Analyse les résultats ltrace pour vulnérabilités"""
        vulnerabilities = []
        
        dangerous_libcalls = {
            'system': 'CRITICAL - Command execution',
            'gets': 'CRITICAL - Unsafe input',
            'strcpy': 'HIGH - Unsafe string copy',
            'sprintf': 'HIGH - Format string vulnerability risk'
        }
        
        for libcall, risk in dangerous_libcalls.items():
            if libcall in ltrace_output:
                severity = 'CRITICAL' if 'CRITICAL' in risk else 'HIGH'
                vulnerabilities.append(self.create_vulnerability_entry(
                    'Dynamic Analysis',
                    f'Dangerous library call: {libcall}',
                    severity,
                    'CWE-676',
                    risk,
                    'Runtime behavior',
                    f'Replace {libcall} with safe alternative'
                ))
        
        return vulnerabilities

    def analyze_process_advanced(self):
        """Analyse processus avancée"""
        process_info = "??? ADVANCED PROCESS ANALYSIS - REAL RESULTS\n"
        process_info += "=" * 60 + "\n\n"
        
        try:
            # Lancer le processus avec monitoring
            process = subprocess.Popen([self.current_file], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            # Monitorer pendant 3 secondes
            time.sleep(3)
            
            # Obtenir les informations détaillées
            try:
                proc_info = psutil.Process(process.pid)
                
                process_info += f"Process ID: {process.pid}\n"
                process_info += f"Status: {proc_info.status()}\n"
                process_info += f"CPU %: {proc_info.cpu_percent()}\n"
                process_info += f"Memory RSS: {proc_info.memory_info().rss / 1024 / 1024:.1f} MB\n"
                process_info += f"Memory VMS: {proc_info.memory_info().vms / 1024 / 1024:.1f} MB\n"
                process_info += f"Create Time: {datetime.fromtimestamp(proc_info.create_time())}\n"
                
                # Connexions réseau
                connections = proc_info.connections()
                if connections:
                    process_info += f"\nNetwork Connections ({len(connections)}):\n"
                    for conn in connections[:5]:  # Premier 5 seulement
                        process_info += f"  - {conn.laddr} -> {conn.raddr if conn.raddr else 'Listening'}\n"
                
                # Threads
                threads = proc_info.threads()
                if threads:
                    process_info += f"\nThreads: {len(threads)}\n"
                
                # Fichiers ouverts
                open_files = proc_info.open_files()
                if open_files:
                    process_info += f"\nOpen Files ({len(open_files)}):\n"
                    for file in open_files[:5]:
                        process_info += f"  - {file.path}\n"
                
            except psutil.NoSuchProcess:
                process_info += "Process terminated already\n"
            
            # Tuer le processus
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            
            # Capturer la sortie
            stdout, stderr = process.communicate()
            if stdout:
                process_info += f"\nStdout:\n{stdout[:500]}\n"
            if stderr:
                process_info += f"\nStderr:\n{stderr[:500]}\n"
                
        except Exception as e:
            process_info += f"Process analysis error: {str(e)}\n"
        
        return process_info

    def analyze_network_behavior(self):
        """Analyse du comportement réseau"""
        network_info = "?? NETWORK BEHAVIOR ANALYSIS - REAL RESULTS\n"
        network_info += "=" * 60 + "\n\n"
        
        try:
            # Utiliser netstat ou ss pour détecter les connexions
            for cmd in [['ss', '-tulpn'], ['netstat', '-tulpn']]:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        network_info += f"Network sockets ({cmd[0]}):\n{result.stdout}\n"
                        break
                except:
                    continue
            
            # Test de connexion sortante
            network_info += "\nOutbound connection test:\n"
            try:
                # Tenter une connexion HTTP simple
                import urllib.request
                with urllib.request.urlopen('http://www.google.com', timeout=5) as response:
                    network_info += "Outbound HTTP: OK\n"
            except:
                network_info += "Outbound HTTP: Blocked or no network\n"
                
        except Exception as e:
            network_info += f"Network analysis error: {str(e)}\n"
        
        return network_info

    def perform_gdb_analysis(self):
        """Analyse GDB avancée"""
        gdb_info = "?? GDB ADVANCED ANALYSIS - REAL RESULTS\n"
        gdb_info += "=" * 60 + "\n\n"
        
        try:
            # Script GDB pour analyse de sécurité
            gdb_script = """
set pagination off
info functions
checksec
quit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(gdb_script)
                gdb_script_file = f.name
            
            result = subprocess.run(['gdb', '--batch', '-x', gdb_script_file, 
                                   self.current_file],
                                  capture_output=True, text=True, timeout=30)
            
            gdb_info += result.stdout
            
            # Nettoyer
            os.unlink(gdb_script_file)
            
        except Exception as e:
            gdb_info += f"GDB analysis error: {str(e)}\n"
        
        return gdb_info

    def perform_radare2_analysis(self):
        """Analyse Radare2 avancée"""
        radare_info = "?? RADARE2 ADVANCED ANALYSIS - REAL RESULTS\n"
        radare_info += "=" * 60 + "\n\n"
        
        try:
            # Commandes Radare2 pour analyse de sécurité
            r2_script = """
aaa
ie
iS
izz
pdf @ main
is~FUNC
q
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.r2', delete=False) as f:
                f.write(r2_script)
                r2_script_file = f.name
            
            result = subprocess.run(['r2', '-n', '-q', '-i', r2_script_file, 
                                   self.current_file],
                                  capture_output=True, text=True, timeout=30)
            
            radare_info += result.stdout
            
            # Nettoyer
            os.unlink(r2_script_file)
            
        except Exception as e:
            radare_info += f"Radare2 analysis error: {str(e)}\n"
        
        return radare_info

    def perform_advanced_scan(self):
        """Scan avancé avec patterns complexes"""
        results = {
            'suspicious': "",
            'memory': "",
            'code_patterns': "",
            'entropy': "",
            'yara': "",
            'vulnerabilities': []
        }
        
        try:
            # Analyse des patterns suspects
            results['suspicious'] = self.analyze_suspicious_patterns()
            
            # Analyse mémoire avancée
            results['memory'] = self.analyze_memory_patterns()
            
            # Analyse des patterns de code
            results['code_patterns'] = self.analyze_code_patterns_advanced()
            
            # Analyse d'entropie
            results['entropy'] = self.analyze_entropy_detailed()
            
            # Analyse YARA (si disponible)
            results['yara'] = self.perform_yara_analysis()
            
        except Exception as e:
            results['suspicious'] = f"Advanced scan error: {str(e)}"
        
        return results

    def analyze_suspicious_patterns(self):
        """Analyse des patterns suspects avancée"""
        suspicious_info = "??? SUSPICIOUS PATTERNS ANALYSIS - REAL RESULTS\n"
        suspicious_info += "=" * 60 + "\n\n"
        
        try:
            # Extraire toutes les strings
            result = subprocess.run(['strings', '-a', self.current_file], 
                                  capture_output=True, text=True, timeout=20)
            all_strings = result.stdout
            
            # Analyser chaque catégorie de patterns suspects
            for category, patterns in self.suspicious_patterns.items():
                found_patterns = []
                for pattern in patterns:
                    matches = re.findall(pattern, all_strings, re.IGNORECASE)
                    found_patterns.extend(matches)
                
                if found_patterns:
                    suspicious_info += f"{category.upper()} ({len(found_patterns)} found):\n"
                    for pattern in set(found_patterns[:10]):  # Dédupliquer et limiter
                        suspicious_info += f"  - {pattern}\n"
                    suspicious_info += "\n"
            
            if not any(len(patterns) > 0 for patterns in self.suspicious_patterns.values()):
                suspicious_info += "No suspicious patterns detected.\n"
                
        except Exception as e:
            suspicious_info += f"Suspicious patterns analysis error: {str(e)}\n"
        
        return suspicious_info

    def analyze_memory_patterns(self):
        """Analyse des patterns mémoire"""
        memory_info = "?? MEMORY PATTERNS ANALYSIS - REAL RESULTS\n"
        memory_info += "=" * 60 + "\n\n"
        
        try:
            # Désassemblage pour analyse mémoire
            result = subprocess.run(['objdump', '-d', self.current_file], 
                                  capture_output=True, text=True, timeout=30)
            assembly = result.stdout
            
            memory_info += "Memory-related patterns found:\n"
            
            for pattern_type, patterns in self.memory_patterns.items():
                found = []
                for pattern in patterns:
                    if re.search(pattern, assembly, re.IGNORECASE):
                        found.append(pattern)
                
                if found:
                    memory_info += f"\n{pattern_type}:\n"
                    for p in found[:5]:
                        memory_info += f"  - {p}\n"
            
        except Exception as e:
            memory_info += f"Memory patterns analysis error: {str(e)}\n"
        
        return memory_info

    def analyze_code_patterns_advanced(self):
        """Analyse avancée des patterns de code"""
        code_info = "?? ADVANCED CODE PATTERNS ANALYSIS - REAL RESULTS\n"
        code_info += "=" * 60 + "\n\n"
        
        try:
            result = subprocess.run(['objdump', '-d', self.current_file], 
                                  capture_output=True, text=True, timeout=30)
            assembly = result.stdout
            
            code_info += "Code patterns analysis:\n"
            
            for pattern_type, patterns in self.code_patterns.items():
                matches = []
                for pattern in patterns:
                    count = len(re.findall(pattern, assembly, re.IGNORECASE))
                    if count > 0:
                        matches.append(f"{pattern}: {count} occurrences")
                
                if matches:
                    code_info += f"\n{pattern_type}:\n"
                    for match in matches[:5]:
                        code_info += f"  - {match}\n"
            
        except Exception as e:
            code_info += f"Code patterns analysis error: {str(e)}\n"
        
        return code_info

    def analyze_entropy_detailed(self):
        """Analyse d'entropie détaillée"""
        entropy_info = "?? DETAILED ENTROPY ANALYSIS - REAL RESULTS\n"
        entropy_info += "=" * 60 + "\n\n"
        
        try:
            with open(self.current_file, 'rb') as f:
                data = f.read()
            
            # Analyser l'entropie par sections
            entropy_info += f"Overall file entropy: {self.calculate_entropy():.4f}\n\n"
            
            # Entropie des différentes parties du fichier
            sections = {
                'First 1KB': data[:1024],
                'Last 1KB': data[-1024:] if len(data) > 1024 else data,
                'Middle 1KB': data[len(data)//2:len(data)//2+1024] if len(data) > 2048 else data
            }
            
            for section_name, section_data in sections.items():
                if section_data:
                    entropy = self.calculate_data_entropy(section_data)
                    entropy_info += f"{section_name} entropy: {entropy:.4f}\n"
                    if entropy > 7.0:
                        entropy_info += "  ??  High entropy - potential encryption/packing\n"
                    elif entropy < 4.0:
                        entropy_info += "  ? Low entropy - likely normal code/data\n"
                    else:
                        entropy_info += "  ??  Medium entropy - mixed content\n"
            
        except Exception as e:
            entropy_info += f"Entropy analysis error: {str(e)}\n"
        
        return entropy_info

    def calculate_data_entropy(self, data):
        """Calcule l'entropie de données spécifiques"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        
        return entropy

    def perform_yara_analysis(self):
        """Analyse YARA pour patterns de malware"""
        yara_info = "?? YARA RULES ANALYSIS - REAL RESULTS\n"
        yara_info += "=" * 60 + "\n\n"
        
        try:
            # Vérifier si YARA est installé
            result = subprocess.run(['yara', '--version'], 
                                  capture_output=True, text=True)
            
            yara_info += "YARA installed - Basic analysis available\n"
            
            # Créer une règle YARA simple pour détection basique
            yara_rule = """
rule SuspiciousBehavior {
    strings:
        $shell = "/bin/sh"
        $system = "system"
        $execve = "execve"
        $backdoor = "backdoor"
    condition:
        any of them
}
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(yara_rule)
                yara_rule_file = f.name
            
            # Exécuter YARA
            result = subprocess.run(['yara', yara_rule_file, self.current_file],
                                  capture_output=True, text=True, timeout=20)
            
            yara_info += f"YARA scan results:\n{result.stdout}\n"
            
            # Nettoyer
            os.unlink(yara_rule_file)
            
        except Exception as e:
            yara_info += f"YARA analysis not available: {str(e)}\n"
        
        return yara_info

    def perform_deep_binary_analysis(self):
        """Analyse binaire profonde"""
        vulnerabilities = []
        
        try:
            # Analyse des sections pour anomalies
            result = subprocess.run(['readelf', '-S', self.current_file], 
                                  capture_output=True, text=True, timeout=10)
            sections = result.stdout
            
            # Vérifier les sections suspectes
            if '.gnu.hash' not in sections:
                vulnerabilities.append(self.create_vulnerability_entry(
                    'Binary Structure',
                    'GNU Hash Section Missing',
                    'LOW',
                    'CWE-1004',
                    'GNU hash section missing - slower symbol resolution',
                    'Binary structure',
                    'Consider modern compilation flags'
                ))
            
            # Vérifier les permissions des sections
            if 'W' in sections and 'AX' in sections:
                vulnerabilities.append(self.create_vulnerability_entry(
                    'Memory Protection',
                    'Writable and Executable Sections',
                    'HIGH',
                    'CWE-123',
                    'Sections with both write and execute permissions',
                    'Section permissions',
                    'Separate code and data sections'
                ))
                    
        except Exception as e:
            vulnerabilities.append(self.create_vulnerability_entry(
                'Analysis Error',
                'Deep Analysis Failed',
                'LOW',
                'N/A',
                f'Deep analysis error: {str(e)}',
                'Analysis process',
                'Check binary integrity'
            ))
        
        return vulnerabilities

    def create_vulnerability_entry(self, category, vuln_type, severity, cwe, description, location, fix):
        """Crée une entrée de vulnérabilité standardisée"""
        # Clé unique pour éviter les doublons
        vuln_key = f"{category}_{vuln_type}_{severity}"
        
        if vuln_key not in self.detected_vulnerabilities:
            self.detected_vulnerabilities.add(vuln_key)
            return {
                'severity': severity,
                'category': category,
                'type': vuln_type,
                'cwe': cwe,
                'description': description,
                'location': location,
                'fix': fix
            }
        return None

    def remove_duplicate_vulnerabilities(self, vulnerabilities):
        """Supprime les vulnérabilités en double"""
        unique_vulns = []
        seen = set()
        
        for vuln in vulnerabilities:
            if vuln:  # Ignorer les None
                signature = f"{vuln['category']}_{vuln['type']}_{vuln['severity']}"
                if signature not in seen:
                    seen.add(signature)
                    unique_vulns.append(vuln)
        
        return unique_vulns

    def calculate_comprehensive_metrics(self, vulnerabilities, analysis_time):
        """Calcule des métriques complètes"""
        metrics = {
            'total_vulnerabilities': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high_risk': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium_risk': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low_risk': sum(1 for v in vulnerabilities if v['severity'] == 'LOW'),
            'memory_issues': sum(1 for v in vulnerabilities if 'memory' in v['category'].lower()),
            'code_issues': sum(1 for v in vulnerabilities if 'code' in v['category'].lower()),
            'security_issues': sum(1 for v in vulnerabilities if 'security' in v['category'].lower()),
            'dynamic_issues': sum(1 for v in vulnerabilities if 'dynamic' in v['category'].lower()),
            'analysis_time': f"{analysis_time:.2f}s"
        }
        
        # Score de sécurité
        security_score = 100
        security_score -= metrics['critical'] * 15
        security_score -= metrics['high_risk'] * 8
        security_score -= metrics['medium_risk'] * 4
        security_score -= metrics['low_risk'] * 1
        security_score = max(0, security_score)
        
        metrics['security_score'] = security_score
        
        return metrics

    def _update_final_results(self, vulnerabilities, metrics):
        """Met à jour l'interface avec les résultats finaux"""
        try:
            # Mettre à jour les vulnérabilités
            self._update_vulnerabilities_display(vulnerabilities)
            
            # Générer le rapport complet
            self._generate_comprehensive_report(vulnerabilities, metrics)
            
            # Mettre à jour les informations
            self._update_info_with_metrics(metrics)
            
        except Exception as e:
            self.show_error("Results Update Error", str(e))

    def _update_vulnerabilities_display(self, vulnerabilities):
        """Met à jour l'affichage des vulnérabilités"""
        # Effacer les anciennes entrées
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
            
        # Ajouter les nouvelles vulnérabilités
        for vuln in vulnerabilities:
            self.vuln_tree.insert('', tk.END, values=(
                vuln['severity'],
                vuln['category'],
                vuln['type'],
                vuln['cwe'],
                vuln['description'],
                vuln['location']
            ))

    def _generate_comprehensive_report(self, vulnerabilities, metrics):
        """Génère un rapport complet"""
        report = "HSBTCm ULTIMATE PRO - COMPREHENSIVE SECURITY ANALYSIS REPORT\n"
        report += "=" * 80 + "\n\n"
        
        # En-tête
        report += f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Target File: {os.path.basename(self.current_file)}\n"
        report += f"Full Path: {self.current_file}\n"
        report += f"Analysis Time: {metrics['analysis_time']}\n\n"
        
        # Résumé exécutif
        report += "?? EXECUTIVE SUMMARY\n"
        report += f"• Total Vulnerabilities: {metrics['total_vulnerabilities']}\n"
        report += f"• Critical Issues: {metrics['critical']}\n"
        report += f"• High Risk Issues: {metrics['high_risk']}\n"
        report += f"• Medium Risk Issues: {metrics['medium_risk']}\n"
        report += f"• Low Risk Issues: {metrics['low_risk']}\n"
        report += f"• Security Score: {metrics['security_score']}/100\n\n"
        
        # Détails par catégorie
        report += "?? VULNERABILITIES BY CATEGORY\n"
        categories = Counter(v['category'] for v in vulnerabilities)
        for category, count in categories.most_common():
            report += f"• {category}: {count} vulnerabilities\n"
        report += "\n"
        
        # Vulnérabilités critiques et hautes
        critical_vulns = [v for v in vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']]
        if critical_vulns:
            report += "?? CRITICAL & HIGH RISK VULNERABILITIES\n"
            for i, vuln in enumerate(critical_vulns, 1):
                report += f"\n{i}. [{vuln['severity']}] {vuln['type']}\n"
                report += f"   Category: {vuln['category']}\n"
                report += f"   CWE: {vuln['cwe']}\n"
                report += f"   Description: {vuln['description']}\n"
                report += f"   Location: {vuln['location']}\n"
                report += f"   Fix: {vuln['fix']}\n"
        
        # Recommandations de sécurité
        report += "\n?? SECURITY RECOMMENDATIONS\n"
        if metrics['critical'] > 0:
            report += "• IMMEDIATE ACTION REQUIRED: Address critical vulnerabilities\n"
        if metrics['high_risk'] > 0:
            report += "• HIGH PRIORITY: Fix high-risk vulnerabilities within 30 days\n"
        if metrics['memory_issues'] > 0:
            report += "• MEMORY SAFETY: Implement bounds checking and use safe functions\n"
        if metrics['code_issues'] > 0:
            report += "• CODE QUALITY: Review and refactor dangerous code patterns\n"
        
        report += "• GENERAL RECOMMENDATIONS:\n"
        report += "  - Enable all security protections (PIE, NX, RELRO, Stack Canary)\n"
        report += "  - Use safe string functions (strncpy, snprintf)\n"
        report += "  - Validate all user inputs\n"
        report += "  - Conduct regular security audits\n"
        report += "  - Keep dependencies updated\n"
        
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(1.0, report)

    def _update_info_with_metrics(self, metrics):
        """Met à jour les informations avec les métriques"""
        info = f"""?? ANALYSIS METRICS - REAL RESULTS

Total Vulnerabilities: {metrics['total_vulnerabilities']}
• Critical: {metrics['critical']}
• High Risk: {metrics['high_risk']}  
• Medium Risk: {metrics['medium_risk']}
• Low Risk: {metrics['low_risk']}

Security Score: {metrics['security_score']}/100
Analysis Time: {metrics['analysis_time']}

Breakdown:
• Memory Issues: {metrics['memory_issues']}
• Code Issues: {metrics['code_issues']}
• Security Issues: {metrics['security_issues']}
• Dynamic Issues: {metrics['dynamic_issues']}"""

        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, info)
        self.info_text.config(state=tk.DISABLED)

    def update_static_views(self, results):
        """Met à jour les vues d'analyse statique"""
        self.file_info_text.delete(1.0, tk.END)
        self.file_info_text.insert(1.0, results['file_info'])
        
        self.strings_text.delete(1.0, tk.END)
        self.strings_text.insert(1.0, results['strings'])
        
        self.functions_text.delete(1.0, tk.END)
        self.functions_text.insert(1.0, results['functions'])
        
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(1.0, results['security'])
        
        self.assembly_text.delete(1.0, tk.END)
        self.assembly_text.insert(1.0, results['assembly'])

    def update_dynamic_views(self, results):
        """Met à jour les vues d'analyse dynamique"""
        self.strace_text.delete(1.0, tk.END)
        self.strace_text.insert(1.0, results['strace'])
        
        self.ltrace_text.delete(1.0, tk.END)
        self.ltrace_text.insert(1.0, results['ltrace'])
        
        self.process_text.delete(1.0, tk.END)
        self.process_text.insert(1.0, results['process'])
        
        self.network_text.delete(1.0, tk.END)
        self.network_text.insert(1.0, results['network'])
        
        self.gdb_text.delete(1.0, tk.END)
        self.gdb_text.insert(1.0, results['gdb'])
        
        self.radare_text.delete(1.0, tk.END)
        self.radare_text.insert(1.0, results['radare'])

    def update_advanced_views(self, results):
        """Met à jour les vues d'analyse avancée"""
        self.suspicious_text.delete(1.0, tk.END)
        self.suspicious_text.insert(1.0, results['suspicious'])
        
        self.memory_analysis_text.delete(1.0, tk.END)
        self.memory_analysis_text.insert(1.0, results['memory'])
        
        self.code_patterns_text.delete(1.0, tk.END)
        self.code_patterns_text.insert(1.0, results['code_patterns'])
        
        self.entropy_text.delete(1.0, tk.END)
        self.entropy_text.insert(1.0, results['entropy'])
        
        self.yara_text.delete(1.0, tk.END)
        self.yara_text.insert(1.0, results['yara'])

    def start_dynamic_analysis(self):
        """Démarre l'analyse dynamique"""
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a binary file first")
            return
            
        thread = threading.Thread(target=self.perform_advanced_dynamic_analysis)
        thread.daemon = True
        thread.start()

    def stop_dynamic_analysis(self):
        """Arrête l'analyse dynamique"""
        try:
            if self.dynamic_process:
                self.dynamic_process.terminate()
            self.scan_status.set("Dynamic analysis stopped")
        except:
            pass

    def analyze_behavior(self):
        """Analyse le comportement du binaire"""
        try:
            behavior_info = "?? BEHAVIORAL ANALYSIS - REAL RESULTS\n"
            behavior_info += "=" * 60 + "\n\n"
            
            # Exécuter le binaire avec différentes entrées
            test_inputs = ['', 'test', '123', 'A' * 100]
            
            for test_input in test_inputs:
                try:
                    process = subprocess.run([self.current_file], 
                                           input=test_input,
                                           capture_output=True, 
                                           text=True, 
                                           timeout=5)
                    
                    behavior_info += f"Input: '{test_input[:20]}...'\n"
                    behavior_info += f"  Return code: {process.returncode}\n"
                    if process.stdout:
                        behavior_info += f"  Stdout: {process.stdout[:100]}...\n"
                    if process.stderr:
                        behavior_info += f"  Stderr: {process.stderr[:100]}...\n"
                    behavior_info += "\n"
                    
                except subprocess.TimeoutExpired:
                    behavior_info += f"Input: '{test_input[:20]}...' - TIMEOUT\n\n"
                except Exception as e:
                    behavior_info += f"Input: '{test_input[:20]}...' - ERROR: {str(e)}\n\n"
            
            self.process_text.delete(1.0, tk.END)
            self.process_text.insert(1.0, behavior_info)
            
        except Exception as e:
            self.process_text.insert(1.0, f"Behavior analysis error: {str(e)}")

    def start_realtime_monitor(self):
        """Démarre le monitoring en temps réel"""
        if not self.current_file:
            messagebox.showwarning("Warning", "Please select a binary file first")
            return
            
        thread = threading.Thread(target=self.realtime_monitoring)
        thread.daemon = True
        thread.start()

    def realtime_monitoring(self):
        """Monitoring en temps réel du binaire"""
        try:
            self.scan_status.set("?? Starting real-time monitoring...")
            
            process = subprocess.Popen([self.current_file],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
            
            monitor_info = "?? REAL-TIME MONITORING - ACTIVE\n"
            monitor_info += "=" * 50 + "\n\n"
            monitor_info += f"Monitoring PID: {process.pid}\n\n"
            
            start_time = time.time()
            max_duration = 10  # 10 secondes max
            
            while time.time() - start_time < max_duration and process.poll() is None:
                try:
                    proc_info = psutil.Process(process.pid)
                    
                    # Mettre à jour les informations
                    current_info = f"Time: {time.time() - start_time:.1f}s\n"
                    current_info += f"CPU: {proc_info.cpu_percent()}%\n"
                    current_info += f"Memory: {proc_info.memory_info().rss / 1024 / 1024:.1f} MB\n"
                    current_info += f"Status: {proc_info.status()}\n"
                    
                    # Connexions
                    connections = proc_info.connections()
                    if connections:
                        current_info += f"Connections: {len(connections)}\n"
                    
                    self.process_text.delete(1.0, tk.END)
                    self.process_text.insert(1.0, monitor_info + current_info)
                    
                    time.sleep(0.5)
                    
                except psutil.NoSuchProcess:
                    break
            
            # Nettoyer
            if process.poll() is None:
                process.terminate()
                process.wait()
            
            self.scan_status.set("Real-time monitoring completed")
            
        except Exception as e:
            self.process_text.insert(1.0, f"Real-time monitoring error: {str(e)}")

    def stop_analysis(self):
        """Arrête l'analyse"""
        self.scanning = False
        self.progress.stop()
        self.scan_status.set("?? Analysis stopped")
        self.update_status("Analysis stopped by user")

    def export_results(self):
        """Exporte les résultats réels"""
        filename = filedialog.asksaveasfilename(
            title="Export Complete Analysis Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if filename:
            try:
                report_content = self.report_text.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                messagebox.showinfo("Export Successful", f"Complete report exported to:\n{filename}")
            except Exception as e:
                self.show_error("Export Error", str(e))

    def clear_results(self):
        """Efface tous les résultats"""
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        text_widgets = [
            'file_info_text', 'strings_text', 'functions_text', 'security_text', 'assembly_text',
            'strace_text', 'ltrace_text', 'process_text', 'network_text', 'gdb_text', 'radare_text',
            'suspicious_text', 'memory_analysis_text', 'code_patterns_text', 'entropy_text', 'yara_text',
            'report_text'
        ]
        
        for attr in text_widgets:
            if hasattr(self, attr):
                getattr(self, attr).delete(1.0, tk.END)
        
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, "Select a binary file to begin comprehensive analysis...")
        self.info_text.config(state=tk.DISABLED)
        
        self.scan_status.set("Ready for analysis")
        self.update_status("?? All results cleared")
        self.detected_vulnerabilities.clear()

    def update_status(self, message):
        """Met à jour le statut"""
        self.status_label.config(text=message)

    def show_error(self, title, message):
        """Affiche une erreur"""
        messagebox.showerror(title, message)

def main():
    """Fonction principale"""
    try:
        root = tk.Tk()
        app = HSBTCmPRO(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("HSBTCm ULTIMATE PRO Error", f"Application failed:\n{str(e)}")

if __name__ == "__main__":
    main()
