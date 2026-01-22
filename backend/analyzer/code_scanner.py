import esprima
import re
import os
from pathlib import Path
from datetime import datetime, timezone
import json

class CodeScanner:
    """
    Scanner de code JavaScript pour détecter les patterns malveillants
    Analyse :
    - Code obfusqué
    - Fonctions dangereuses (eval, Function, etc.)
    - Exfiltration de données
    - Communication avec des domaines suspects
    - Manipulation du DOM suspecte
    """
    
    def __init__(self):
        # Patterns de fonctions dangereuses
        self.dangerous_functions = {
            'eval': {
                'severity': 'critical',
                'reason': 'Exécution de code arbitraire - vecteur d\'injection'
            },
            'Function': {
                'severity': 'critical',
                'reason': 'Construction dynamique de fonctions - risque d\'injection'
            },
            'setTimeout': {
                'severity': 'medium',
                'reason': 'Exécution différée de code - peut masquer des comportements'
            },
            'setInterval': {
                'severity': 'medium',
                'reason': 'Exécution répétée de code'
            },
            'execScript': {
                'severity': 'critical',
                'reason': 'Exécution de scripts (IE legacy) - très dangereux'
            }
        }
        
        # Patterns d'encodage/obfuscation
        self.obfuscation_patterns = [
            {
                'pattern': r'atob\s*\(',
                'name': 'Base64 Decode',
                'severity': 'high',
                'reason': 'Décodage Base64 - souvent utilisé pour masquer du code'
            },
            {
                'pattern': r'btoa\s*\(',
                'name': 'Base64 Encode',
                'severity': 'medium',
                'reason': 'Encodage Base64 - peut exfiltrer des données'
            },
            {
                'pattern': r'String\.fromCharCode',
                'name': 'CharCode Obfuscation',
                'severity': 'high',
                'reason': 'Construction de strings par codes - obfuscation classique'
            },
            {
                'pattern': r'\\x[0-9a-fA-F]{2}',
                'name': 'Hex Encoding',
                'severity': 'medium',
                'reason': 'Encodage hexadécimal de strings'
            },
            {
                'pattern': r'\\u[0-9a-fA-F]{4}',
                'name': 'Unicode Escaping',
                'severity': 'low',
                'reason': 'Échappement Unicode - peut masquer du contenu'
            },
            {
                'pattern': r'unescape\s*\(',
                'name': 'Unescape',
                'severity': 'medium',
                'reason': 'Décodage d\'URL - peut révéler du code caché'
            },
            {
                'pattern': r'decodeURIComponent\s*\(',
                'name': 'URI Decode',
                'severity': 'low',
                'reason': 'Décodage URI'
            }
        ]
        
        # Patterns d'exfiltration de données
        self.exfiltration_patterns = [
            {
                'pattern': r'document\.cookie',
                'name': 'Cookie Access',
                'severity': 'high',
                'reason': 'Accès aux cookies - risque de vol de session'
            },
            {
                'pattern': r'localStorage\.(getItem|setItem)',
                'name': 'LocalStorage Access',
                'severity': 'medium',
                'reason': 'Accès au stockage local'
            },
            {
                'pattern': r'sessionStorage\.(getItem|setItem)',
                'name': 'SessionStorage Access',
                'severity': 'medium',
                'reason': 'Accès au stockage de session'
            },
            {
                'pattern': r'navigator\.credentials',
                'name': 'Credentials API',
                'severity': 'high',
                'reason': 'Accès aux credentials stockés'
            },
            {
                'pattern': r'password|passwd|pwd',
                'name': 'Password Keywords',
                'severity': 'medium',
                'reason': 'Manipulation potentielle de mots de passe',
                'case_sensitive': False
            }
        ]
        
        # Patterns de communication réseau suspecte
        self.network_patterns = [
            {
                'pattern': r'XMLHttpRequest',
                'name': 'XMLHttpRequest',
                'severity': 'low',
                'reason': 'Requêtes HTTP - surveiller les destinations'
            },
            {
                'pattern': r'fetch\s*\(',
                'name': 'Fetch API',
                'severity': 'low',
                'reason': 'Requêtes modernes - surveiller les destinations'
            },
            {
                'pattern': r'WebSocket',
                'name': 'WebSocket',
                'severity': 'medium',
                'reason': 'Communication temps réel - canal d\'exfiltration'
            },
            {
                'pattern': r'postMessage',
                'name': 'PostMessage',
                'severity': 'medium',
                'reason': 'Communication inter-frames - risque de fuite'
            }
        ]
        
        # Patterns de manipulation du DOM suspecte
        self.dom_patterns = [
            {
                'pattern': r'innerHTML\s*=',
                'name': 'innerHTML Assignment',
                'severity': 'medium',
                'reason': 'Injection HTML - risque XSS'
            },
            {
                'pattern': r'outerHTML\s*=',
                'name': 'outerHTML Assignment',
                'severity': 'medium',
                'reason': 'Remplacement d\'éléments - risque XSS'
            },
            {
                'pattern': r'document\.write',
                'name': 'document.write',
                'severity': 'high',
                'reason': 'Écriture directe dans le document - dangereux'
            },
            {
                'pattern': r'insertAdjacentHTML',
                'name': 'insertAdjacentHTML',
                'severity': 'medium',
                'reason': 'Insertion HTML - risque XSS'
            }
        ]
    
    def scan_extension(self, extension_path):
        """
        Scan complet d'une extension
        Args:
            extension_path: Chemin vers le dossier de l'extension
        Returns:
            dict: Résultats du scan avec tous les findings
        """
        results = {
            'scanned_at': datetime.now(timezone.utc).isoformat(),
            'extension_path': str(extension_path),
            'files_scanned': 0,
            'total_findings': 0,
            'severity_counts': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'findings': [],
            'obfuscation_score': 0,
            'risk_indicators': []
        }
        
        js_files = self._find_js_files(extension_path)
        
        for js_file in js_files:
            file_results = self._scan_file(js_file)
            
            if file_results:
                results['files_scanned'] += 1
                results['findings'].extend(file_results['findings'])
                results['total_findings'] += len(file_results['findings'])
                
                for finding in file_results['findings']:
                    severity = finding['severity']
                    results['severity_counts'][severity] += 1
        
        results['obfuscation_score'] = self._calculate_obfuscation_score(results['findings'])
        
        results['risk_indicators'] = self._generate_risk_indicators(results)
        
        return results
    
    def _find_js_files(self, base_path):
        """
        Trouve tous les fichiers JavaScript dans l'extension
        """
        js_files = []
        base_path = Path(base_path)
        
        if not base_path.exists():
            return js_files
        
        for root, dirs, files in os.walk(base_path):
            for file in files:
                if file.endswith('.js'):
                    js_files.append(Path(root) / file)
        
        return js_files
    
    def _scan_file(self, file_path):
        """
        Scan un fichier JavaScript individuel
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            findings = []
            findings.extend(self._scan_dangerous_functions(content, file_path))
            findings.extend(self._scan_obfuscation(content, file_path))
            findings.extend(self._scan_exfiltration(content, file_path))
            findings.extend(self._scan_network(content, file_path))
            findings.extend(self._scan_dom_manipulation(content, file_path))
            
            ast_findings = self._analyze_ast(content, file_path)
            if ast_findings:
                findings.extend(ast_findings)
            
            return {
                'file': str(file_path),
                'findings': findings
            }
            
        except Exception as e:
            print(f"Erreur scan fichier {file_path}: {e}")
            return None
    
    def _scan_dangerous_functions(self, content, file_path):
        """
        Détecte l'utilisation de fonctions dangereuses
        """
        findings = []
        
        for func_name, info in self.dangerous_functions.items():
            pattern = rf'\b{func_name}\s*\('
            matches = re.finditer(pattern, content)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'dangerous_function',
                    'name': func_name,
                    'severity': info['severity'],
                    'reason': info['reason'],
                    'file': str(file_path.name),
                    'line': line_num,
                    'context': self._get_context(content, match.start())
                })
        
        return findings
    
    def _scan_obfuscation(self, content, file_path):
        """
        Détecte les techniques d'obfuscation
        """
        findings = []
        
        for pattern_info in self.obfuscation_patterns:
            matches = re.finditer(pattern_info['pattern'], content, 
                                re.IGNORECASE if pattern_info.get('case_sensitive') == False else 0)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'obfuscation',
                    'name': pattern_info['name'],
                    'severity': pattern_info['severity'],
                    'reason': pattern_info['reason'],
                    'file': str(file_path.name),
                    'line': line_num,
                    'context': self._get_context(content, match.start())
                })
        
        return findings
    
    def _scan_exfiltration(self, content, file_path):
        """
        Détecte les patterns d'exfiltration de données
        """
        findings = []
        
        for pattern_info in self.exfiltration_patterns:
            flags = 0 if pattern_info.get('case_sensitive', True) else re.IGNORECASE
            matches = re.finditer(pattern_info['pattern'], content, flags)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'data_exfiltration',
                    'name': pattern_info['name'],
                    'severity': pattern_info['severity'],
                    'reason': pattern_info['reason'],
                    'file': str(file_path.name),
                    'line': line_num,
                    'context': self._get_context(content, match.start())
                })
        
        return findings
    
    def _scan_network(self, content, file_path):
        """
        Détecte les communications réseau
        """
        findings = []
        
        for pattern_info in self.network_patterns:
            matches = re.finditer(pattern_info['pattern'], content)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'network_communication',
                    'name': pattern_info['name'],
                    'severity': pattern_info['severity'],
                    'reason': pattern_info['reason'],
                    'file': str(file_path.name),
                    'line': line_num,
                    'context': self._get_context(content, match.start())
                })
        
        return findings
    
    def _scan_dom_manipulation(self, content, file_path):
        """
        Détecte les manipulations du DOM suspectes
        """
        findings = []
        
        for pattern_info in self.dom_patterns:
            matches = re.finditer(pattern_info['pattern'], content)
            
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'dom_manipulation',
                    'name': pattern_info['name'],
                    'severity': pattern_info['severity'],
                    'reason': pattern_info['reason'],
                    'file': str(file_path.name),
                    'line': line_num,
                    'context': self._get_context(content, match.start())
                })
        
        return findings
    
    def _analyze_ast(self, content, file_path):
        """
        Analyse syntaxique avec esprima pour détections avancées
        """
        try:
            ast = esprima.parseScript(content, {'loc': True, 'range': True})
            findings = []
            
            # Analyse des appels de fonctions suspects
            self._walk_ast(ast, findings, file_path, content)
            
            return findings
            
        except Exception as e:
            return [{
                'type': 'parsing_error',
                'name': 'Unparseable JavaScript',
                'severity': 'low',
                'reason': 'Code potentiellement minifié ou obfusqué',
                'file': str(file_path.name),
                'line': 0,
                'context': str(e)
            }]
    
    def _walk_ast(self, node, findings, file_path, content):
        """
        Parcours récursif de l'AST
        """
        if isinstance(node, dict):
            node_type = node.get('type')
            if node_type == 'Literal' and isinstance(node.get('value'), str):
                if len(node['value']) > 500:
                    findings.append({
                        'type': 'suspicious_literal',
                        'name': 'Large String Literal',
                        'severity': 'medium',
                        'reason': f'String de {len(node["value"])} caractères - possiblement du code encodé',
                        'file': str(file_path.name),
                        'line': node.get('loc', {}).get('start', {}).get('line', 0),
                        'context': node['value'][:100] + '...'
                    })
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    self._walk_ast(value, findings, file_path, content)
        
        elif isinstance(node, list):
            for item in node:
                self._walk_ast(item, findings, file_path, content)
    
    def _get_context(self, content, position, context_length=80):
        """
        Extrait le contexte autour d'une position dans le code
        """
        start = max(0, position - context_length // 2)
        end = min(len(content), position + context_length // 2)
        
        context = content[start:end]
        context = ' '.join(context.split())
        
        return context[:100]
    
    def _calculate_obfuscation_score(self, findings):
        """
        Calcule un score d'obfuscation (0-100)
        """
        obfuscation_findings = [f for f in findings if f['type'] == 'obfuscation']
        
        score = 0
        score += min(len(obfuscation_findings) * 10, 50)
        critical_obf = [f for f in obfuscation_findings if f['severity'] == 'high']
        score += min(len(critical_obf) * 15, 50)
        
        return min(score, 100)
    
    def _generate_risk_indicators(self, results):
        """
        Génère une liste d'indicateurs de risque basée sur les findings
        """
        indicators = []
        
        if results['severity_counts']['critical'] > 0:
            indicators.append(f"{results['severity_counts']['critical']} finding(s) critique(s) détecté(s)")
        
        if results['obfuscation_score'] > 50:
            indicators.append(f"Code fortement obfusqué (score: {results['obfuscation_score']})")
        
        type_counts = {}
        for finding in results['findings']:
            ftype = finding['type']
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        
        if type_counts.get('data_exfiltration', 0) > 3:
            indicators.append("Multiples accès à des données sensibles détectés")
        
        if type_counts.get('dangerous_function', 0) > 2:
            indicators.append("Utilisation extensive de fonctions dangereuses")
        
        return indicators
