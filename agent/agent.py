import sys
import json
from datetime import datetime, timezone
from pathlib import Path
import socket
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Module 'requests' non disponible Mode local uniquement")
sys.path.insert(0, str(Path(__file__).parent / 'collectors'))
from chrome_collector import ChromeCollector
from firefox_collector import FirefoxCollector
from edge_collector import EdgeCollector
backend_analyzer_path = Path(__file__).parent.parent / 'backend' / 'analyzer'
sys.path.insert(0, str(backend_analyzer_path))
try:
    from code_scanner import CodeScanner
    CODE_SCANNER_AVAILABLE = True
except ImportError:
    CODE_SCANNER_AVAILABLE = False
    print("Avertissement Code scanner non disponible")

class ExtensionAgent:
    """
    Agent principal qui orchestre la collecte multi-navigateurs
    """
    def __init__(self, config_path=None):
        self.all_extensions = []
        self.stats = {
            'chrome': 0,
            'firefox': 0,
            'edge': 0,
            'total': 0
        }
        if config_path is None:
            config_path = Path(__file__).parent / "config.json"
        
        self.config = self.load_config(config_path)
    
    def load_config(self, config_path):
        """
        Charge la configuration depuis le fichier JSON.
        """
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Attention: Fichier de config non trouvé: {config_path}")
            print("Utilisation de la configuration par défaut (mode local)")
            return {
                "api": {"enabled": False},
                "scan": {
                    "browsers": ["chrome", "firefox", "edge"],
                    "export_local": True,
                    "export_path": "extensions_inventory.json"
                }
            }
        except Exception as e:
            print(f"Erreur chargement config: {e}")
            return {"api": {"enabled": False}, "scan": {}}
    
    def run_collectors(self):
        """
        Exécute tous les collectors et agrège les résultats
        """
        print("Browser Extension Security Auditor")
        scan_time = datetime.now(timezone.utc).isoformat()
        print(f"Démarrage du scan: {scan_time}\n")
        
        browsers = self.config.get('scan', {}).get('browsers', ['chrome', 'firefox', 'edge'])
        
        if 'chrome' in browsers:
            print("[1/3] Scan Chrome ")
            chrome_collector = ChromeCollector()
            chrome_exts = chrome_collector.collect_extensions()
            self.all_extensions.extend(chrome_exts)
            self.stats['chrome'] = len(chrome_exts)
            print(f"Chrome: {len(chrome_exts)} extension(s)\n")
        
        if 'firefox' in browsers:
            print("[2/3] Scan Firefox ")
            firefox_collector = FirefoxCollector()
            firefox_exts = firefox_collector.collect_extensions()
            self.all_extensions.extend(firefox_exts)
            self.stats['firefox'] = len(firefox_exts)
            print(f"Firefox: {len(firefox_exts)} extension(s)\n")
        
        if 'edge' in browsers:
            print("[3/3] Scan Edge ")
            edge_collector = EdgeCollector()
            edge_exts = edge_collector.collect_extensions()
            self.all_extensions.extend(edge_exts)
            self.stats['edge'] = len(edge_exts)
            print(f"Edge: {len(edge_exts)} extension(s)\n")
        
        self.stats['total'] = len(self.all_extensions)
    
    def analyze_permissions(self):
        """
        Analyse rapide des permissions trouvées
        """
        dangerous_perms = [
            'cookies', 'webRequest', '<all_urls>', 
            'debugger', 'management', 'tabs'
        ]
        
        extensions_with_dangerous = []
        for ext in self.all_extensions:
            ext_perms = ext['manifest']['permissions']
            dangerous_found = [p for p in ext_perms if any(d in p for d in dangerous_perms)]
            
            if dangerous_found:
                extensions_with_dangerous.append({
                    'name': ext['manifest']['name'],
                    'browser': ext['browser'],
                    'dangerous_permissions': dangerous_found
                })
        
        return extensions_with_dangerous
    
    def scan_extensions_code(self):
        """
        Scan le code JavaScript de chaque extension collectée
        """
        if not CODE_SCANNER_AVAILABLE:
            print("\nCode scanner non disponible - installation requise:")
            print("  pip install esprima jsbeautifier")
            return
        print("SCAN DU CODE JAVASCRIPT")
        scanner = CodeScanner()
        scanned_count = 0
        
        for ext in self.all_extensions:
            try:
                ext_path = ext.get('installed_path')
                ext_name = ext['manifest']['name']
                
                if not ext_path:
                    print(f"  [SKIP] {ext_name} - Pas de chemin")
                    continue
                
                print(f"\n  Analyse: {ext_name}")
                print(f"    Chemin: {ext_path}")
                
                scan_results = scanner.scan_extension(ext_path)
                
                # Ajoute les résultats au dictionnaire de l'extension
                ext['code_scan'] = scan_results
                
                findings = scan_results['total_findings']
                critical = scan_results['severity_counts']['critical']
                high = scan_results['severity_counts']['high']
                obfusc = scan_results['obfuscation_score']
                
                print(f" Fichiers: {scan_results['files_scanned']}")
                print(f"Findings: {findings} (Critique: {critical}, Élevé: {high})")
                print(f" Obfuscation: {obfusc}/100")
                
                if scan_results['risk_indicators']:
                    print(f"    Risques:")
                    for indicator in scan_results['risk_indicators']:
                        print(f"      - {indicator}")
                
                scanned_count += 1
                
            except Exception as e:
                print(f"  [ERREUR] {ext['manifest']['name']}: {e}")
                ext['code_scan'] = None
        print(f"Scan terminé: {scanned_count}/{len(self.all_extensions)} extensions analysées")
        

    def print_summary(self):
        """
        Affiche un résumé de la collecte
        """
        print("RÉSUMÉ DE LA COLLECTE")
        print(f"Chrome:   {self.stats['chrome']} extension(s)")
        print(f"Firefox:  {self.stats['firefox']} extension(s)")
        print(f"Edge:     {self.stats['edge']} extension(s)")
        print(f"TOTAL:    {self.stats['total']} extension(s)")
        
        dangerous = self.analyze_permissions()
        
        if dangerous:
            print(f"\nExtensions avec permissions sensibles: {len(dangerous)}")
            for ext in dangerous:
                print(f"\n  {ext['name']} ({ext['browser']})")
                print(f"    Permissions: {', '.join(ext['dangerous_permissions'])}")
    
    def export_results(self):
        """
        Exporte l'inventaire complet au format JSON
        """
        scan_config = self.config.get('scan', {})
        
        if not scan_config.get('export_local', True):
            return
        
        output_file = scan_config.get('export_path', 'extensions_inventory.json')
        
        current_time = datetime.now(timezone.utc).isoformat()
        output_data = {
            'scan_time': current_time,
            'statistics': self.stats,
            'extensions': self.all_extensions
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"\nInventaire exporté: {output_file}")
    
    def send_to_api(self):
        """
        Envoie l'inventaire à l'API backend si configuré
        """
        api_config = self.config.get('api', {})
        
        if not api_config.get('enabled', False):
            print("\nEnvoi à l'API désactivé dans la configuration")
            return False
        
        if not REQUESTS_AVAILABLE:
            print("\nImpossible d'envoyer à l'API: module 'requests' non installé")
            return False
        
        api_url = api_config.get('url')
        
        if not api_url:
            print("\nURL de l'API non configurée")
            return False
        
        try:
            current_time = datetime.now(timezone.utc).isoformat()
            hostname = socket.gethostname()
            
            payload = {
                'scan_time': current_time,
                'hostname': hostname,
                'statistics': self.stats,
                'extensions': self.all_extensions
            }
            
            print(f"\nEnvoi des données à l'API: {api_url}")
            
            timeout = api_config.get('timeout', 10)
            response = requests.post(api_url, json=payload, timeout=timeout)
            
            if response.status_code == 201:
                result = response.json()
                print(f"Succès: {result['processed']}/{result['total']} extensions traitées")
                print(f"Scan ID: {result['scan_id']}")
                return True
            else:
                print(f"Erreur API: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            print("Erreur: Impossible de se connecter à l'API")
            print(f"Vérifiez que le backend est accessible à: {api_url}")
            return False
        except Exception as e:
            print(f"Erreur lors de l'envoi: {e}")
            return False

def main():
    agent = ExtensionAgent()
    agent.run_collectors()
    agent.print_summary()
    
    agent.scan_extensions_code()
    agent.export_results()
    
    agent.send_to_api()
    
    print("\nScan terminé avec succès.")

if __name__ == "__main__":
    main()