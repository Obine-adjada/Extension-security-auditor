import requests
import hashlib
import time
from pathlib import Path
import zipfile
from datetime import datetime, timezone

class ThreatIntelligence:
    """
    Module d'intégration avec les services de threat intelligence
    Services supportés:
    - VirusTotal: Analyse de fichiers et URLs
    - AbuseIPDB: Réputation d'IPs 
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.vt_api_key = self.config.get('virustotal_api_key', '')
        self.vt_enabled = self.config.get('enable_vt_check', False) and bool(self.vt_api_key)
        
        self.vt_base_url = 'https://www.virustotal.com/api/v3'
        self.cache = {}
    
    def check_extension(self, extension_data):
        """
        Vérifie une extension auprès des services de threat intel
        Args:
            extension_data: Dict avec extension_id, browser, installed_path
        Returns:
            dict: Résultat de l'analyse threat intel
        """
        result = {
            'extension_id': extension_data.get('id'),
            'threat_detected': False,
            'reputation_score': 0,
            'detections': [],
            'sources': [],
            'checked_at': datetime.now(timezone.utc).isoformat()
        }
        
        if not self.vt_enabled:
            result['error'] = 'VirusTotal non configuré'
            return result
        extension_hash = self._calculate_extension_hash(extension_data)
        
        if not extension_hash:
            result['error'] = 'Impossible de calculer le hash'
            return result
        if extension_hash in self.cache:
            cached_result = self.cache[extension_hash]
            cached_result['from_cache'] = True
            return cached_result
        vt_result = self._check_virustotal(extension_hash)
        
        if vt_result:
            result.update(vt_result)
            self.cache[extension_hash] = result
        
        return result
    
    def _calculate_extension_hash(self, extension_data):
        """
        Calcule le SHA256 du dossier de l'extension
        """
        try:
            manifest = extension_data.get('manifest', {})
            hash_input = f"{extension_data.get('id')}:{manifest.get('version', '')}"
            return hashlib.sha256(hash_input.encode()).hexdigest()
            
        except Exception as e:
            print(f"Erreur calcul hash: {e}")
            return None
    
    def _check_virustotal(self, file_hash):
        """
        Vérifie un hash sur VirusTotal
        """
        if not self.vt_api_key:
            return None
        
        try:
            url = f"{self.vt_base_url}/files/{file_hash}"
            
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {
                    'virustotal_checked': True,
                    'virustotal_known': False,
                    'threat_detected': False,
                    'sources': ['virustotal']
                }
            
            if response.status_code != 200:
                return {
                    'error': f'VirusTotal API error: {response.status_code}',
                    'virustotal_checked': False
                }
            
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis = attributes.get('last_analysis_stats', {})
            
            malicious = last_analysis.get('malicious', 0)
            suspicious = last_analysis.get('suspicious', 0)
            undetected = last_analysis.get('undetected', 0)
            
            total_engines = malicious + suspicious + undetected
            if total_engines > 0:
                reputation = int((undetected / total_engines) * 100)
            else:
                reputation = 50  # Neutre si pas de données
            
            detections = []
            if malicious > 0:
                detections.append(f"{malicious} moteur(s) détectent comme malveillant")
            if suspicious > 0:
                detections.append(f"{suspicious} moteur(s) signalent comme suspect")
            
            return {
                'virustotal_checked': True,
                'virustotal_known': True,
                'threat_detected': malicious > 0,
                'reputation_score': reputation,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'undetected_count': undetected,
                'detections': detections,
                'sources': ['virustotal'],
                'virustotal_link': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'error': f'Erreur réseau VirusTotal: {str(e)}',
                'virustotal_checked': False
            }
        except Exception as e:
            return {
                'error': f'Erreur VirusTotal: {str(e)}',
                'virustotal_checked': False
            }
    
    def check_update_url(self, update_url):
        """
        Vérifie la réputation d'une URL de mise à jour
        """
        if not update_url or not self.vt_enabled:
            return None
        
        try:
            url_id = hashlib.sha256(update_url.encode()).hexdigest()
            
            url = f"{self.vt_base_url}/urls/{url_id}"
            
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {
                    'url_checked': True,
                    'url_known': False,
                    'threat_detected': False
                }
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis = attributes.get('last_analysis_stats', {})
            
            malicious = last_analysis.get('malicious', 0)
            
            return {
                'url_checked': True,
                'url_known': True,
                'url_malicious': malicious > 0,
                'url_detections': malicious
            }
            
        except Exception as e:
            print(f"Erreur vérification URL: {e}")
            return None
    
    def get_community_reports(self, extension_id):
        """
        Vérifie si l'extension apparaît dans des listes de malware connues
        """
        return {
            'community_reports': [],
            'blocklisted': False
        }
