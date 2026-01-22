#!/usr/bin/env python3
"""
Chrome Collector Multi-plateforme
"""
import json
import platform
import os
from pathlib import Path
from datetime import datetime, timezone
import subprocess

class ChromeCollector:
    """
    Collecte les extensions Chrome
    """
    def __init__(self, custom_path=None):
        self.extensions = []
        self.os_type = platform.system()
        
        if custom_path and Path(custom_path).exists():
            self.base_path = Path(custom_path)
            print(f"  Chemin custom: {custom_path}")
        else:
            self.base_path = self._find_chrome_extensions()
    
    def _find_chrome_extensions(self):
        """
        Cherche Chrome - essaie plusieurs méthodes
        """
        standard_paths = self._get_standard_paths()
        for path in standard_paths:
            if path.exists():
                print(f"  Chrome trouvé: {path}")
                return path
        
        if self.os_type == 'Linux':
            detected_path = self._detect_via_executable()
            if detected_path and detected_path.exists():
                print(f"  Chrome détecté: {detected_path}")
                return detected_path
        
        print(f"  Chrome non trouvé dans les emplacements connus")
        return standard_paths[0] if standard_paths else Path('.')
    
    def _get_standard_paths(self):
        """
        Retourne les chemins standards selon l'OS.
        """
        if self.os_type == 'Windows':
            base = Path(os.getenv('LOCALAPPDATA', ''))
            return [
                base / 'Google' / 'Chrome' / 'User Data' / 'Default' / 'Extensions',
            ]
        elif self.os_type == 'Linux':
            return [
                Path.home() / '.config' / 'google-chrome' / 'Default' / 'Extensions',           # Standard
                Path.home() / '.config' / 'chromium' / 'Default' / 'Extensions',                # Chromium
                Path.home() / 'snap' / 'chromium' / 'common' / 'chromium' / 'Default' / 'Extensions',  # Snap Chromium
                Path.home() / 'snap' / 'chrome' / 'common' / 'chromium' / 'Default' / 'Extensions',    # Snap Chrome (rare)
                Path.home() / '.var' / 'app' / 'com.google.Chrome' / 'config' / 'google-chrome' / 'Default' / 'Extensions',  # Flatpak Chrome
                Path.home() / '.var' / 'app' / 'org.chromium.Chromium' / 'config' / 'chromium' / 'Default' / 'Extensions',    # Flatpak Chromium
            ]
        
        elif self.os_type == 'Darwin':  
            return [
                Path.home() / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default' / 'Extensions',
            ]
        return []
    
    def _detect_via_executable(self):
        """
        Détecte Chrome/Chromium via son exécutable
        """
        executables = ['google-chrome', 'chromium', 'chromium-browser', 'chrome']
        for exe in executables:
            try:
                result = subprocess.run(['which', exe], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=5)
                
                if result.returncode == 0:
                    chrome_bin = result.stdout.strip()
                    
                    if 'snap' in chrome_bin:
                        if 'chromium' in chrome_bin:
                            return Path.home() / 'snap' / 'chromium' / 'common' / 'chromium' / 'Default' / 'Extensions'
                        else:
                            return Path.home() / 'snap' / 'chrome' / 'common' / 'chromium' / 'Default' / 'Extensions'
                    elif 'flatpak' in chrome_bin:
                        if 'chromium' in exe:
                            return Path.home() / '.var' / 'app' / 'org.chromium.Chromium' / 'config' / 'chromium' / 'Default' / 'Extensions'
                        else:
                            return Path.home() / '.var' / 'app' / 'com.google.Chrome' / 'config' / 'google-chrome' / 'Default' / 'Extensions'
                    else:
                        if 'chromium' in exe:
                            return Path.home() / '.config' / 'chromium' / 'Default' / 'Extensions'
                        else:
                            return Path.home() / '.config' / 'google-chrome' / 'Default' / 'Extensions'
            except Exception:
                continue
        return None
    
    def collect_extensions(self):
        """
        Collecte les extensions Chrome installées
        """
        print(f"Scan Chrome ({self.os_type}): {self.base_path}")
        
        if not self.base_path.exists():
            print(f"  Chrome/Chromium non installé ou extensions introuvables")
            return []
        
        for ext_folder in self.base_path.iterdir():
            if not ext_folder.is_dir():
                continue
            
            extension_id = ext_folder.name
            version_folders = [f for f in ext_folder.iterdir() if f.is_dir()]
            
            if not version_folders:
                continue
            latest_version = sorted(version_folders, key=lambda x: x.name, reverse=True)[0]
            manifest_path = latest_version / 'manifest.json'
            if not manifest_path.exists():
                continue
            
            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
                
                extension_data = {
                    'id': extension_id,
                    'browser': 'chrome',
                    'manifest': manifest,
                    'installed_path': str(latest_version),
                    'collected_at': datetime.now(timezone.utc).isoformat(),
                    'os': self.os_type
                }
                self.extensions.append(extension_data)
                
                name = manifest.get('name', 'Unknown')
                version = manifest.get('version', '?')
                print(f"Collecte: {name} v{version}")   
            except Exception as e:
                print(f"Erreur lecture {extension_id}: {e}")
                continue
        print(f"Chrome: {len(self.extensions)} extension(s)")
        return self.extensions