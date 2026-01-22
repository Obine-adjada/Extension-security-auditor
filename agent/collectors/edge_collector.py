#!/usr/bin/env python3
"""
Edge Collector Multi-plateforme
"""
import json
import platform
import os
from pathlib import Path
from datetime import datetime, timezone
import subprocess

class EdgeCollector:
    """
    Collecte les extensions Edge
    """
    def __init__(self, custom_path=None):
        self.extensions = []
        self.os_type = platform.system()
        
        if custom_path and Path(custom_path).exists():
            self.base_path = Path(custom_path)
            print(f"  Chemin custom: {custom_path}")
        else:
            self.base_path = self._find_edge_extensions()
    
    def _find_edge_extensions(self):
        """
        Cherche Edge
        """
        standard_paths = self._get_standard_paths()
        for path in standard_paths:
            if path.exists():
                print(f"  Edge trouvé: {path}")
                return path
        if self.os_type == 'Linux':
            detected_path = self._detect_via_executable()
            if detected_path and detected_path.exists():
                print(f"  Edge détecté: {detected_path}")
                return detected_path
        print(f"  Edge non trouvé dans les emplacements connus")
        return standard_paths[0] if standard_paths else Path('.')
    
    def _get_standard_paths(self):
        """
        Retourne les chemins standards selon l'OS
        """
        if self.os_type == 'Windows':
            base = Path(os.getenv('LOCALAPPDATA', ''))
            return [
                base / 'Microsoft' / 'Edge' / 'User Data' / 'Default' / 'Extensions',
            ]
        elif self.os_type == 'Linux':
            return [
                Path.home() / '.config' / 'microsoft-edge' / 'Default' / 'Extensions',           # Standard
                Path.home() / '.config' / 'microsoft-edge-dev' / 'Default' / 'Extensions',       # Edge Dev
                Path.home() / '.config' / 'microsoft-edge-beta' / 'Default' / 'Extensions',      # Edge Beta
                Path.home() / '.var' / 'app' / 'com.microsoft.Edge' / 'config' / 'microsoft-edge' / 'Default' / 'Extensions',  # Flatpak
            ]
        elif self.os_type == 'Darwin':  
            return [
                Path.home() / 'Library' / 'Application Support' / 'Microsoft Edge' / 'Default' / 'Extensions',
            ]
        
        return []
    
    def _detect_via_executable(self):
        """
        Détecte Edge via son exécutable
        """
        executables = ['microsoft-edge', 'microsoft-edge-stable', 'microsoft-edge-dev', 'microsoft-edge-beta']
        for exe in executables:
            try:
                result = subprocess.run(['which', exe], 
                                       capture_output=True, 
                                       text=True, 
                                       timeout=5)
                
                if result.returncode == 0:
                    edge_bin = result.stdout.strip()
                    if 'flatpak' in edge_bin:
                        return Path.home() / '.var' / 'app' / 'com.microsoft.Edge' / 'config' / 'microsoft-edge' / 'Default' / 'Extensions'
                    elif 'edge-dev' in exe:
                        return Path.home() / '.config' / 'microsoft-edge-dev' / 'Default' / 'Extensions'
                    elif 'edge-beta' in exe:
                        return Path.home() / '.config' / 'microsoft-edge-beta' / 'Default' / 'Extensions'
                    else:
                        return Path.home() / '.config' / 'microsoft-edge' / 'Default' / 'Extensions'
            
            except Exception:
                continue
        
        return None
    
    def collect_extensions(self):
        """
        Collecte les extensions Edge installées
        """
        print(f"Scan Edge ({self.os_type}): {self.base_path}")
        
        if not self.base_path.exists():
            print(f"  Edge non installé ou extensions introuvables")
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
                    'browser': 'edge',
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
        print(f"Edge: {len(self.extensions)} extension")
        return self.extensions