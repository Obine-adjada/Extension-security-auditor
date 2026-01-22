#!/usr/bin/env python3
"""
Firefox Collector Multi-plateforme
"""
import json
import platform
import os
from pathlib import Path
from datetime import datetime, timezone
import zipfile
import subprocess

class FirefoxCollector:
    """
    Collecte les extensions Firefox 
    """
    
    def __init__(self, custom_path=None):
        self.extensions = []
        self.os_type = platform.system()
        
        if custom_path and Path(custom_path).exists():
            self.profiles_path = Path(custom_path)
            print(f"  Chemin custom {custom_path}")
        else:
            self.profiles_path = self._find_firefox_profiles()
    
    def _find_firefox_profiles(self):
        """
        Cherche Firefox 
        """
        # Méthode 1: Chemins standards
        standard_paths = self._get_standard_paths()
        for path in standard_paths:
            if path.exists():
                print(f"  Firefox trouvé: {path}")
                return path
        
        # Méthode 2: Détection par exécutable 
        if self.os_type == 'Linux':
            detected_path = self._detect_via_executable()
            if detected_path and detected_path.exists():
                print(f"  Firefox détecté: {detected_path}")
                return detected_path
        
        print(f"  Firefox non trouvé dans les emplacements connus")
        return standard_paths[0] if standard_paths else Path('.')
    
    def _get_standard_paths(self):
        """
        Retourne les chemins standards selon l'OS
        """
        if self.os_type == 'Windows':
            return [
                Path(os.getenv('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles',
            ]
        
        elif self.os_type == 'Linux':
            return [
                Path.home() / '.mozilla' / 'firefox',                              # Standard
                Path.home() / 'snap' / 'firefox' / 'common' / '.mozilla' / 'firefox',  # Snap
                Path.home() / '.var' / 'app' / 'org.mozilla.firefox' / '.mozilla' / 'firefox',  # Flatpak
                Path('/var/lib/flatpak/app/org.mozilla.firefox') / 'current' / 'active' / 'files' / 'share' / 'mozilla' / 'firefox',  # Flatpak system
            ]
        
        elif self.os_type == 'Darwin':
            return [
                Path.home() / 'Library' / 'Application Support' / 'Firefox' / 'Profiles',
            ]
        
        return []
    
    def _detect_via_executable(self):
        """
        Détecte Firefox via son exécutable 
        """
        try:
            result = subprocess.run(['which', 'firefox'], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=5)
            
            if result.returncode == 0:
                firefox_bin = result.stdout.strip()
                
                if 'snap' in firefox_bin:
                    return Path.home() / 'snap' / 'firefox' / 'common' / '.mozilla' / 'firefox'
                elif 'flatpak' in firefox_bin:
                    return Path.home() / '.var' / 'app' / 'org.mozilla.firefox' / '.mozilla' / 'firefox'
                else:
                    return Path.home() / '.mozilla' / 'firefox'
        except Exception:
            pass
        
        return None
    
    def collect_extensions(self):
        """
        Collecte les extensions Firefox installées
        """
        print(f"Scan Firefox ({self.os_type}): {self.profiles_path}")
        
        if not self.profiles_path.exists():
            print(f"  Profils Firefox introuvables")
            return []
        
        for profile_folder in self.profiles_path.iterdir():
            if not profile_folder.is_dir():
                continue
            
            if self.os_type == 'Linux':
                if not any(suffix in profile_folder.name for suffix in ['.default', '.default-release', 'default']):
                    continue
            
            print(f"Profil: {profile_folder.name}")
            
            extensions_dir = profile_folder / 'extensions'
            if not extensions_dir.exists():
                continue
            
            for ext_file in extensions_dir.iterdir():
                if ext_file.suffix == '.xpi':
                    self._process_xpi(ext_file, profile_folder.name)
        
        print(f"Firefox: {len(self.extensions)} extension(s)")
        return self.extensions
    
    def _process_xpi(self, xpi_path, profile_name):
        """
        Traite un fichier XPI
        """
        try:
            with zipfile.ZipFile(xpi_path, 'r') as zip_ref:
                if 'manifest.json' not in zip_ref.namelist():
                    return
                
                with zip_ref.open('manifest.json') as manifest_file:
                    manifest = json.load(manifest_file)
                
                ext_id = manifest.get('browser_specific_settings', {}).get('gecko', {}).get('id')
                if not ext_id:
                    ext_id = manifest.get('applications', {}).get('gecko', {}).get('id')
                if not ext_id:
                    ext_id = xpi_path.stem
                
                extension_data = {
                    'id': ext_id,
                    'browser': 'firefox',
                    'manifest': manifest,
                    'installed_path': str(xpi_path),
                    'profile': profile_name,
                    'collected_at': datetime.now(timezone.utc).isoformat(),
                    'os': self.os_type
                }
                
                self.extensions.append(extension_data)
                
                name = manifest.get('name', 'Unknown')
                version = manifest.get('version', '?')
                print(f"Collecte: {name} v{version}")
                
        except Exception as e:
            print(f"Erreur {xpi_path.name}: {e}")