"""
Actions de remediation concrètes.
"""
import os
import shutil
import json
from pathlib import Path
from datetime import datetime, timezone
import platform

class RemediationActions:
    """
    Actions de remediation pour les extensions.
    """
    def __init__(self, quarantine_dir=None):
        if quarantine_dir:
            self.quarantine_dir = Path(quarantine_dir)
        else:
            self.quarantine_dir = Path.home() / 'SecurityQuarantine' / 'extensions'
        
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        self.action_log = []
    
    def disable_extension(self, extension_data, dry_run=False):
        """
        Désactive une extension navigateur
        Méthodes selon l'OS:
        - Windows: Renomme le dossier (.DISABLED)
        - Linux/macOS: Change les permissions (chmod 000)
        """
        ext_name = extension_data['manifest']['name']
        ext_path = Path(extension_data.get('installed_path', ''))
        os_type = platform.system()
        
        if dry_run:
            self._log_action('disable', ext_name, True, dry_run=True)
            return {
                'success': True,
                'dry_run': True,
                'message': f'[DRY-RUN] Extension serait désactivée: {ext_name}'
            }
        
        try:
            if not ext_path.exists():
                return {
                    'success': False,
                    'message': f'Chemin introuvable: {ext_path}'
                }
            
            if os_type == 'Windows':
                # Méthode Windows: Renommer
                disabled_path = ext_path.parent / f"{ext_path.name}.DISABLED"
                
                if disabled_path.exists():
                    return {
                        'success': False,
                        'message': 'Extension déjà désactivée'
                    }
                
                ext_path.rename(disabled_path)
                method = 'rename'
                
            else:
                # Méthode Linux/macOS: Chmod
                import stat
                
                os.chmod(ext_path, 0o000)
                marker_file = ext_path.parent / f".{ext_path.name}.disabled"
                marker_file.touch()
                
                method = 'chmod'
            
            self._log_action('disable', ext_name, True, details={'method': method})
            
            return {
                'success': True,
                'message': f'Extension désactivée: {ext_name} (méthode: {method})',
                'method': method
            }
            
        except Exception as e:
            self._log_action('disable', ext_name, False, error=str(e))
            return {
                'success': False,
                'message': f'Erreur désactivation: {str(e)}'
            }
    
    def quarantine_extension(self, extension_data, reason='Policy violation', dry_run=False):
        """
        Met une extension en quarantaine (déplace vers un dossier sécurisé)
        """
        ext_name = extension_data['manifest']['name']
        ext_id = extension_data.get('id')
        ext_path = Path(extension_data.get('installed_path', ''))
        
        if dry_run:
            self._log_action('quarantine', ext_name, True, dry_run=True)
            return {
                'success': True,
                'dry_run': True,
                'message': f'[DRY-RUN] Extension serait mise en quarantaine: {ext_name}'
            }
        
        try:
            if not ext_path.exists():
                return {
                    'success': False,
                    'message': f'Chemin introuvable: {ext_path}'
                }
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_name = f"{ext_id}_{timestamp}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            shutil.move(str(ext_path), str(quarantine_path))
            
            metadata = {
                'extension_id': ext_id,
                'name': ext_name,
                'version': extension_data['manifest'].get('version'),
                'browser': extension_data.get('browser'),
                'quarantine_date': datetime.now(timezone.utc).isoformat(),
                'original_path': str(ext_path),
                'reason': reason,
                'system': platform.system()
            }
            
            metadata_path = quarantine_path / 'QUARANTINE_INFO.json'
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            self._log_action('quarantine', ext_name, True, 
                           details={'quarantine_path': str(quarantine_path)})
            
            return {
                'success': True,
                'message': f'Extension mise en quarantaine: {ext_name}',
                'quarantine_path': str(quarantine_path),
                'metadata': metadata
            }
            
        except Exception as e:
            self._log_action('quarantine', ext_name, False, error=str(e))
            return {
                'success': False,
                'message': f'Erreur quarantaine: {str(e)}'
            }
    
    def remove_permissions(self, extension_data, permissions_to_remove, dry_run=False):
        """
        Retire des permissions dangereuses du manifest
        """
        ext_name = extension_data['manifest']['name']
        ext_path = Path(extension_data.get('installed_path', ''))
        manifest_path = ext_path / 'manifest.json'
        
        if dry_run:
            return {
                'success': True,
                'dry_run': True,
                'message': f'[DRY-RUN] Permissions seraient retirées de: {ext_name}',
                'permissions': permissions_to_remove
            }
        
        try:
            if not manifest_path.exists():
                return {
                    'success': False,
                    'message': 'Manifest introuvable'
                }
            backup_path = manifest_path.parent / 'manifest.json.backup'
            shutil.copy(manifest_path, backup_path)
            
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            original_perms = manifest.get('permissions', [])
            new_perms = [p for p in original_perms if p not in permissions_to_remove]
            
            manifest['permissions'] = new_perms
            
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)
            
            self._log_action('remove_permissions', ext_name, True,
                           details={'removed': permissions_to_remove})
            
            return {
                'success': True,
                'message': f'Permissions retirées de: {ext_name}',
                'removed_permissions': permissions_to_remove,
                'backup_path': str(backup_path)
            }
        except Exception as e:
            self._log_action('remove_permissions', ext_name, False, error=str(e))
            return {
                'success': False,
                'message': f'Erreur modification permissions: {str(e)}'
            }
    
    def restore_from_quarantine(self, quarantine_path, dry_run=False):
        """
        Restaure une extension depuis la quarantaine
        """
        quarantine_path = Path(quarantine_path)
        
        if not quarantine_path.exists():
            return {
                'success': False,
                'message': 'Dossier de quarantaine introuvable'
            }
        
        metadata_path = quarantine_path / 'QUARANTINE_INFO.json'
        
        if not metadata_path.exists():
            return {
                'success': False,
                'message': 'Métadonnées de quarantaine introuvables'
            }
        
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        original_path = Path(metadata['original_path'])
        
        if dry_run:
            return {
                'success': True,
                'dry_run': True,
                'message': f"[DRY-RUN] Extension serait restaurée vers: {original_path}"
            }
        
        try:
            if original_path.exists():
                return {
                    'success': False,
                    'message': 'Une extension existe déjà à l\'emplacement d\'origine'
                }
            
            shutil.move(str(quarantine_path), str(original_path))
            
            self._log_action('restore', metadata['name'], True,
                           details={'from': str(quarantine_path), 'to': str(original_path)})
            
            return {
                'success': True,
                'message': f"Extension restaurée: {metadata['name']}",
                'restored_path': str(original_path)
            }
            
        except Exception as e:
            self._log_action('restore', metadata.get('name', 'Unknown'), False, error=str(e))
            return {
                'success': False,
                'message': f'Erreur restauration: {str(e)}'
            }
    
    def list_quarantined(self):
        """
        Liste toutes les extensions en quarantaine
        """
        quarantined = []
        
        if not self.quarantine_dir.exists():
            return quarantined
        
        for item in self.quarantine_dir.iterdir():
            if item.is_dir():
                metadata_path = item / 'QUARANTINE_INFO.json'
                
                if metadata_path.exists():
                    with open(metadata_path, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                    
                    quarantined.append({
                        'quarantine_path': str(item),
                        'metadata': metadata
                    })
        
        return quarantined
    
    def _log_action(self, action_type, target, success, dry_run=False, error=None, details=None):
        """
        Enregistre une action dans le log
        """
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action_type,
            'target': target,
            'success': success,
            'dry_run': dry_run
        }
        
        if error:
            log_entry['error'] = error
        
        if details:
            log_entry['details'] = details
        
        self.action_log.append(log_entry)
    
    def get_action_log(self):
        """
        Retourne le log des actions effectuées
        """
        return self.action_log