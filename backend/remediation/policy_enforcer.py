"""
Policy Enforcer - Applique les politiques de sécurité.
"""
from datetime import datetime, timezone
from .actions import RemediationActions

class PolicyEnforcer:
    """
    Évalue les extensions et applique les politiques de sécurité
    """
    def __init__(self, config=None):
        self.config = config or {}
        self.actions_handler = RemediationActions()
        
        # Seuils de remediation
        self.thresholds = self.config.get('thresholds', {
            'auto_disable_score': 90,
            'auto_quarantine_score': 85,
            'critical_findings_max': 5,
            'obfuscation_max': 80,
            'high_findings_max': 15
        })
        
        # Politiques
        self.policies = self.config.get('policies', {
            'auto_remediation_enabled': False,
            'quarantine_on_blacklist': True,
            'disable_on_critical': True,
            'alert_on_high_risk': True
        })
        
        self.whitelist = self.config.get('whitelist') or []
        self.blacklist = self.config.get('blacklist') or []

    def evaluate_extension(self, extension_data, analysis_results, code_scan_results=None):
        """
        Évalue une extension et détermine les actions nécessaires.
        """
        ext_id = extension_data.get('id')
        ext_name = extension_data['manifest']['name']
        risk_score = analysis_results.get('risk_score', 0)
        
        evaluation = {
            'extension_id': ext_id,
            'extension_name': ext_name,
            'risk_score': risk_score,
            'status': 'evaluated',
            'recommended_actions': [],
            'auto_actions': [],
            'reasons': [],
            'severity': 'low'
        }
        
        if self._is_whitelisted(ext_id):
            evaluation['status'] = 'whitelisted'
            evaluation['reasons'].append('Extension approuvée (whitelist)')
            return evaluation
        
        if self._is_blacklisted(ext_id):
            evaluation['status'] = 'blacklisted'
            evaluation['severity'] = 'critical'
            evaluation['auto_actions'] = ['disable', 'quarantine']
            evaluation['reasons'].append('Extension blacklistée - Menace connue')
            return evaluation
        
        if risk_score >= self.thresholds['auto_disable_score']:
            evaluation['severity'] = 'critical'
            evaluation['auto_actions'].append('disable')
            evaluation['recommended_actions'].append('quarantine')
            evaluation['reasons'].append(f'Score de risque critique: {risk_score}/100')
        
        elif risk_score >= self.thresholds['auto_quarantine_score']:
            evaluation['severity'] = 'high'
            evaluation['recommended_actions'].append('quarantine')
            evaluation['reasons'].append(f'Score de risque élevé: {risk_score}/100')
        
        elif risk_score >= 50:
            evaluation['severity'] = 'medium'
            evaluation['recommended_actions'].append('review')
            evaluation['reasons'].append(f'Score de risque moyen: {risk_score}/100')
        
        if code_scan_results:
            critical_count = code_scan_results['severity_counts']['critical']
            high_count = code_scan_results['severity_counts']['high']
            obfusc_score = code_scan_results['obfuscation_score']
            
            if critical_count >= self.thresholds['critical_findings_max']:
                evaluation['severity'] = 'critical'
                if 'disable' not in evaluation['auto_actions']:
                    evaluation['auto_actions'].append('disable')
                evaluation['reasons'].append(f'{critical_count} findings critiques dans le code')
            
            if high_count >= self.thresholds['high_findings_max']:
                evaluation['recommended_actions'].append('review')
                evaluation['reasons'].append(f'{high_count} findings à risque élevé')
            
            if obfusc_score >= self.thresholds['obfuscation_max']:
                if evaluation['severity'] == 'low':
                    evaluation['severity'] = 'medium'
                evaluation['recommended_actions'].append('review')
                evaluation['reasons'].append(f'Code fortement obfusqué: {obfusc_score}/100')
        
        dangerous_combos = analysis_results.get('dangerous_combinations', [])
        if dangerous_combos:
            evaluation['recommended_actions'].append('review')
            evaluation['reasons'].append(f'{len(dangerous_combos)} combinaisons de permissions dangereuses')
        
        return evaluation
    
    def apply_remediation(self, extension_data, evaluation, dry_run=True):
        """
        Applique les actions de remediation
        Args:
            dry_run: Si True, simule sans exécuter
        """
        results = {
            'extension_id': evaluation['extension_id'],
            'extension_name': evaluation['extension_name'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dry_run': dry_run,
            'actions_executed': [],
            'actions_failed': [],
            'status': 'completed'
        }
        
        if not self.policies['auto_remediation_enabled'] and not dry_run:
            results['status'] = 'skipped'
            results['message'] = 'Auto-remediation désactivée'
            return results
        for action in evaluation.get('auto_actions', []):
            try:
                if action == 'disable':
                    result = self.actions_handler.disable_extension(extension_data, dry_run)
                    results['actions_executed'].append({
                        'action': 'disable',
                        'result': result
                    })
                
                elif action == 'quarantine':
                    reason = ' | '.join(evaluation['reasons'])
                    result = self.actions_handler.quarantine_extension(
                        extension_data, 
                        reason=reason, 
                        dry_run=dry_run
                    )
                    results['actions_executed'].append({
                        'action': 'quarantine',
                        'result': result
                    })
                
            except Exception as e:
                results['actions_failed'].append({
                    'action': action,
                    'error': str(e)
                })
        
        return results
    
    def _is_whitelisted(self, extension_id):
        """Vérifie si extension est whitelistée  """
        return any(w.get('extension_id') == extension_id for w in self.whitelist)
    
    def _is_blacklisted(self, extension_id):
        """Vérifie si extension est blacklistée """
        return any(b.get('extension_id') == extension_id for b in self.blacklist)
    
    def add_to_whitelist(self, extension_id, reason=''):
        """Ajoute une extension à la whitelist."""
        if not self._is_whitelisted(extension_id):
            self.whitelist.append({
                'extension_id': extension_id,
                'added_at': datetime.now(timezone.utc).isoformat(),
                'reason': reason
            })
            return True
        return False
    
    def add_to_blacklist(self, extension_id, reason=''):
        """Ajoute une extension à la blacklist """
        if not self._is_blacklisted(extension_id):
            self.blacklist.append({
                'extension_id': extension_id,
                'added_at': datetime.now(timezone.utc).isoformat(),
                'reason': reason
            })
            return True
        return False