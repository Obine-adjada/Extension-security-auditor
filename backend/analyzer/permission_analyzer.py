import json
from datetime import datetime, timezone

class PermissionAnalyzer:
    """
    Analyseur avancé de permissions d'extensions navigateur
    """
    def __init__(self, config=None):
        self.config = config or {}
        
        # Permissions par catégorie de risque
        self.critical_permissions = {
            'debugger': {
                'weight': 25,
                'reason': 'Accès complet au débogueur - peut intercepter tout le trafic'
            },
            'management': {
                'weight': 20,
                'reason': 'Peut gérer/désinstaller d\'autres extensions'
            },
            'nativeMessaging': {
                'weight': 20,
                'reason': 'Communication avec applications natives du système'
            },
            'proxy': {
                'weight': 20,
                'reason': 'Contrôle total du trafic réseau'
            }
        }
        
        self.high_risk_permissions = {
            'cookies': {
                'weight': 15,
                'reason': 'Accès aux cookies - risque de vol de session'
            },
            'webRequest': {
                'weight': 15,
                'reason': 'Interception des requêtes HTTP'
            },
            'webRequestBlocking': {
                'weight': 15,
                'reason': 'Blocage et modification des requêtes'
            },
            '<all_urls>': {
                'weight': 18,
                'reason': 'Accès à tous les sites web'
            },
            'tabs': {
                'weight': 12,
                'reason': 'Accès aux onglets - peut lire URLs et titres'
            },
            'history': {
                'weight': 12,
                'reason': 'Accès complet à l\'historique de navigation'
            },
            'downloads': {
                'weight': 10,
                'reason': 'Gestion des téléchargements'
            }
        }
        
        self.medium_risk_permissions = {
            'storage': {
                'weight': 5,
                'reason': 'Stockage local de données'
            },
            'notifications': {
                'weight': 3,
                'reason': 'Affichage de notifications'
            },
            'activeTab': {
                'weight': 4,
                'reason': 'Accès à l\'onglet actif uniquement'
            },
            'bookmarks': {
                'weight': 6,
                'reason': 'Accès aux favoris'
            },
            'topSites': {
                'weight': 6,
                'reason': 'Accès aux sites les plus visités'
            },
            'contextMenus': {
                'weight': 3,
                'reason': 'Modification des menus contextuels'
            },
            'declarativeNetRequest': {
                'weight': 8,
                'reason': 'Filtrage réseau déclaratif'
            }
        }
        # Patterns d'URLs à risque
        self.url_patterns = {
            'all_sites': ['<all_urls>', 'http://*/*', 'https://*/*'],
            'financial': ['*://*/checkout/*', '*://*/payment/*', '*://*/billing/*'],
            'admin': ['*://*/admin/*', '*://*/wp-admin/*'],
            'api': ['*://*/api/*']
        }
        # Combinaisons dangereuses
        self.dangerous_combinations = [
            {
                'permissions': ['cookies', 'webRequest'],
                'weight': 25,
                'reason': 'Peut intercepter et voler tous les cookies'
            },
            {
                'permissions': ['cookies', '<all_urls>'],
                'weight': 20,
                'reason': 'Accès complet aux cookies de tous les sites'
            },
            {
                'permissions': ['tabs', 'webRequest'],
                'weight': 15,
                'reason': 'Surveillance complète de la navigation'
            },
            {
                'permissions': ['management', 'tabs'],
                'weight': 15,
                'reason': 'Contrôle complet des extensions et navigation'
            },
            {
                'permissions': ['webRequestBlocking', 'cookies'],
                'weight': 20,
                'reason': 'Modification de requêtes et vol de cookies'
            }
        ]
    
    def analyze(self, extension_data):
        """
        Analyse complète d'une extension
        Args:
            extension_data: Dict avec manifest et métadonnées
        Returns:
            dict: Résultat de l'analyse avec score et détails
        """
        manifest = extension_data.get('manifest', {})
        permissions = manifest.get('permissions', [])
        
        analysis = {
            'extension_id': extension_data.get('id'),
            'name': manifest.get('name', 'Unknown'),
            'permissions_count': len(permissions),
            'risk_score': 0,
            'risk_level': 'low',
            'flags': [],
            'permission_details': [],
            'dangerous_combinations': [],
            'recommendations': []
        }
        for perm in permissions:
            perm_analysis = self._analyze_permission(perm)
            analysis['risk_score'] += perm_analysis['weight']
            analysis['permission_details'].append(perm_analysis)
        
        combo_score = self._check_dangerous_combinations(permissions)
        if combo_score > 0:
            analysis['risk_score'] += combo_score

        analysis['risk_score'] += self._check_manifest_version(manifest)
        analysis['risk_score'] += self._check_excessive_permissions(permissions)
        analysis['risk_score'] += self._check_background_scripts(manifest)
        analysis['risk_score'] += self._check_content_scripts(manifest)
        analysis['risk_score'] = min(analysis['risk_score'], 100)
        
        if analysis['risk_score'] >= 70:
            analysis['risk_level'] = 'critical'
        elif analysis['risk_score'] >= 50:
            analysis['risk_level'] = 'high'
        elif analysis['risk_score'] >= 30:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'low'
        
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_permission(self, permission):
        """
        Analyse une permission individuelle.
        """
        perm_lower = permission.lower()
        if permission in self.critical_permissions:
            info = self.critical_permissions[permission]
            return {
                'permission': permission,
                'category': 'critical',
                'weight': info['weight'],
                'reason': info['reason']
            }
        
        if permission in self.high_risk_permissions:
            info = self.high_risk_permissions[permission]
            return {
                'permission': permission,
                'category': 'high',
                'weight': info['weight'],
                'reason': info['reason']
            }
        
        if permission in self.medium_risk_permissions:
            info = self.medium_risk_permissions[permission]
            return {
                'permission': permission,
                'category': 'medium',
                'weight': info['weight'],
                'reason': info['reason']
            }
        if any(pattern in permission for pattern in self.url_patterns['all_sites']):
            return {
                'permission': permission,
                'category': 'high',
                'weight': 18,
                'reason': 'Accès très large à tous les sites'
            }
        
        if 'http://' in permission or 'https://' in permission:
            return {
                'permission': permission,
                'category': 'medium',
                'weight': 8,
                'reason': 'Accès à des domaines spécifiques'
            }
        return {
            'permission': permission,
            'category': 'low',
            'weight': 2,
            'reason': 'Permission standard'
        }
    
    def _check_dangerous_combinations(self, permissions):
        """
        Vérifie les combinaisons dangereuses de permissions
        """
        additional_score = 0
        
        for combo in self.dangerous_combinations:
            combo_perms = combo['permissions']
            if all(any(cp in p for p in permissions) for cp in combo_perms):
                additional_score += combo['weight']
        
        return additional_score
    
    def _check_manifest_version(self, manifest):
        """
        Pénalité pour Manifest V2 
        """
        version = manifest.get('manifest_version', 2)
        if version == 2:
            return 5
        return 0
    
    def _check_excessive_permissions(self, permissions):
        """
        Pénalité si trop de permissions demandées
        """
        count = len(permissions)
        if count > 15:
            return 15
        elif count > 10:
            return 10
        elif count > 7:
            return 5
        return 0
    
    def _check_background_scripts(self, manifest):
        """
        Analyse des scripts en arrière-plan
        """
        background = manifest.get('background', {})
        if not background:
            return 0
        if background.get('persistent', False):
            return 8
        
        if background.get('service_worker') or background.get('scripts'):
            return 5
        
        return 0
    
    def _check_content_scripts(self, manifest):
        """
        Analyse des content scripts
        """
        content_scripts = manifest.get('content_scripts', [])
        
        if not content_scripts:
            return 0
        
        score = 0
        score += min(len(content_scripts) * 2, 10)
        for script in content_scripts:
            matches = script.get('matches', [])
            if '<all_urls>' in matches or 'http://*/*' in matches or 'https://*/*' in matches:
                score += 8
                break
        
        return score
    
    def _generate_recommendations(self, analysis):
        """
        Génère des recommandations basées sur l'analyse
        """
        recommendations = []
        
        if analysis['risk_score'] >= 70:
            recommendations.append({
                'severity': 'critical',
                'message': 'Extension à risque critique - Bloquer immédiatement'
            })
        
        if analysis['risk_score'] >= 50:
            recommendations.append({
                'severity': 'high',
                'message': 'Audit manuel requis avant autorisation'
            })
        critical_perms = [p for p in analysis['permission_details'] if p['category'] == 'critical']
        if critical_perms:
            recommendations.append({
                'severity': 'high',
                'message': f'{len(critical_perms)} permission(s) critique(s) détectée(s)'
            })
        
        if analysis['permissions_count'] > 10:
            recommendations.append({
                'severity': 'medium',
                'message': 'Nombre de permissions excessif - Vérifier la légitimité'
            })
        
        return recommendations
