from flask import Flask, request, jsonify
from datetime import datetime, timezone
import sys
from pathlib import Path
import socket
import yaml
current_dir = Path(__file__).parent
backend_dir = current_dir.parent
root_dir = backend_dir.parent
sys.path.insert(0, str(backend_dir))
sys.path.insert(0, str(root_dir))
database_path = backend_dir / 'database'
models_path = backend_dir / 'models'
analyzer_path = backend_dir / 'analyzer'
sys.path.insert(0, str(database_path))
sys.path.insert(0, str(models_path))
sys.path.insert(0, str(analyzer_path))
from db_manager import DatabaseManager
from permission_analyzer import PermissionAnalyzer
from threat_intel import ThreatIntelligence
from code_scanner import CodeScanner
from remediation.policy_enforcer import PolicyEnforcer
from remediation.actions import RemediationActions
from remediation.report_generator import ReportGenerator
app = Flask(__name__)

config_path = Path(__file__).parent.parent.parent / "config" / "config.yaml"
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)
db = DatabaseManager(config['backend']['database'])
DANGEROUS_PERMISSIONS = config['analysis']['dangerous_permissions']

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Endpoint de santé pour vérifier que l'API fonctionne
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'database': 'connected'
    }), 200

@app.route('/api/extensions', methods=['POST'])
def receive_extensions():
    """
    Reçoit l'inventaire d'extensions depuis un agent
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if 'extensions' not in data:
            return jsonify({'error': 'Missing extensions field'}), 400
        
        extensions_data = data.get('extensions', [])
        stats = data.get('statistics', {})
        hostname = data.get('hostname', 'unknown')
        scan_id = db.record_scan(stats, hostname)
        # Traite chaque extension
        processed_count = 0
        for ext_data in extensions_data:
            try:
                print(f"Traitement: {ext_data.get('manifest', {}).get('name', 'Unknown')}")
                
                # Analyse avancée de l'extension
                analyzer = PermissionAnalyzer()
                analysis = analyzer.analyze(ext_data)
                
                # Utilise le score de l'analyseur
                risk_score = analysis['risk_score']
                
                # Prépare les données pour la base avec le risk_score
                db_data = ext_data.copy()
                
                extension_pk = db.add_extension(db_data)
                
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE extensions 
                        SET risk_score = ?
                        WHERE id = ?
                    """, (risk_score, extension_pk))
                
                # Marque les permissions dangereuses
                mark_dangerous_permissions(extension_pk, ext_data['manifest']['permissions'])
                
                # Sauvegarde le scan de code s'il existe
                if 'code_scan' in ext_data and ext_data['code_scan']:
                    db.save_code_scan(extension_pk, ext_data['code_scan'])
                    print(f"  Code scan sauvegardé: {ext_data['code_scan']['total_findings']} findings")
                
                # Crée des alertes si score élevé
                if risk_score > 70:
                    create_alert(extension_pk, 'high_risk', 'critical',
                               f"Extension à risque critique détectée: {ext_data['manifest']['name']}")
                elif risk_score > 50:
                    create_alert(extension_pk, 'high_risk', 'high',
                               f"Extension à risque élevé détectée: {ext_data['manifest']['name']}")
                
                processed_count += 1
                
            except Exception as e:
                print(f"Erreur traitement extension: {e}")
                import traceback
                traceback.print_exc()
                continue

        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'processed': processed_count,
            'total': len(extensions_data)
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extensions', methods=['GET'])
def get_extensions():
    """
    Récupère toutes les extensions avec filtres optionnels
    """
    try:
        browser = request.args.get('browser')
        risk_min = request.args.get('risk_min', type=int)
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        extensions = db.get_all_extensions(active_only=active_only)
        
        if browser:
            extensions = [e for e in extensions if e['browser'] == browser]
        if risk_min is not None:
            extensions = [e for e in extensions if e['risk_score'] >= risk_min]
        return jsonify({
            'count': len(extensions),
            'extensions': extensions
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extensions/<int:extension_id>', methods=['GET'])
def get_extension_details(extension_id):
    """
    Récupère les détails d'une extension spécifique
    """
    try:
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        return jsonify(extension), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """
    Récupère des statistiques globales
    """
    try:
        stats = db.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extensions/<int:extension_id>', methods=['GET'])
def get_extension_detail(extension_id):
    """
    Récupère les détails d'une extension spécifique
    """
    try:
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        
        return jsonify(extension), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    Récupère les alertes non résolues
    """
    try:
        severity = request.args.get('severity')
        resolved = request.args.get('resolved', 'false').lower() == 'true'
        
        with db.get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT a.*, e.name as extension_name, e.browser 
                FROM alerts a
                JOIN extensions e ON a.extension_fk = e.id
                WHERE a.is_resolved = ?
            """
            params = [1 if resolved else 0]
            if severity:
                query += " AND a.severity = ?"
                params.append(severity)
            query += " ORDER BY a.created_at DESC"
            cursor.execute(query, params)
            alerts = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({
            'count': len(alerts),
            'alerts': alerts
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extensions/<int:extension_id>/analysis', methods=['GET'])
def get_extension_analysis(extension_id):
    """
    Récupère l'analyse détaillée d'une extension
    """
    try:
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        
        ext_data = {
            'id': extension['extension_id'],
            'manifest': {
                'name': extension['name'],
                'version': extension['version'],
                'manifest_version': extension['manifest_version'],
                'permissions': [p['name'] for p in extension['permissions']],
                'description': extension.get('description', ''),
                'author': extension.get('author', 'Unknown')
            }
        }
        analyzer = PermissionAnalyzer()
        analysis = analyzer.analyze(ext_data)
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extensions/<int:extension_id>/threat-intel', methods=['GET'])
def get_threat_intel(extension_id):
    """
    Récupère les informations threat intelligence pour une extension
    """
    try:
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        
        ext_data = {
            'id': extension['extension_id'],
            'manifest': {
                'name': extension['name'],
                'version': extension['version'],
                'update_url': extension.get('homepage_url', '')
            }
        }
        ti_config = config.get('threat_intel', {})
        ti = ThreatIntelligence(ti_config)
        ti_result = ti.check_extension(ext_data)
        
        return jsonify(ti_result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extensions/<int:extension_id>/code-scan', methods=['GET'])
def get_code_scan(extension_id):
    """
    Récupère le scan de code d'une extension
    """
    try:
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        
        # Récupère le dernier scan depuis la base
        latest_scan = db.get_latest_code_scan(extension['id'])
        
        if latest_scan and latest_scan.get('scan_results'):
            return jsonify(latest_scan['scan_results']), 200
        else:
            return jsonify({
                'error': 'Aucun scan de code disponible',
                'files_scanned': 0,
                'total_findings': 0,
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'findings': []
            }), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/remediation/evaluate/<int:extension_id>', methods=['GET'])
def evaluate_for_remediation(extension_id):
    """
    Évalue une extension et retourne les actions recommandées
    """
    try:
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        
        ext_data = {
            'id': extension['extension_id'],
            'manifest': {
                'name': extension['name'],
                'version': extension['version'],
                'manifest_version': extension['manifest_version'],
                'permissions': [p['name'] for p in extension['permissions']]
            },
            'browser': extension['browser'],
            'installed_path': extension.get('installed_path')
        }
        
        # Analyse des permissions
        analyzer = PermissionAnalyzer()
        analysis = analyzer.analyze(ext_data)
        
        # Scan de code 
        code_scan = db.get_latest_code_scan(extension['id'])
        code_scan_results = code_scan.get('scan_results') if code_scan else None
        
        # Évaluation par le policy enforcer
        enforcer = PolicyEnforcer(config.get('remediation', {}))
        evaluation = enforcer.evaluate_extension(ext_data, analysis, code_scan_results)
        
        return jsonify(evaluation), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/remediation/apply/<int:extension_id>', methods=['POST'])
def apply_remediation(extension_id):
    """
    Applique les actions de remediation sur une extension
    
    Body JSON:
    {
        "dry_run": true/false,
        "actions": ["disable", "quarantine"]  // Optionnel, sinon utilise auto_actions
    }
    """
    try:
        data = request.get_json() or {}
        dry_run = data.get('dry_run', True)  # Par défaut en mode dry-run
        
        extension = db.get_extension_by_id(extension_id)
        
        if not extension:
            return jsonify({'error': 'Extension not found'}), 404
        
        ext_data = {
            'id': extension['extension_id'],
            'manifest': {
                'name': extension['name'],
                'version': extension['version'],
                'permissions': [p['name'] for p in extension['permissions']]
            },
            'browser': extension['browser'],
            'installed_path': extension.get('installed_path')
        }
        
        # Évaluation
        analyzer = PermissionAnalyzer()
        analysis = analyzer.analyze(ext_data)
        
        code_scan = db.get_latest_code_scan(extension['id'])
        code_scan_results = code_scan.get('scan_results') if code_scan else None
        
        enforcer = PolicyEnforcer(config.get('remediation', {}))
        evaluation = enforcer.evaluate_extension(ext_data, analysis, code_scan_results)
        
        # Applique les actions
        results = enforcer.apply_remediation(ext_data, evaluation, dry_run)
        
        return jsonify(results), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/remediation/quarantine/list', methods=['GET'])
def list_quarantined():
    """
    Liste toutes les extensions en quarantaine
    """
    try:
        actions = RemediationActions()
        quarantined = actions.list_quarantined()
        
        return jsonify({
            'count': len(quarantined),
            'extensions': quarantined
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remediation/quarantine/restore', methods=['POST'])
def restore_quarantined():
    """
    Restaure une extension depuis la quarantaine
    """
    try:
        data = request.get_json()
        quarantine_path = data.get('quarantine_path')
        dry_run = data.get('dry_run', True)
        
        if not quarantine_path:
            return jsonify({'error': 'quarantine_path required'}), 400
        actions = RemediationActions()
        result = actions.restore_from_quarantine(quarantine_path, dry_run)
        return jsonify(result), 200  
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remediation/report', methods=['GET'])
def generate_remediation_report():
    """
    Génère un rapport global de remediation
    """
    try:
        # Récupère toutes les extensions
        extensions = db.get_all_extensions(active_only=True)
        
        evaluations = []
        actions_results = []
        
        analyzer = PermissionAnalyzer()
        enforcer = PolicyEnforcer(config.get('remediation', {}))
        
        for ext in extensions:
            ext_data = {
                'id': ext['extension_id'],
                'manifest': {
                    'name': ext['name'],
                    'version': ext['version'],
                    'manifest_version': ext.get('manifest_version', 2),
                    'permissions': []
                },
                'browser': ext['browser'],
                'installed_path': ext.get('installed_path', '')
            }
            
            # Récupère les permissions depuis la base
            # ext['permissions'] est déjà une liste de dicts avec 'name'
            if ext.get('permissions'):
                if isinstance(ext['permissions'], list):
                    ext_data['manifest']['permissions'] = [
                        p['name'] if isinstance(p, dict) else str(p) 
                        for p in ext['permissions']
                    ]
            
            analysis = analyzer.analyze(ext_data)
            
            code_scan = db.get_latest_code_scan(ext['id'])
            code_scan_results = code_scan.get('scan_results') if code_scan else None
            
            evaluation = enforcer.evaluate_extension(ext_data, analysis, code_scan_results)
            evaluations.append(evaluation)
        
        report_gen = ReportGenerator()
        report = report_gen.generate_remediation_report(evaluations, actions_results)
        
        return jsonify(report), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500
        
def mark_dangerous_permissions(extension_pk, permissions):
    """
    Marque les permissions dangereuses dans la base
    """
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        for perm in permissions:
            is_dangerous = any(d in perm for d in DANGEROUS_PERMISSIONS)
            cursor.execute("""
                UPDATE permissions 
                SET is_dangerous = ? 
                WHERE extension_fk = ? AND permission = ?
            """, (1 if is_dangerous else 0, extension_pk, perm))

def create_alert(extension_pk, alert_type, severity, message):
    """
    Crée une alerte pour une extension
    """
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (extension_fk, alert_type, severity, message)
            VALUES (?, ?, ?, ?)
        """, (extension_pk, alert_type, severity, message))
