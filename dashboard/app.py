from flask import Flask, render_template, jsonify, request
import sys
import requests
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.database.db_manager import DatabaseManager
import yaml
app = Flask(__name__)
config_path = Path(__file__).parent.parent / "config" / "config.yaml"
with open(config_path, 'r') as f:
    config = yaml.safe_load(f)
db = DatabaseManager(config['backend']['database'])

@app.route('/')
def index():
    """
    Page d'accueil du dashboard
    """
    return render_template('index.html')

@app.route('/extensions')
def extensions():
    """
    Page d'inventaire des extensions
    """
    return render_template('extensions.html')

@app.route('/extension/<int:ext_id>')
def extension_detail(ext_id):
    """
    Page de détails d'une extension
    """
    return render_template('extension_detail.html', ext_id=ext_id)
    
@app.route('/api/extensions/<int:ext_id>')
def get_extension_detail(ext_id):
    """
    Récupère les détails d'une extension depuis l'API backend
    """
    try:
        response = requests.get(f"http://127.0.0.1:5000/api/extensions/{ext_id}")
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Extension not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/alerts')
def alerts():
    """
    Page des alertes
    """
    return render_template('alerts.html')

@app.route('/scans')
def scans():
    """
    Page d'historique des scans
    """
    return render_template('scans.html')

@app.route('/api/dashboard/stats')
def dashboard_stats():
    """
    API pour les statistiques du dashboard
    """
    stats = db.get_statistics()
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN risk_score >= 70 THEN 'critical'
                    WHEN risk_score >= 50 THEN 'high'
                    WHEN risk_score >= 30 THEN 'medium'
                    ELSE 'low'
                END as risk_level,
                COUNT(*) as count
            FROM extensions
            WHERE is_active = 1
            GROUP BY risk_level
        """)
        stats['risk_distribution'] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Les permissions les plus utilisées
        cursor.execute("""
            SELECT p.permission, COUNT(*) as count
            FROM permissions p
            JOIN extensions e ON p.extension_fk = e.id
            WHERE e.is_active = 1
            GROUP BY p.permission
            ORDER BY count DESC
            LIMIT 5
        """)
        stats['top_permissions'] = [
            {'permission': row[0], 'count': row[1]} 
            for row in cursor.fetchall()
        ]
    
    return jsonify(stats)

@app.route('/api/dashboard/extensions')
def dashboard_extensions():
    """
    API pour la liste des extensions avec filtres
    """
    extensions = db.get_all_extensions(active_only=True)
    return jsonify(extensions)

@app.route('/api/dashboard/alerts')
def dashboard_alerts():
    """
    API pour les alertes actives
    """
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                a.id, a.alert_type, a.severity, a.message, 
                a.created_at, e.name, e.browser
            FROM alerts a
            JOIN extensions e ON a.extension_fk = e.id
            WHERE a.is_resolved = 0
            ORDER BY 
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                a.created_at DESC
        """)
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'type': row[1],
                'severity': row[2],
                'message': row[3],
                'created_at': row[4],
                'extension_name': row[5],
                'browser': row[6]
            })
    
    return jsonify(alerts)

@app.route('/api/dashboard/scans')
def dashboard_scans():
    """
    API pour l'historique des scans
    """
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, scan_time, total_extensions, 
                   chrome_count, firefox_count, edge_count, hostname
            FROM scans
            ORDER BY scan_time DESC
            LIMIT 20
        """)
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'scan_time': row[1],
                'total': row[2],
                'chrome': row[3],
                'firefox': row[4],
                'edge': row[5],
                'hostname': row[6]
            })
    
    return jsonify(scans)

@app.route('/api/dashboard/threat-intel/<int:ext_id>')
def dashboard_threat_intel(ext_id):
    """
    API pour les informations threat intelligence
    """
    try:
        response = requests.get(f"http://127.0.0.1:5000/api/extensions/{ext_id}/threat-intel")
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Threat intel non disponible'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/code-scan/<int:ext_id>')
def dashboard_code_scan(ext_id):
    """
    API pour le scan de code
    """
    try:
        response = requests.get(f"http://127.0.0.1:5000/api/extensions/{ext_id}/code-scan")
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Code scan non disponible'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/remediation')
def remediation():
    """
    Page de remediation
    """
    return render_template('remediation.html')

@app.route('/api/dashboard/remediation/report')
def dashboard_remediation_report():
    """
    Proxy pour le rapport de remediation
    """
    try:
        response = requests.get('http://127.0.0.1:5000/api/remediation/report')
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/remediation/apply/<int:ext_id>', methods=['POST'])
def dashboard_remediation_apply(ext_id):
    """
    Proxy pour appliquer la remediation
    """
    try:
        data = request.get_json()
        response = requests.post(
            f'http://127.0.0.1:5000/api/remediation/apply/{ext_id}',
            json=data
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/remediation/quarantine/list')
def dashboard_remediation_quarantine_list():
    """
    Proxy pour lister les extensions en quarantaine
    """
    try:
        response = requests.get('http://127.0.0.1:5000/api/remediation/quarantine/list')
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500