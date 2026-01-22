import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
import json

class DatabaseManager:
    """
    Gestionnaire de la base de données SQLite
    """
    def __init__(self, db_path="backend/database/extensions.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """
        Context manager pour les connexions SQLite
        Assure la fermeture automatique de la connexion
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """
        Initialise la base de données avec le schéma
        """
        schema_path = Path(__file__).parent / "schema.sql"
        
        with open(schema_path, 'r') as f:
            schema = f.read()
        with self.get_connection() as conn:
            conn.executescript(schema)
        
        print(f"Base de données initialisée: {self.db_path}")
    
    def add_extension(self, extension_data):
        """
        Ajoute ou met à jour une extension dans la base
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            manifest = extension_data.get('manifest', {})
            ext_id = extension_data.get('id', 'unknown')
            browser = extension_data.get('browser', 'unknown')
            path = extension_data.get('installed_path', '')
            
            cursor.execute("""
                SELECT id FROM extensions 
                WHERE extension_id = ? AND browser = ?
            """, (ext_id, browser))
            existing = cursor.fetchone()
            if existing:
                extension_pk = existing[0]
                cursor.execute("""
                    UPDATE extensions 
                    SET version = ?, last_seen = ?, is_active = 1
                    WHERE id = ?
                """, (
                    manifest.get('version', 'unknown'),
                    datetime.now(timezone.utc).isoformat(),
                    extension_pk
                ))
                cursor.execute("DELETE FROM permissions WHERE extension_fk = ?", (extension_pk,))
            else:
                name = str(manifest.get('name', 'Unknown'))
                version = str(manifest.get('version', 'unknown'))
                manifest_version = int(manifest.get('manifest_version', 2))
                description = str(manifest.get('description', ''))[:500]  # Limite à 500 chars
                author = str(manifest.get('author', 'Unknown'))[:100]
                homepage = str(manifest.get('homepage_url', ''))[:200]
                profile = str(extension_data.get('profile', 'default'))[:50]
                
                cursor.execute("""
                    INSERT INTO extensions (
                        extension_id, browser, name, version, 
                        manifest_version, description, author, 
                        homepage_url, installed_path, profile
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ext_id, browser, name, version,
                    manifest_version, description, author,
                    homepage, path, profile
                ))
                
                extension_pk = cursor.lastrowid
            permissions = manifest.get('permissions', [])
            if isinstance(permissions, list):
                for perm in permissions:
                    if isinstance(perm, str):
                        cursor.execute(
                            "INSERT INTO permissions (extension_fk, permission) VALUES (?, ?)",
                            (extension_pk, perm)
                        )
            return extension_pk
            
    def record_scan(self, scan_stats, hostname="unknown"):
        """
        Enregistre les statistiques d'un scan
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (
                    total_extensions, chrome_count, 
                    firefox_count, edge_count, hostname
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                scan_stats['total'],
                scan_stats['chrome'],
                scan_stats['firefox'],
                scan_stats['edge'],
                hostname
            ))
            
            return cursor.lastrowid
    
    def get_all_extensions(self, active_only=True):
        """
        Récupère toutes les extensions de la base
        Args:
            active_only: Si True, ne retourne que les extensions actives
        Returns:
            list: Liste de dicts avec les données des extensions
        """
        query = "SELECT * FROM extensions"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY risk_score DESC, name ASC"
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            extensions = []
            for row in cursor.fetchall():
                ext = dict(row)
                cursor.execute("""
                    SELECT permission FROM permissions 
                    WHERE extension_fk = ?
                """, (ext['id'],))
                
                ext['permissions'] = [p[0] for p in cursor.fetchall()]
                extensions.append(ext)
            return extensions
    
    def get_extension_by_id(self, extension_pk):
        """
        Récupère une extension spécifique avec ses permissions
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM extensions WHERE id = ?", 
                         (extension_pk,))
            row = cursor.fetchone()
            if not row:
                return None
            extension = dict(row)
            cursor.execute("""
                SELECT permission, is_dangerous 
                FROM permissions 
                WHERE extension_fk = ?
            """, (extension_pk,))
            extension['permissions'] = [
                {'name': p[0], 'is_dangerous': bool(p[1])} 
                for p in cursor.fetchall()
            ]
            return extension
    
    def get_statistics(self):
        """
        Retourne des statistiques globales
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            cursor.execute("SELECT COUNT(*) FROM extensions WHERE is_active = 1")
            stats['total_extensions'] = cursor.fetchone()[0]
            cursor.execute("""
                SELECT browser, COUNT(*) 
                FROM extensions 
                WHERE is_active = 1 
                GROUP BY browser
            """)
            stats['by_browser'] = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.execute("""
                SELECT COUNT(*) 
                FROM extensions 
                WHERE is_active = 1 AND risk_score > 50
            """)
            stats['high_risk_count'] = cursor.fetchone()[0]
            cursor.execute("""
                SELECT scan_time, total_extensions 
                FROM scans 
                ORDER BY scan_time DESC 
                LIMIT 1
            """)
            last_scan = cursor.fetchone()
            if last_scan:
                stats['last_scan'] = {
                    'time': last_scan[0],
                    'count': last_scan[1]
                }
            return stats
    
    def save_code_scan(self, extension_pk, scan_results):
        """
        Sauvegarde les résultats d'un scan de code
        Args:
            extension_pk: ID de l'extension
            scan_results: Dict avec les résultats du scan
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO code_scans (
                    extension_fk, files_scanned, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    obfuscation_score, scan_results
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                extension_pk,
                scan_results.get('files_scanned', 0),
                scan_results.get('total_findings', 0),
                scan_results['severity_counts']['critical'],
                scan_results['severity_counts']['high'],
                scan_results['severity_counts']['medium'],
                scan_results['severity_counts']['low'],
                scan_results.get('obfuscation_score', 0),
                json.dumps(scan_results)
            ))
            
            return cursor.lastrowid
    
    def get_latest_code_scan(self, extension_pk):
        """
        Récupère le dernier scan de code pour une extension
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM code_scans
                WHERE extension_fk = ?
                ORDER BY scanned_at DESC
                LIMIT 1
            """, (extension_pk,))
            
            row = cursor.fetchone()
            
            if not row:
                return None
            
            result = dict(row)
            if result.get('scan_results'):
                result['scan_results'] = json.loads(result['scan_results'])
            return result
