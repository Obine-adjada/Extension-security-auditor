#!/usr/bin/env python3
"""
Browser Extension Security Auditor
Point d'entrée principal du projet

Usage:
    python main.py              # Lance backend + dashboard
    python main.py --api-only   # Lance seulement l'API
    python main.py --dash-only  # Lance seulement le dashboard
    python main.py --agent      # Lance l'agent de collecte 
"""

import sys
import os
import threading
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

def clear_screen():
    """Nettoie l'écran."""
    os.system('clear' if os.name != 'nt' else 'cls')

def run_api_backend():
    """Lance le serveur API Backend."""
    print("\n[API] Démarrage du serveur API Backend.")
    
    try:
        from backend.api.app import app, config
        
        host = config['backend']['host']
        port = config['backend']['port']
        
        print(f"[API] Serveur API: http://{host}:{port}")
        print(f"[API] Base de données: {config['backend']['database']}")
        print("\n[API] Endpoints disponibles:")
        print(f"      GET  http://{host}:{port}/api/health")
        print(f"      POST http://{host}:{port}/api/extensions")
        print(f"      GET  http://{host}:{port}/api/extensions")
        print(f"      GET  http://{host}:{port}/api/statistics")
        print(f"      GET  http://{host}:{port}/api/alerts")
        
        app.run(host=host, port=port, debug=False, use_reloader=False)
        
    except Exception as e:
        print(f"[API] ERREUR: {e}")
        import traceback
        traceback.print_exc()

def run_dashboard():
    """Lance le Dashboard Web"""
    print("\n[DASHBOARD] Démarrage du Dashboard Web")
    
    try:
        from dashboard.app import app
        
        host = '0.0.0.0'
        port = 8080
        
        print(f"[DASHBOARD] Interface web: http://127.0.0.1:{port}")
        print(f"[DASHBOARD]                http://0.0.0.0:{port}")
        print("\n[DASHBOARD] Pages disponibles:")
        print(f"            /            - Dashboard principal")
        print(f"            /extensions  - Inventaire des extensions")
        print(f"            /alerts      - Alertes de sécurité")
        print(f"            /scans       - Historique des scans")
        
        app.run(host=host, port=port, debug=False, use_reloader=False)
        
    except Exception as e:
        print(f"[DASHBOARD] ERREUR: {e}")
        import traceback
        traceback.print_exc()

def run_agent():
    """Lance l'agent de collecte """
    print("\n[AGENT] Démarrage de l'agent de collecte    ")
    
    try:
        from agent.agent import main as agent_main
        agent_main()
        
    except Exception as e:
        print(f"[AGENT] ERREUR: {e}")
        import traceback
        traceback.print_exc()

def run_all():
    """Lance API + Dashboard en parallèle"""
    clear_screen()
    print_banner()
    
    print("DÉMARRAGE DES SERVICES")
    
    api_thread = threading.Thread(target=run_api_backend, daemon=True)
    api_thread.start()
    import time
    time.sleep(2)
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    time.sleep(2)
    print("SERVICES ACTIFS")
    print("\nAPI Backend : http://127.0.0.1:5000")
    print("Dashboard  : http://127.0.0.1:8080")
    print("\nAppuyez sur Ctrl+C pour arrêter tous les services")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[MAIN] Arrêt des services   ")
        print("[MAIN] Au revoir !")
        sys.exit(0)

def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description='Browser Extension Security Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--api-only',
        action='store_true',
        help='Lance seulement le serveur API Backend'
    )
    
    parser.add_argument(
        '--dash-only',
        action='store_true',
        help='Lance seulement le Dashboard Web'
    )
    
    parser.add_argument(
        '--agent',
        action='store_true',
        help='Lance l\'agent de collecte '
    )
    
    args = parser.parse_args()
    if args.agent:
        clear_screen()
        run_agent()
    elif args.api_only:
        clear_screen()
        run_api_backend()
    elif args.dash_only:
        clear_screen()
        run_dashboard()
    else:
        run_all()

if __name__ == "__main__":
    main()