"""
Générateur de rapports de remediation
"""
from datetime import datetime, timezone
import json

class ReportGenerator:
    """
    Génère des rapports de remediation
    """
    def __init__(self):
        self.reports = []
    
    def generate_remediation_report(self, evaluations, actions_results):
        """
        Génère un rapport complet de remediation.
        """
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'total_extensions_evaluated': len(evaluations),
                'critical_severity': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'whitelisted': 0,
                'blacklisted': 0,
                'actions_executed': 0,
                'actions_failed': 0
            },
            'evaluations': evaluations,
            'actions': actions_results
        }
        
        for eval_data in evaluations:
            severity = eval_data.get('severity', 'low')
            status = eval_data.get('status', '')
            
            if status == 'whitelisted':
                report['summary']['whitelisted'] += 1
            elif status == 'blacklisted':
                report['summary']['blacklisted'] += 1
            
            if severity == 'critical':
                report['summary']['critical_severity'] += 1
            elif severity == 'high':
                report['summary']['high_severity'] += 1
            elif severity == 'medium':
                report['summary']['medium_severity'] += 1
            else:
                report['summary']['low_severity'] += 1
        
        for action_result in actions_results:
            report['summary']['actions_executed'] += len(action_result.get('actions_executed', []))
            report['summary']['actions_failed'] += len(action_result.get('actions_failed', []))
        
        self.reports.append(report)
        return report
    
    def format_report_text(self, report):
        """
        Formate un rapport en texte lisible.
        """
        lines = []
        lines.append("RAPPORT DE REMEDIATION")
        lines.append(f"Généré le: {report['generated_at']}")
        lines.append("")
        
        summary = report['summary']
        lines.append("RÉSUMÉ")
        lines.append(f"Extensions évaluées:     {summary['total_extensions_evaluated']}")
        lines.append(f"  Critique:              {summary['critical_severity']}")
        lines.append(f"  Élevé:                 {summary['high_severity']}")
        lines.append(f"  Moyen:                 {summary['medium_severity']}")
        lines.append(f"  Faible:                {summary['low_severity']}")
        lines.append(f"  Whitelistées:          {summary['whitelisted']}")
        lines.append(f"  Blacklistées:          {summary['blacklisted']}")
        lines.append("")
        lines.append(f"Actions exécutées:       {summary['actions_executed']}")
        lines.append(f"Actions échouées:        {summary['actions_failed']}")
        lines.append("")
        
        critical_exts = [e for e in report['evaluations'] if e.get('severity') == 'critical']
        if critical_exts:
            lines.append("EXTENSIONS CRITIQUES")
            for ext in critical_exts:
                lines.append(f"\n• {ext['extension_name']}")
                lines.append(f"  Score de risque: {ext['risk_score']}/100")
                lines.append(f"  Raisons:")
                for reason in ext['reasons']:
                    lines.append(f"    - {reason}")
                if ext.get('auto_actions'):
                    lines.append(f"  Actions automatiques: {', '.join(ext['auto_actions'])}")
            lines.append("")
        
        return "\n".join(lines)
    
    def export_report_json(self, report, filepath):
        """
        Exporte un rapport en JSON
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)