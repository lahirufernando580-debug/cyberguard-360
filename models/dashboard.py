from collections import Counter
from datetime import timedelta

from odoo import api, fields, models

from .incident import CATEGORIES, STAGES

OPEN_ALERT = ('new', 'acknowledged', 'investigating')
OPEN_VULN = ('open', 'in_progress')


class CgDashboard(models.AbstractModel):
    _name = 'cg.dashboard'
    _description = 'CyberGuard Dashboard Data'

    @api.model
    def get_data(self):
        """One call returns everything the Command Center renders (DA01-DA15)."""
        env = self.env
        now = fields.Datetime.now()
        Asset, Alert, Vuln, Risk, Incident = (env['cg.asset'], env['cg.alert'], env['cg.vulnerability'],
                                              env['cg.risk'], env['cg.incident'])
        assets = Asset.search([])
        open_alerts = Alert.search([('state', 'in', OPEN_ALERT)])
        open_vulns = Vuln.search([('state', 'in', OPEN_VULN)])
        all_vulns = Vuln.search([('state', '!=', 'false_positive')])
        risks = Risk.search([])
        open_risks = risks.filtered(lambda r: r.state != 'closed')
        incidents = Incident.search([])
        open_incidents = incidents.filtered(lambda i: i.stage != 'closed')

        sev_open = Counter(open_alerts.mapped('severity'))
        agents = assets.filtered(lambda a: a.agent_status != 'none')
        connected = agents.filtered(lambda a: a.agent_status == 'active')
        offline = agents.filtered(lambda a: a.agent_status in ('disconnected', 'never_connected'))
        overdue_incidents = open_incidents.filtered('is_overdue')
        critical_vulns = open_vulns.filtered(lambda v: v.severity == 'critical')
        critical_risks = open_risks.filtered(lambda r: r.level == 'critical')

        kpis = {
            'assets': len(assets),
            'agents_connected': len(connected),
            'agents_disconnected': len(offline),
            'alerts_total': Alert.search_count([]),
            'alerts_24h': Alert.search_count([('timestamp', '>=', now - timedelta(hours=24))]),
            'alerts_open': len(open_alerts),
            'alerts_critical_open': sev_open.get('critical', 0),
            'vulns_open': len(open_vulns),
            'vulns_critical': len(critical_vulns),
            'risks_open': len(open_risks),
            'risks_critical': len(critical_risks),
            'incidents_open': len(open_incidents),
            'incidents_overdue': len(overdue_incidents),
        }

        # DA14: posture score = 100 minus capped penalties, so one area cannot hide the rest.
        factors = [
            ('Open critical alerts', min(22, sev_open.get('critical', 0) * 4), 22),
            ('Open high alerts', min(10, sev_open.get('high', 0) * 1.0), 10),
            ('Critical vulnerabilities', min(20, len(critical_vulns) * 4), 20),
            ('Critical risks', min(18, len(critical_risks) * 5), 18),
            ('Incidents past SLA', min(15, len(overdue_incidents) * 5), 15),
            ('Unmonitored endpoints', min(10, round(10 * len(offline) / len(agents)) if agents else 0), 10),
        ]
        score = int(max(5, round(100 - sum(penalty for _label, penalty, _cap in factors))))
        grade = ('Strong' if score >= 85 else 'Good' if score >= 70 else 'Fair' if score >= 55
                 else 'Weak' if score >= 40 else 'Critical')
        posture = {
            'score': score,
            'grade': grade,
            'factors': [{'label': label, 'penalty': round(penalty, 1), 'cap': cap,
                         'pct': round(100 * penalty / cap) if cap else 0} for label, penalty, cap in factors],
        }

        # Alert trend, last 14 days
        start = (now - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)
        buckets = {(start + timedelta(days=i)).date(): Counter() for i in range(14)}
        for alert in Alert.search([('timestamp', '>=', start)]):
            day = alert.timestamp.date()
            if day in buckets:
                buckets[day][alert.severity] += 1
        peak = max((sum(c.values()) for c in buckets.values()), default=0) or 1
        trend = [{
            'label': day.strftime('%d %b'), 'short': day.strftime('%d'),
            'critical': c['critical'], 'high': c['high'], 'medium': c['medium'], 'low': c['low'],
            'total': sum(c.values()), 'pct': round(100 * sum(c.values()) / peak),
        } for day, c in buckets.items()]

        # DA09: 5x5 matrix, rows = impact 5..1, columns = likelihood 1..5
        cells = Counter((int(r.impact), int(r.likelihood)) for r in open_risks)
        matrix = [[{'impact': impact, 'likelihood': likelihood, 'count': cells.get((impact, likelihood), 0),
                    'score': impact * likelihood} for likelihood in range(1, 6)] for impact in range(5, 0, -1)]

        category_counts = Counter(incidents.mapped('category'))
        stage_counts = Counter(incidents.mapped('stage'))
        top_assets = sorted(assets, key=lambda a: a.risk_score, reverse=True)[:6]

        fixed_vulns = all_vulns.filtered(lambda v: v.state in ('patched', 'accepted'))
        closed_risks = risks.filtered(lambda r: r.state in ('closed', 'monitoring'))
        total_work = len(all_vulns) + len(risks)
        remediation = {
            'vuln_total': len(all_vulns), 'vuln_fixed': len(fixed_vulns),
            'vuln_pct': round(100 * len(fixed_vulns) / len(all_vulns)) if all_vulns else 0,
            'risk_total': len(risks), 'risk_closed': len(closed_risks),
            'risk_pct': round(100 * len(closed_risks) / len(risks)) if risks else 0,
            'pct': round(100 * (len(fixed_vulns) + len(closed_risks)) / total_work) if total_work else 0,
        }

        week = Alert.search([('timestamp', '>=', now - timedelta(days=7))])
        attackers = Counter(ip for ip in week.mapped('src_ip') if ip).most_common(5)
        top_attack = attackers[0][1] if attackers else 1
        techniques = Counter()
        for alert in week:
            for technique in alert.mitre_technique_ids:
                techniques[(technique.id, technique.code, technique.name)] += 1
        top_tech = techniques.most_common(5)
        tech_peak = top_tech[0][1] if top_tech else 1

        wazuh = env['cg.wazuh.config'].search([], limit=1)
        return {
            'user': {'name': env.user.name, 'role': env.user.cg_role or 'User',
                     'is_manager': env.user.has_group('cyberguard_360.group_cg_manager')},
            'generated': fields.Datetime.to_string(now),
            'kpis': kpis,
            'posture': posture,
            'alert_severity': [{'key': s, 'count': sev_open.get(s, 0)} for s in ('critical', 'high', 'medium', 'low')],
            'trend': trend,
            'matrix': matrix,
            'risk_levels': [{'key': s, 'count': len(open_risks.filtered(lambda r, s=s: r.level == s))}
                            for s in ('critical', 'high', 'medium', 'low')],
            'incident_categories': [{'key': key, 'label': label, 'count': category_counts.get(key, 0)}
                                    for key, label in CATEGORIES if category_counts.get(key)],
            'incident_stages': [{'key': key, 'label': label, 'count': stage_counts.get(key, 0)}
                                for key, label in STAGES],
            'top_assets': [{
                'id': a.id, 'name': a.name, 'type': dict(a._fields['asset_type'].selection)[a.asset_type],
                'criticality': a.criticality, 'score': a.risk_score, 'band': a.risk_band,
                'alerts': a.open_alert_count, 'vulns': a.vulnerability_count, 'agent': a.agent_status,
            } for a in top_assets],
            'remediation': remediation,
            'top_attackers': [{'ip': ip, 'count': count, 'pct': round(100 * count / top_attack)}
                              for ip, count in attackers],
            'techniques': [{'id': tid, 'code': code, 'name': name, 'count': count,
                            'pct': round(100 * count / tech_peak)} for (tid, code, name), count in top_tech],
            'recent_alerts': [{
                'id': a.id, 'ref': a.reference, 'name': a.name, 'severity': a.severity,
                'asset': a.asset_id.name or a.agent_name or '-', 'src_ip': a.src_ip or '',
                'time': fields.Datetime.to_string(a.timestamp), 'state': a.state,
            } for a in Alert.search([], order='timestamp desc', limit=7)],
            'feed': [{
                'id': n.id, 'name': n.name, 'severity': n.severity, 'ntype': n.ntype,
                'time': fields.Datetime.to_string(n.create_date),
            } for n in env['cg.notification'].search([], limit=6)],
            'insights': self._insights(kpis, posture, open_alerts, open_vulns, overdue_incidents, offline,
                                       attackers, top_assets, trend),
            'wazuh': {
                'id': wazuh.id, 'state': wazuh.state or 'not_tested', 'mode': wazuh.mode or 'demo',
                'last_sync': fields.Datetime.to_string(wazuh.last_sync) if wazuh.last_sync else '',
            },
        }

    @api.model
    def _insights(self, kpis, posture, open_alerts, open_vulns, overdue, offline, attackers, top_assets, trend):
        """DA15: short, prioritised observations in plain language."""
        insights = []
        repeated = open_alerts.filtered('is_repeated')
        if attackers and attackers[0][1] >= 8:
            ip, count = attackers[0]
            insights.append({
                'tone': 'critical', 'title': 'Persistent attacker',
                'text': '%s generated %d alerts this week. Blocking it would remove the largest single source of noise.' % (ip, count),
                'target': 'alerts_ip', 'value': ip})
        exposed = open_vulns.filtered(lambda v: v.priority == 'p1')
        if exposed:
            worst = exposed[0]
            insights.append({
                'tone': 'critical', 'title': 'Patch first',
                'text': '%s (CVSS %.1f) on %s has the highest priority score: severe, on an important asset%s.' % (
                    worst.cve_id or worst.name, worst.cvss_score, ', '.join(worst.asset_ids[:2].mapped('name')) or 'unassigned assets',
                    ', and internet-facing' if any(worst.asset_ids.mapped('internet_facing')) else ''),
                'target': 'vulns_p1'})
        if overdue:
            insights.append({
                'tone': 'high', 'title': 'Response SLA breached',
                'text': '%d incident(s) passed their response deadline. Oldest: %s.' % (
                    len(overdue), overdue.sorted('detected_date')[0].reference),
                'target': 'incidents_overdue'})
        if offline:
            insights.append({
                'tone': 'high', 'title': 'Blind spots',
                'text': '%s %s not reporting to Wazuh, so attacks on %s would go unseen.' % (
                    ', '.join(offline[:3].mapped('name')), 'is' if len(offline) == 1 else 'are',
                    'it' if len(offline) == 1 else 'them'),
                'target': 'agents_offline'})
        if repeated:
            rule, count = Counter(repeated.mapped('name')).most_common(1)[0]
            insights.append({
                'tone': 'medium', 'title': 'Recurring pattern',
                'text': '"%s" keeps firing (%d open alerts). Recurrence suggests an automated attack or a misconfiguration.' % (rule, count),
                'target': 'alerts_repeated'})
        if len(trend) >= 8:
            recent, before = sum(d['total'] for d in trend[-7:]), sum(d['total'] for d in trend[:7])
            if before and abs(recent - before) / before >= 0.25:
                change = round(100 * (recent - before) / before)
                insights.append({
                    'tone': 'medium' if change > 0 else 'ok', 'title': 'Alert volume %s' % ('rising' if change > 0 else 'falling'),
                    'text': 'Alerts are %s %d%% week over week (%d vs %d).' % ('up' if change > 0 else 'down', abs(change), recent, before),
                    'target': 'alerts_open'})
        if top_assets and top_assets[0].risk_score >= 60:
            asset = top_assets[0]
            insights.append({
                'tone': 'medium', 'title': 'Most exposed asset',
                'text': '%s scores %d/100 with %d open alert(s) and %d open vulnerabilit%s.' % (
                    asset.name, asset.risk_score, asset.open_alert_count, asset.vulnerability_count,
                    'y' if asset.vulnerability_count == 1 else 'ies'),
                'target': 'asset', 'value': asset.id})
        if not insights:
            insights.append({'tone': 'ok', 'title': 'All clear',
                             'text': 'No urgent findings. Posture score is %d/100.' % posture['score'], 'target': ''})
        return insights[:5]

    @api.model
    def generate_management_report(self):
        """DA16: an executive summary saved as an analysis and returned as a PDF action."""
        payload = self.env['cg.ai.analysis'].run_console(mode='executive', hours=24 * 7)
        analysis = self.env['cg.ai.analysis'].browse(payload['id'])
        analysis.name = 'Management security report - %s' % fields.Date.context_today(self).strftime('%d %b %Y')
        self.env['cg.activity.log'].log('Management report generated', 'admin', analysis)
        return self.env.ref('cyberguard_360.action_report_analysis').report_action(analysis)

    @api.model
    def sync_now(self):
        config = self.env['cg.wazuh.config'].search([], limit=1)
        if not config:
            return {'ok': False, 'message': 'No Wazuh connection is configured.'}
        config.action_sync_agents()
        config.action_sync_alerts()
        return {'ok': config.state == 'connected', 'message': config.last_message or ''}
