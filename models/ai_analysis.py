from datetime import timedelta

from markupsafe import Markup, escape

from odoo import api, fields, models
from odoo.exceptions import UserError

from .common import SEVERITY, system_write

ANALYSIS_TYPES = [
    ('log_analysis', 'Log Analysis'),
    ('alert_explanation', 'Alert Explanation'),
    ('incident', 'Incident Analysis'),
    ('risk', 'Risk Analysis'),
    ('threat', 'Threat Investigation'),
    ('daily_summary', 'Daily Summary'),
    ('executive', 'Executive Summary'),
    ('comparison', 'Period Comparison'),
]


def _lines(items):
    return '\n'.join(str(item) for item in items or [])


class CgAiAnalysis(models.Model):
    _name = 'cg.ai.analysis'
    _description = 'AI Security Analysis'
    _inherit = ['cg.system.record', 'mail.thread']
    _order = 'create_date desc, id desc'
    # The AI report is a record of what the engine produced; analysts review it (state) but do not rewrite it.
    _cg_locked_fields = (
        'name', 'analysis_type', 'period_start', 'period_end', 'alert_ids', 'asset_ids', 'technique_ids',
        'executive_summary', 'detected_activity', 'affected_assets', 'source_ips', 'destination_ips',
        'attack_technique', 'severity', 'confidence', 'business_impact', 'investigation_steps',
        'remediation', 'event_references', 'confirmed_facts', 'hypotheses', 'timeline_data')

    name = fields.Char(string='Title', required=True)
    reference = fields.Char(readonly=True, copy=False, default='New')
    analysis_type = fields.Selection(ANALYSIS_TYPES, string='Type', required=True, default='log_analysis')
    user_id = fields.Many2one('res.users', string='Requested By', default=lambda self: self.env.user, readonly=True)
    engine = fields.Selection([('builtin', 'CyberGuard Engine'), ('claude', 'Claude')], readonly=True,
                              default='builtin')
    engine_note = fields.Char(readonly=True)
    state = fields.Selection([
        ('draft', 'AI Draft'),
        ('reviewed', 'Analyst Reviewed'),
        ('approved', 'Approved'),
    ], default='draft', required=True, tracking=True,
        help="AI output is a draft until a human analyst reviews it.")
    period_start = fields.Datetime()
    period_end = fields.Datetime()
    event_count = fields.Integer(string='Events Analysed', readonly=True)

    alert_ids = fields.Many2many('cg.alert', 'cg_analysis_alert_rel', 'analysis_id', 'alert_id', string='Events')
    asset_ids = fields.Many2many('cg.asset', 'cg_analysis_asset_rel', 'analysis_id', 'asset_id',
                                 string='Affected Assets')
    technique_ids = fields.Many2many('cg.mitre.technique', 'cg_analysis_mitre_rel', 'analysis_id',
                                     'technique_id', string='ATT&CK Techniques')
    incident_id = fields.Many2one('cg.incident', ondelete='set null')
    risk_id = fields.Many2one('cg.risk', ondelete='set null')

    # The ten sections of the structured report
    executive_summary = fields.Text()
    detected_activity = fields.Text(string='Detected Security Activity')
    affected_assets = fields.Text(string='Affected Endpoints / Servers')
    source_ips = fields.Char(string='Source IPs')
    destination_ips = fields.Char(string='Destination IPs')
    attack_technique = fields.Text(string='Potential Attack Technique')
    severity = fields.Selection(SEVERITY, default='low')
    confidence = fields.Integer(help="How well the evidence supports the analysis, 0-100.")
    business_impact = fields.Text(string='Potential Business Impact')
    investigation_steps = fields.Text(string='Recommended Investigation Steps')
    remediation = fields.Text(string='Recommended Remediation')
    event_references = fields.Text(string='Supporting Event References')
    # Confirmed vs. inferred
    confirmed_facts = fields.Text(string='Confirmed Events')
    hypotheses = fields.Text(string='AI Hypotheses')
    timeline_data = fields.Json(string='Timeline Data')
    timeline_html = fields.Html(compute='_compute_timeline_html', sanitize=False)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('reference', 'New') == 'New':
                vals['reference'] = self.env['ir.sequence'].next_by_code('cg.ai.analysis') or 'New'
        return super().create(vals_list)

    @api.depends('timeline_data')
    def _compute_timeline_html(self):
        for analysis in self:
            rows = Markup()
            for item in analysis.timeline_data or []:
                kind = 'hypothesis' if item.get('kind') == 'hypothesis' else 'confirmed'
                rows += Markup(
                    '<div class="cg_tl_item cg_tl_%s"><span class="cg_tl_dot"></span>'
                    '<span class="cg_tl_time">%s</span><span class="cg_tl_text">%s</span>'
                    '<span class="cg_tl_kind">%s</span></div>') % (
                    kind, escape(item.get('time', '')), escape(item.get('event', '')),
                    'AI hypothesis' if kind == 'hypothesis' else 'Confirmed')
            analysis.timeline_html = (Markup('<div class="cg_timeline">%s</div>') % rows) if rows else False

    # ------------------------------------------------------------------ creation
    @api.model
    @system_write
    def create_from_alerts(self, alerts, analysis_type='log_analysis', title=None, focus_alert=None,
                           extra=None, incident=None, risk=None, period=None):
        """AI05/AI06/AI14: run the engine on a set of alerts and store the result."""
        engine = self.env['cg.ai.engine']
        context = engine.build_context(alerts, focus_alert=focus_alert, extra=extra)
        report, engine_name, note = engine.analyse(context, analysis_type)
        codes = [t.get('id') for t in report.get('attack_techniques', []) if t.get('id')]
        techniques = self.env['cg.mitre.technique'].search([('code', 'in', codes)])
        dates = alerts.mapped('timestamp')
        label = dict(ANALYSIS_TYPES)[analysis_type]
        analysis = self.create({
            'name': title or '%s - %s' % (label, fields.Datetime.now().strftime('%d %b %Y %H:%M')),
            'analysis_type': analysis_type,
            'engine': engine_name,
            'engine_note': note,
            'period_start': (period or {}).get('start') or (min(dates) if dates else False),
            'period_end': (period or {}).get('end') or (max(dates) if dates else False),
            'event_count': len(alerts),
            'alert_ids': [(6, 0, alerts.ids)],
            'asset_ids': [(6, 0, alerts.asset_id.ids)],
            'technique_ids': [(6, 0, techniques.ids)],
            'incident_id': incident.id if incident else False,
            'risk_id': risk.id if risk else False,
            'executive_summary': report.get('executive_summary'),
            'detected_activity': _lines(report.get('detected_activity')),
            'affected_assets': _lines(report.get('affected_assets')),
            'source_ips': ', '.join(report.get('source_ips') or []),
            'destination_ips': ', '.join(report.get('destination_ips') or []),
            'attack_technique': _lines('%s %s: %s' % (t.get('id'), t.get('name'), t.get('rationale'))
                                       for t in report.get('attack_techniques', [])),
            'severity': report.get('severity') or 'low',
            'confidence': report.get('confidence') or 0,
            'business_impact': report.get('business_impact'),
            'investigation_steps': _lines(report.get('investigation_steps')),
            'remediation': _lines(report.get('remediation')),
            'event_references': ', '.join(report.get('event_references') or []),
            'confirmed_facts': _lines(report.get('confirmed_facts')),
            'hypotheses': _lines(report.get('hypotheses')),
            'timeline_data': report.get('timeline') or [],
        })
        self.env['cg.activity.log'].log('AI analysis generated', 'ai', analysis, label)
        return analysis

    # ------------------------------------------------------------------ console RPC
    @api.model
    def run_console(self, mode='log_analysis', hours=24, severity=None, asset_id=None):
        """Entry point for the AI Analyst console (AI03, AI13, AI15, AI17)."""
        hours = max(1, int(hours or 24))
        now = fields.Datetime.now()
        start = now - timedelta(hours=hours)
        domain = [('timestamp', '>=', start), ('timestamp', '<=', now)]
        if severity:
            ranks = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            domain.append(('severity_rank', '>=', ranks.get(severity, 1)))
        if asset_id:
            domain.append(('asset_id', '=', int(asset_id)))
        alert_model = self.env['cg.alert']
        alerts = alert_model.search(domain)
        extra = {}
        if mode in ('executive', 'daily_summary'):
            data = self.env['cg.dashboard'].get_data()
            extra['posture'] = dict(data['kpis'], score=data['posture']['score'], grade=data['posture']['grade'])
        if mode == 'comparison':
            previous_domain = [('timestamp', '>=', start - timedelta(hours=hours)), ('timestamp', '<', start)] + domain[2:]
            previous = alert_model.search(previous_domain)
            counts = {}
            for alert in previous:
                counts[alert.severity] = counts.get(alert.severity, 0) + 1
            extra['previous_period'] = {
                'total_events': len(previous),
                'severity_counts': counts,
                'source_ips': list({ip for ip in previous.mapped('src_ip') if ip}),
            }
        analysis = self.create_from_alerts(alerts, mode, extra=extra, period={'start': start, 'end': now})
        return analysis.console_payload()

    def console_payload(self):
        self.ensure_one()

        def split(text):
            return [line for line in (text or '').split('\n') if line.strip()]

        return {
            'id': self.id,
            'reference': self.reference,
            'name': self.name,
            'type': dict(ANALYSIS_TYPES)[self.analysis_type],
            'engine': dict(self._fields['engine'].selection)[self.engine],
            'engine_note': self.engine_note or '',
            'event_count': self.event_count,
            'severity': self.severity,
            'confidence': self.confidence,
            'executive_summary': self.executive_summary or '',
            'detected_activity': split(self.detected_activity),
            'affected_assets': split(self.affected_assets),
            'source_ips': self.source_ips or '',
            'destination_ips': self.destination_ips or '',
            'attack_technique': split(self.attack_technique),
            'business_impact': self.business_impact or '',
            'confirmed_facts': split(self.confirmed_facts),
            'hypotheses': split(self.hypotheses),
            'investigation_steps': split(self.investigation_steps),
            'remediation': split(self.remediation),
            'event_references': self.event_references or '',
            'timeline': self.timeline_data or [],
        }

    @api.model
    def cron_daily_summary(self):
        """AI15 / NR08: a daily briefing delivered to analysts and managers."""
        payload = self.run_console(mode='daily_summary', hours=24)
        analysis = self.browse(payload['id'])
        self.env['cg.notification'].notify(
            'Daily AI security summary', analysis.executive_summary, ntype='daily_summary',
            severity=analysis.severity, record=analysis, group_xmlid='cyberguard_360.group_cg_analyst')
        return True

    # ------------------------------------------------------------------ workflow
    def action_open(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'cg.ai.analysis',
            'res_id': self.id,
            'view_mode': 'form',
        }

    def action_mark_reviewed(self):
        self.write({'state': 'reviewed'})

    def action_approve(self):
        self.write({'state': 'approved'})

    def action_reset(self):
        self.write({'state': 'draft'})

    def action_create_incident(self):
        self.ensure_one()
        if not self.alert_ids:
            raise UserError("This analysis has no events to convert into an incident.")
        action = self.alert_ids.action_create_incident()
        incident = self.env['cg.incident'].browse(action['res_id'])
        incident.write({'name': self.name, 'severity': self.severity,
                        'description': self.executive_summary})
        self.incident_id = incident
        return action

    def action_view_events(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Events analysed',
            'res_model': 'cg.alert',
            'view_mode': 'list,form',
            'domain': [('id', 'in', self.alert_ids.ids)],
        }

    def action_print(self):
        return self.env.ref('cyberguard_360.action_report_analysis').report_action(self)
