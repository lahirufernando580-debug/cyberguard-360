from datetime import timedelta

from markupsafe import Markup, escape

from odoo import api, fields, models
from odoo.exceptions import UserError

from .common import SEVERITY, notify_action, system_write

STAGES = [
    ('new', 'New'),
    ('triage', 'Triage'),
    ('investigating', 'Investigating'),
    ('contained', 'Contained'),
    ('eradicated', 'Eradicated'),
    ('closed', 'Closed'),
]
STAGE_ORDER = [key for key, _label in STAGES]
SLA_HOURS = {'critical': 4, 'high': 8, 'medium': 24, 'low': 72}
CATEGORIES = [
    ('phishing', 'Phishing'),
    ('malware', 'Malware'),
    ('ransomware', 'Ransomware'),
    ('brute_force', 'Brute Force'),
    ('web_attack', 'Web Attack'),
    ('unauthorized_access', 'Unauthorised Access'),
    ('data_breach', 'Data Breach'),
    ('dos', 'Denial of Service'),
    ('insider', 'Insider Threat'),
    ('other', 'Other'),
]


class CgIncident(models.Model):
    _name = 'cg.incident'
    _description = 'Security Incident'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'severity_rank desc, detected_date desc, id desc'

    name = fields.Char(string='Incident', required=True, tracking=True)
    reference = fields.Char(readonly=True, copy=False, default='New')
    category = fields.Selection(CATEGORIES, required=True, default='other', tracking=True)
    severity = fields.Selection(SEVERITY, required=True, default='medium', tracking=True)
    severity_rank = fields.Integer(compute='_compute_severity_rank', store=True)
    stage = fields.Selection(STAGES, default='new', required=True, index=True, tracking=True,
                             group_expand='_group_expand_stage')
    reporter_id = fields.Many2one('res.users', string='Reported By', default=lambda self: self.env.user)
    analyst_id = fields.Many2one('res.users', string='Analyst', tracking=True)
    description = fields.Text()
    asset_ids = fields.Many2many('cg.asset', 'cg_incident_asset_rel', 'incident_id', 'asset_id',
                                 string='Affected Assets')
    alert_ids = fields.One2many('cg.alert', 'incident_id', string='Linked Alerts')
    alert_count = fields.Integer(compute='_compute_alert_count')
    note_ids = fields.One2many('cg.incident.note', 'incident_id', string='Investigation Notes')
    evidence_ids = fields.Many2many('ir.attachment', 'cg_incident_attachment_rel', 'incident_id',
                                    'attachment_id', string='Evidence')
    response_action_ids = fields.One2many('cg.response.action', 'incident_id', string='Response Actions')
    analysis_ids = fields.One2many('cg.ai.analysis', 'incident_id', string='AI Analyses')

    detected_date = fields.Datetime(string='Detected', default=fields.Datetime.now, required=True)
    contained_date = fields.Datetime(string='Contained', readonly=True)
    closed_date = fields.Datetime(string='Closed', readonly=True)
    sla_deadline = fields.Datetime(string='Response Due', compute='_compute_sla', store=True)
    is_overdue = fields.Boolean(compute='_compute_is_overdue')
    hours_open = fields.Float(compute='_compute_is_overdue')
    escalated = fields.Boolean(readonly=True, tracking=True)
    escalation_level = fields.Integer(readonly=True)
    escalated_to = fields.Many2one('res.users', readonly=True)

    ai_summary = fields.Text(string='AI Summary', readonly=True)
    recommended_actions = fields.Text(string='Recommended Response', readonly=True)
    root_cause = fields.Text()
    resolution = fields.Text()
    lessons_learned = fields.Text()
    timeline_html = fields.Html(compute='_compute_timeline_html', sanitize=False)

    @api.model
    def _group_expand_stage(self, stages, domain):
        return STAGE_ORDER

    @api.depends('severity')
    def _compute_severity_rank(self):
        rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        for incident in self:
            incident.severity_rank = rank.get(incident.severity, 0)

    def _compute_alert_count(self):
        for incident in self:
            incident.alert_count = len(incident.sudo().alert_ids)

    @api.depends('detected_date', 'severity')
    def _compute_sla(self):
        for incident in self:
            incident.sla_deadline = (incident.detected_date or fields.Datetime.now()) + timedelta(
                hours=SLA_HOURS.get(incident.severity, 24))

    @api.depends('sla_deadline', 'stage', 'contained_date')
    def _compute_is_overdue(self):
        now = fields.Datetime.now()
        for incident in self:
            end = incident.closed_date or now
            incident.hours_open = (end - incident.detected_date).total_seconds() / 3600 if incident.detected_date else 0
            incident.is_overdue = bool(
                incident.stage in ('new', 'triage', 'investigating')
                and incident.sla_deadline and incident.sla_deadline < now)

    @api.depends('alert_ids', 'note_ids', 'detected_date', 'contained_date', 'closed_date')
    def _compute_timeline_html(self):
        """IM10: one chronological view of alerts, notes and milestones."""
        for incident in self:
            items = []
            # sudo: reporters may see the timeline of their incident without alert access
            for alert in incident.sudo().alert_ids:
                items.append((alert.timestamp, 'alert', '%s  %s%s' % (
                    alert.reference, alert.name, ' from %s' % alert.src_ip if alert.src_ip else '')))
            for note in incident.sudo().note_ids:
                items.append((note.date, note.note_type, '%s: %s' % (note.author_id.name or 'System', note.content or '')))
            if incident.detected_date:
                items.append((incident.detected_date, 'milestone', 'Incident detected'))
            if incident.contained_date:
                items.append((incident.contained_date, 'milestone', 'Incident contained'))
            if incident.closed_date:
                items.append((incident.closed_date, 'milestone', 'Incident closed'))
            rows = Markup()
            for date, kind, text in sorted((i for i in items if i[0]), key=lambda i: i[0]):
                rows += Markup(
                    '<div class="cg_tl_item cg_tl_%s"><span class="cg_tl_dot"></span>'
                    '<span class="cg_tl_time">%s</span><span class="cg_tl_text">%s</span>'
                    '<span class="cg_tl_kind">%s</span></div>') % (
                    escape(kind), escape(fields.Datetime.to_string(date)), escape(text),
                    escape(kind.replace('_', ' ').title()))
            incident.timeline_html = (Markup('<div class="cg_timeline">%s</div>') % rows) if rows else False

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('reference', 'New') == 'New':
                vals['reference'] = self.env['ir.sequence'].next_by_code('cg.incident') or 'New'
        incidents = super().create(vals_list)
        if not self.env.context.get('cg_demo'):
            for incident in incidents:
                recipients = incident.analyst_id
                self.env['cg.notification'].notify(
                    'New incident %s: %s' % (incident.reference, incident.name),
                    '%s severity %s incident. Response due %s.' % (
                        incident.severity.title(), dict(CATEGORIES)[incident.category].lower(),
                        fields.Datetime.to_string(incident.sla_deadline)),
                    ntype='incident', severity=incident.severity, record=incident, users=recipients,
                    group_xmlid=None if recipients else 'cyberguard_360.group_cg_analyst')
                self.env['cg.activity.log'].log('Incident created', 'incident', incident)
        return incidents

    def write(self, vals):
        if 'stage' in vals:
            now = fields.Datetime.now()
            if vals['stage'] == 'contained':
                vals.setdefault('contained_date', now)
            if vals['stage'] == 'closed':
                vals.setdefault('closed_date', now)
            labels = dict(STAGES)
            for incident in self.filtered(lambda i: i.stage != vals['stage']):
                incident._add_note('Stage changed: %s to %s' % (labels[incident.stage], labels[vals['stage']]), 'system')
        return super().write(vals)

    def _add_note(self, content, note_type='note'):
        return self.env['cg.incident.note'].sudo().create([{
            'incident_id': incident.id, 'content': content, 'note_type': note_type,
            'author_id': self.env.uid,
        } for incident in self])

    def action_open(self):
        self.ensure_one()
        return {'type': 'ir.actions.act_window', 'res_model': 'cg.incident', 'res_id': self.id, 'view_mode': 'form'}

    # ------------------------------------------------------------------ workflow
    def action_next_stage(self):
        for incident in self:
            index = STAGE_ORDER.index(incident.stage)
            if STAGE_ORDER[index + 1:index + 2] == ['closed']:
                incident.action_close()
            elif index < len(STAGE_ORDER) - 1:
                incident.stage = STAGE_ORDER[index + 1]
                if not incident.analyst_id:
                    incident.analyst_id = self.env.uid

    def action_assign_to_me(self):
        self.write({'analyst_id': self.env.uid})

    def action_escalate(self):
        """IM13"""
        managers = self.env.ref('cyberguard_360.group_cg_manager').sudo().user_ids
        for incident in self:
            level = incident.escalation_level + 1
            target = managers[:1]
            incident.write({'escalated': True, 'escalation_level': level, 'escalated_to': target.id})
            incident._add_note('Escalated to level %d%s' % (level, ' (%s)' % target.name if target else ''), 'system')
            self.env['cg.notification'].notify(
                'Incident escalated: %s' % incident.reference,
                '%s (%s) was escalated to level %d.' % (incident.name, incident.severity, level),
                ntype='escalation', severity='critical' if incident.severity == 'critical' else 'high',
                record=incident, group_xmlid='cyberguard_360.group_cg_manager')
            self.env['cg.activity.log'].log('Incident escalated', 'incident', incident)

    def action_close(self):
        """IM15"""
        for incident in self:
            if not incident.resolution:
                raise UserError("Document the resolution before closing incident %s." % incident.reference)
            incident.stage = 'closed'
            incident.alert_ids.filtered(lambda a: a.state not in ('false_positive',)).write({'state': 'resolved'})
            self.env['cg.activity.log'].log('Incident closed', 'incident', incident)

    def action_reopen(self):
        self.write({'stage': 'investigating', 'closed_date': False})

    def action_ai_analysis(self):
        """IM11/IM12"""
        self.ensure_one()
        alerts = self.alert_ids
        if not alerts and self.asset_ids:
            alerts = self.env['cg.alert'].search([
                ('asset_id', 'in', self.asset_ids.ids),
                ('timestamp', '>=', self.detected_date - timedelta(hours=24)),
                ('timestamp', '<=', self.detected_date + timedelta(hours=24))], limit=150)
        if not alerts:
            raise UserError("Link alerts or affected assets to this incident so the AI has evidence to analyse.")
        analysis = self.env['cg.ai.analysis'].create_from_alerts(
            alerts, 'incident', title='Incident analysis: %s' % self.reference, incident=self)
        self.write({
            'ai_summary': analysis.executive_summary,
            'recommended_actions': '\n'.join(filter(None, [analysis.investigation_steps, analysis.remediation])),
        })
        self._add_note('AI analysis %s generated (confidence %d%%).' % (analysis.reference, analysis.confidence), 'system')
        return analysis.action_open()

    @system_write
    def action_recommend_response(self):
        """IM12/NR11: propose concrete response actions. Nothing runs without approval."""
        self.ensure_one()
        action_model = self.env['cg.response.action']
        existing = set(self.response_action_ids.mapped(lambda a: (a.action_type, a.target)))
        proposals = []
        for ip in {a.src_ip for a in self.alert_ids if a.src_ip}:
            proposals.append(('block_ip', ip, False, 'Source of %d alert(s) in this incident.' % len(
                self.alert_ids.filtered(lambda a, ip=ip: a.src_ip == ip))))
        if self.category in ('malware', 'ransomware', 'data_breach') or self.severity == 'critical':
            for asset in self.asset_ids:
                proposals.append(('isolate_host', asset.name, asset.id, 'Contain the affected host while it is investigated.'))
        if self.category in ('brute_force', 'unauthorized_access', 'phishing'):
            for user in {a.dst_user for a in self.alert_ids if a.dst_user}:
                proposals.append(('disable_account', user, False, 'Account targeted or used during the incident.'))
        created = action_model
        for action_type, target, asset_id, reason in proposals:
            if (action_type, target) in existing:
                continue
            created |= action_model.create({
                'name': '%s: %s' % (dict(action_model._fields['action_type'].selection)[action_type], target),
                'action_type': action_type, 'target': target, 'asset_id': asset_id,
                'incident_id': self.id, 'reason': reason,
            })
        if not created:
            return notify_action('No new recommendations', 'Every applicable response action is already listed.', 'info')
        self._add_note('%d response action(s) recommended, awaiting approval.' % len(created), 'system')
        return notify_action('Response recommended', '%d action(s) added and awaiting approval.' % len(created))

    @api.model
    def cron_escalate_overdue(self):
        """NR07"""
        overdue = self.search([
            ('stage', 'in', ('new', 'triage', 'investigating')),
            ('sla_deadline', '<', fields.Datetime.now()), ('escalated', '=', False)])
        overdue.action_escalate()
        if overdue:
            self.env['cg.automation.rule'].sudo().run_trigger('incident_overdue', overdue)

    def action_print(self):
        return self.env.ref('cyberguard_360.action_report_incident').report_action(self)


class CgIncidentNote(models.Model):
    _name = 'cg.incident.note'
    _description = 'Incident Investigation Note'
    _order = 'date desc, id desc'

    incident_id = fields.Many2one('cg.incident', required=True, ondelete='cascade', index=True)
    date = fields.Datetime(default=fields.Datetime.now, required=True)
    author_id = fields.Many2one('res.users', string='Author', default=lambda self: self.env.user)
    note_type = fields.Selection([
        ('note', 'Note'),
        ('finding', 'Finding'),
        ('action', 'Action Taken'),
        ('evidence', 'Evidence'),
        ('system', 'System'),
    ], string='Type', default='note', required=True)
    content = fields.Text(required=True)
