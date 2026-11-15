import json
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError

from .common import SEVERITY, SEV_RANK, notify_action, system_write, wazuh_level_to_severity

# Keyword -> incident category, used when an alert is promoted to an incident.
CATEGORY_HINTS = [
    ('ransom', 'ransomware'),
    ('phish', 'phishing'),
    ('malware', 'malware'), ('virus', 'malware'), ('trojan', 'malware'), ('rootkit', 'malware'),
    ('brute', 'brute_force'), ('authentication_fail', 'brute_force'), ('failed password', 'brute_force'),
    ('sql', 'web_attack'), ('xss', 'web_attack'), ('web', 'web_attack'),
    ('exfil', 'data_breach'), ('dlp', 'data_breach'),
    ('dos', 'dos'), ('flood', 'dos'),
    ('privilege', 'unauthorized_access'), ('sudo', 'unauthorized_access'),
]


class CgAlert(models.Model):
    _name = 'cg.alert'
    _description = 'Security Alert'
    _inherit = ['cg.system.record', 'mail.thread']
    _order = 'timestamp desc, id desc'
    # Imported from Wazuh: only the handling fields (state, assignee, incident, risk) can change.
    _cg_locked_fields = (
        'name', 'wazuh_id', 'timestamp', 'rule_id', 'rule_level', 'rule_groups', 'severity',
        'agent_id', 'agent_name', 'src_ip', 'dst_ip', 'src_user', 'dst_user', 'location',
        'decoder', 'full_log', 'raw_json', 'mitre_technique_ids', 'group_key', 'repeat_count')

    name = fields.Char(string='Description', required=True, index=True)
    reference = fields.Char(compute='_compute_reference')
    wazuh_id = fields.Char(string='Wazuh Alert ID', index=True, copy=False, readonly=True)
    timestamp = fields.Datetime(required=True, default=fields.Datetime.now, index=True)
    rule_id = fields.Char(string='Rule ID', index=True)
    rule_level = fields.Integer(string='Rule Level', help="Wazuh rule level 0-16.")
    rule_groups = fields.Char(string='Rule Groups')
    severity = fields.Selection(SEVERITY, compute='_compute_severity', store=True, readonly=False,
                                index=True, tracking=True)
    severity_rank = fields.Integer(compute='_compute_severity_rank', store=True)
    agent_id = fields.Char(string='Agent ID', index=True)
    agent_name = fields.Char(string='Agent')
    asset_id = fields.Many2one('cg.asset', string='Asset', index=True, ondelete='set null', tracking=True)
    asset_criticality = fields.Selection(related='asset_id.criticality', string='Asset Criticality')
    src_ip = fields.Char(string='Source IP', index=True)
    dst_ip = fields.Char(string='Destination IP')
    src_user = fields.Char(string='Source User')
    dst_user = fields.Char(string='Target User')
    location = fields.Char(string='Log Source')
    decoder = fields.Char()
    full_log = fields.Text(string='Full Log')
    raw_json = fields.Text(string='Raw Event')
    mitre_technique_ids = fields.Many2many('cg.mitre.technique', 'cg_alert_mitre_rel', 'alert_id',
                                           'technique_id', string='ATT&CK Techniques')
    state = fields.Selection([
        ('new', 'New'),
        ('acknowledged', 'Acknowledged'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ], default='new', required=True, index=True, tracking=True)
    assigned_to = fields.Many2one('res.users', string='Assigned To', tracking=True)
    incident_id = fields.Many2one('cg.incident', string='Incident', ondelete='set null', index=True)
    risk_id = fields.Many2one('cg.risk', string='Risk', ondelete='set null')
    group_key = fields.Char(index=True, readonly=True,
                            help="Alerts sharing rule, agent and source are grouped together.")
    repeat_count = fields.Integer(string='Occurrences (24h)', default=1, readonly=True)
    is_repeated = fields.Boolean(string='Recurring', compute='_compute_is_repeated', store=True)
    analysis_ids = fields.Many2many('cg.ai.analysis', 'cg_analysis_alert_rel', 'alert_id', 'analysis_id',
                                    string='AI Analyses')
    analysis_count = fields.Integer(compute='_compute_analysis_count')

    _wazuh_id_unique = models.Constraint('UNIQUE(wazuh_id)', "This Wazuh alert was already imported.")

    def _compute_reference(self):
        for alert in self:
            alert.reference = 'ALR-%05d' % alert.id if alert.id else 'ALR-NEW'

    @api.depends('rule_level')
    def _compute_severity(self):
        for alert in self:
            alert.severity = wazuh_level_to_severity(alert.rule_level)

    @api.depends('severity')
    def _compute_severity_rank(self):
        for alert in self:
            alert.severity_rank = SEV_RANK.get(alert.severity, 0)

    @api.depends('repeat_count')
    def _compute_is_repeated(self):
        for alert in self:
            alert.is_repeated = alert.repeat_count >= 5

    def _compute_analysis_count(self):
        for alert in self:
            alert.analysis_count = len(alert.analysis_ids)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get('group_key'):
                vals['group_key'] = '%s:%s:%s' % (vals.get('rule_id') or '-', vals.get('agent_id') or '-',
                                                  vals.get('src_ip') or '-')
            if vals.get('agent_id') and not vals.get('asset_id'):
                asset = self.env['cg.asset'].search([('wazuh_agent_id', '=', vals['agent_id'])], limit=1)
                vals['asset_id'] = asset.id
        return super().create(vals_list)

    # ------------------------------------------------------------------ import
    @api.model
    @system_write
    def import_wazuh_hits(self, hits):
        """SOC05: turn Wazuh indexer hits into alerts, skipping ones already imported."""
        ids = [hit.get('_id') for hit in hits if hit.get('_id')]
        known = set(self.search([('wazuh_id', 'in', ids)]).mapped('wazuh_id'))
        technique_model = self.env['cg.mitre.technique']
        vals_list = []
        for hit in hits:
            if hit.get('_id') in known:
                continue
            src = hit.get('_source', {})
            rule, agent, data = src.get('rule', {}), src.get('agent', {}), src.get('data', {}) or {}
            mitre = rule.get('mitre', {}) or {}
            techniques = technique_model
            for index, code in enumerate(mitre.get('id', []) or []):
                technique = technique_model.search([('code', '=', code)], limit=1)
                if not technique:
                    names = mitre.get('technique', []) or []
                    tactics = mitre.get('tactic', []) or []
                    technique = technique_model.create({
                        'code': code,
                        'name': names[index] if index < len(names) else code,
                        'tactic': tactics[0] if tactics else False,
                    })
                techniques |= technique
            timestamp = (src.get('timestamp') or src.get('@timestamp') or '')[:19].replace('T', ' ')
            vals_list.append({
                'name': rule.get('description') or 'Wazuh alert',
                'wazuh_id': hit.get('_id'),
                'timestamp': timestamp or fields.Datetime.now(),
                'rule_id': str(rule.get('id') or ''),
                'rule_level': int(rule.get('level') or 0),
                'rule_groups': ', '.join(rule.get('groups', []) or []),
                'agent_id': agent.get('id'),
                'agent_name': agent.get('name'),
                'src_ip': data.get('srcip') or data.get('src_ip'),
                'dst_ip': data.get('dstip') or data.get('dst_ip') or agent.get('ip'),
                'src_user': data.get('srcuser'),
                'dst_user': data.get('dstuser'),
                'location': src.get('location'),
                'decoder': (src.get('decoder') or {}).get('name'),
                'full_log': src.get('full_log'),
                'raw_json': json.dumps(src, indent=2, default=str)[:20000],
                'mitre_technique_ids': [(6, 0, techniques.ids)],
            })
        alerts = self.create(vals_list)
        alerts._post_process()
        return alerts

    def _post_process(self):
        """Repeat detection (SOC14), IoC extraction and automation for freshly imported alerts."""
        if not self:
            return
        since = fields.Datetime.now() - timedelta(hours=24)
        for key in set(self.mapped('group_key')):
            count = self.search_count([('group_key', '=', key), ('timestamp', '>=', since)])
            self.filtered(lambda a, key=key: a.group_key == key).write({'repeat_count': max(count, 1)})
        self.env['cg.ioc'].sudo().extract_from_alerts(self)
        critical = self.filtered(lambda a: a.severity == 'critical')
        if critical:
            self.env['cg.notification'].notify(
                '%d critical alert(s) detected' % len(critical),
                '\n'.join('%s on %s' % (a.name, a.asset_id.name or a.agent_name or 'unknown host')
                          for a in critical[:5]),
                ntype='critical_alert', severity='critical', record=critical[:1],
                group_xmlid='cyberguard_360.group_cg_analyst')
        self.env['cg.automation.rule'].sudo().run_trigger('alert', self)

    # ------------------------------------------------------------------ workflow
    def action_acknowledge(self):
        self.filtered(lambda a: a.state == 'new').write({'state': 'acknowledged', 'assigned_to': self.env.uid})

    def action_investigate(self):
        self.write({'state': 'investigating', 'assigned_to': self.env.uid})

    def action_resolve(self):
        self.write({'state': 'resolved'})

    def action_false_positive(self):
        self.write({'state': 'false_positive'})

    def action_reopen(self):
        self.write({'state': 'new'})

    def _guess_category(self):
        text = ' '.join(filter(None, [self[:1].name, self[:1].rule_groups])).lower()
        return next((category for keyword, category in CATEGORY_HINTS if keyword in text), 'other')

    def action_create_incident(self):
        """IM02: convert the selected alert(s) into one incident."""
        if not self:
            raise UserError("Select at least one alert.")
        worst = max(self, key=lambda a: (a.severity_rank, a.timestamp))
        incident = self.env['cg.incident'].create({
            'name': worst.name,
            'category': self._guess_category(),
            'severity': worst.severity,
            'detected_date': min(self.mapped('timestamp')),
            'description': "Created from %d alert(s). Highest severity rule: %s (level %s)." % (
                len(self), worst.rule_id or 'n/a', worst.rule_level),
            'asset_ids': [(6, 0, self.asset_id.ids)],
            'analyst_id': self.env.uid,
        })
        self.write({'incident_id': incident.id, 'state': 'investigating'})
        self.env['cg.activity.log'].log('Incident created from alert', 'incident', incident)
        return incident.action_open()

    def action_create_risk(self):
        """RA16: convert relevant alerts into a risk record."""
        if not self:
            raise UserError("Select at least one alert.")
        worst = max(self, key=lambda a: a.severity_rank)
        likelihood = min(5, 2 + (1 if len(self) > 3 else 0) + (1 if any(a.is_repeated for a in self) else 0)
                         + (1 if worst.severity in ('high', 'critical') else 0))
        impact = max([SEV_RANK.get(c, 2) for c in self.asset_id.mapped('criticality')] or [2]) + 1
        risk = self.env['cg.risk'].create({
            'name': 'Risk from alert: %s' % worst.name,
            'threat': worst.name,
            'weakness': "Observed through %d security alert(s); underlying weakness to be confirmed." % len(self),
            'category': 'technical',
            'likelihood': str(likelihood),
            'impact': str(min(5, impact)),
            'asset_ids': [(6, 0, self.asset_id.ids)],
            'owner_id': self.env.uid,
        })
        self.write({'risk_id': risk.id})
        self.env['cg.activity.log'].log('Risk created from alert', 'risk', risk)
        return risk.action_open()

    def action_ai_explain(self):
        """AI10: explain what this alert means and why it matters."""
        self.ensure_one()
        related = self.search([('group_key', '=', self.group_key), ('id', '!=', self.id)], limit=40)
        analysis = self.env['cg.ai.analysis'].create_from_alerts(
            self | related, 'alert_explanation', title='Alert explained: %s' % self.name, focus_alert=self)
        return analysis.action_open()

    def action_ai_analyse(self):
        """AI05: analyse the selected alerts together."""
        if not self:
            raise UserError("Select at least one alert.")
        analysis = self.env['cg.ai.analysis'].create_from_alerts(self, 'log_analysis')
        return analysis.action_open()

    def action_view_related(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Related alerts',
            'res_model': 'cg.alert',
            'view_mode': 'list,form',
            'domain': [('group_key', '=', self.group_key)],
        }

    def action_view_analyses(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'AI analyses',
            'res_model': 'cg.ai.analysis',
            'view_mode': 'list,form',
            'domain': [('alert_ids', 'in', self.ids)],
        }

    @system_write
    def action_block_source(self):
        """NR11: recommend blocking the source IP; execution needs approval."""
        self.ensure_one()
        if not self.src_ip:
            raise UserError("This alert has no source IP to block.")
        action = self.env['cg.response.action'].create({
            'name': 'Block %s' % self.src_ip,
            'action_type': 'block_ip',
            'target': self.src_ip,
            'asset_id': self.asset_id.id,
            'alert_id': self.id,
            'incident_id': self.incident_id.id,
            'reason': 'Recommended from alert %s: %s' % (self.reference, self.name),
        })
        return notify_action('Response recommended',
                             '%s is awaiting manager approval.' % action.name, 'info')
