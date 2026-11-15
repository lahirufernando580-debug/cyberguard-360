from odoo import api, fields, models

from .common import SEVERITY, SEV_RANK

OPEN_ALERT_STATES = ('new', 'acknowledged', 'investigating')
OPEN_VULN_STATES = ('open', 'in_progress')


class CgAssetCategory(models.Model):
    _name = 'cg.asset.category'
    _description = 'IT Asset Category'
    _order = 'sequence, name'

    name = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    code = fields.Char(help="Short code shown on asset cards, e.g. SRV, EP, NET.")
    description = fields.Text()
    asset_ids = fields.One2many('cg.asset', 'category_id')
    asset_count = fields.Integer(compute='_compute_asset_count')

    @api.depends('asset_ids')
    def _compute_asset_count(self):
        for category in self:
            category.asset_count = len(category.asset_ids)


class CgAsset(models.Model):
    _name = 'cg.asset'
    _description = 'IT Asset'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'criticality_rank desc, name'

    name = fields.Char(required=True, tracking=True)
    active = fields.Boolean(default=True)
    asset_type = fields.Selection([
        ('server', 'Server'),
        ('endpoint', 'Endpoint'),
        ('network', 'Network Device'),
        ('cloud', 'Cloud Resource'),
        ('application', 'Application'),
        ('iot', 'IoT / OT'),
    ], string='Type', required=True, default='endpoint', tracking=True)
    category_id = fields.Many2one('cg.asset.category', string='Category', tracking=True)
    hostname = fields.Char()
    ip_address = fields.Char(string='IP Address', index=True, tracking=True)
    mac_address = fields.Char(string='MAC Address')
    operating_system = fields.Char(string='Operating System')
    location = fields.Char()
    internet_facing = fields.Boolean(
        string='Internet Facing', tracking=True,
        help="Internet-facing assets carry more business risk for the same weakness.")
    owner_id = fields.Many2one('res.users', string='Owner', tracking=True)
    department = fields.Char(tracking=True)
    criticality = fields.Selection(SEVERITY, required=True, default='medium', tracking=True,
                                   help="Business importance of this asset.")
    criticality_rank = fields.Integer(compute='_compute_criticality_rank', store=True)
    status = fields.Selection([
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('maintenance', 'Maintenance'),
        ('retired', 'Retired'),
    ], default='active', required=True, tracking=True)
    notes = fields.Text()

    # Wazuh agent link
    wazuh_agent_id = fields.Char(string='Wazuh Agent ID', index=True, tracking=True, copy=False,
                                 help="Agent ID as shown in Wazuh (e.g. 003). Alerts are matched on it.")
    agent_status = fields.Selection([
        ('active', 'Active'),
        ('disconnected', 'Disconnected'),
        ('never_connected', 'Never Connected'),
        ('pending', 'Pending'),
        ('none', 'No Agent'),
    ], string='Agent Status', default='none', tracking=True)
    agent_version = fields.Char(string='Agent Version')
    agent_last_keepalive = fields.Datetime(string='Last Keepalive')

    # History
    alert_ids = fields.One2many('cg.alert', 'asset_id', string='Alerts')
    vulnerability_ids = fields.Many2many('cg.vulnerability', 'cg_vulnerability_asset_rel',
                                         'asset_id', 'vulnerability_id', string='Vulnerabilities')
    risk_ids = fields.Many2many('cg.risk', 'cg_risk_asset_rel', 'asset_id', 'risk_id', string='Risks')
    incident_ids = fields.Many2many('cg.incident', 'cg_incident_asset_rel', 'asset_id', 'incident_id',
                                    string='Incidents')
    alert_count = fields.Integer(compute='_compute_counts')
    open_alert_count = fields.Integer(compute='_compute_counts')
    vulnerability_count = fields.Integer(compute='_compute_counts')
    risk_count = fields.Integer(compute='_compute_counts')
    incident_count = fields.Integer(compute='_compute_counts')
    risk_score = fields.Integer(string='Exposure Score', compute='_compute_counts',
                                help="0-100 indicator combining criticality, open alerts, "
                                     "open vulnerabilities, exposure and agent health.")
    risk_band = fields.Selection(SEVERITY, string='Exposure', compute='_compute_counts')

    _wazuh_agent_unique = models.Constraint(
        'UNIQUE(wazuh_agent_id)', "This Wazuh agent is already linked to another asset.")

    @api.depends('criticality')
    def _compute_criticality_rank(self):
        for asset in self:
            asset.criticality_rank = SEV_RANK.get(asset.criticality, 0)

    @api.depends('alert_ids.state', 'alert_ids.severity', 'vulnerability_ids.state',
                 'vulnerability_ids.cvss_score', 'risk_ids', 'incident_ids', 'criticality',
                 'internet_facing', 'agent_status', 'status')
    def _compute_counts(self):
        base = {'low': 8, 'medium': 16, 'high': 26, 'critical': 36}
        alert_weight = {'low': 0.5, 'medium': 1.5, 'high': 4, 'critical': 8}
        for asset in self:
            # sudo: asset owners see the counters without access to the underlying records
            source = asset.sudo()
            open_alerts = source.alert_ids.filtered(lambda a: a.state in OPEN_ALERT_STATES)
            open_vulns = source.vulnerability_ids.filtered(lambda v: v.state in OPEN_VULN_STATES)
            asset.alert_count = len(source.alert_ids)
            asset.open_alert_count = len(open_alerts)
            asset.vulnerability_count = len(open_vulns)
            asset.risk_count = len(source.risk_ids)
            asset.incident_count = len(source.incident_ids)
            score = base.get(asset.criticality, 16)
            score += min(30, sum(alert_weight.get(a.severity, 1) for a in open_alerts))
            score += min(22, sum(v.cvss_score for v in open_vulns) * 0.9)
            if asset.internet_facing and open_vulns:
                score += 8
            if asset.status == 'active' and asset.agent_status in ('disconnected', 'never_connected'):
                score += 6
            score = int(min(100, round(score)))
            asset.risk_score = score
            asset.risk_band = ('critical' if score >= 75 else 'high' if score >= 55
                               else 'medium' if score >= 35 else 'low')

    @api.model_create_multi
    def create(self, vals_list):
        assets = super().create(vals_list)
        if not self.env.context.get('cg_demo'):
            for asset in assets:
                self.env['cg.activity.log'].log('Asset registered', 'asset', asset)
        return assets

    def _open_related(self, model, name, domain):
        return {
            'type': 'ir.actions.act_window',
            'name': name,
            'res_model': model,
            'view_mode': 'list,form',
            'domain': domain,
        }

    def action_view_alerts(self):
        return self._open_related('cg.alert', 'Alerts', [('asset_id', 'in', self.ids)])

    def action_view_vulnerabilities(self):
        return self._open_related('cg.vulnerability', 'Vulnerabilities', [('asset_ids', 'in', self.ids)])

    def action_view_risks(self):
        return self._open_related('cg.risk', 'Risks', [('asset_ids', 'in', self.ids)])

    def action_view_incidents(self):
        return self._open_related('cg.incident', 'Incidents', [('asset_ids', 'in', self.ids)])

    def action_set_inactive(self):
        self.write({'status': 'inactive'})

    def action_set_active(self):
        self.write({'status': 'active'})
