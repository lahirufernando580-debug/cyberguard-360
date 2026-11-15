from odoo import api, fields, models
from odoo.exceptions import UserError

from .common import SCALE_1_5, SEVERITY, SEV_RANK, score_to_level

CONTROL_REDUCTION = {'none': 0, 'partial': 1, 'substantial': 2, 'full': 3}


class CgRisk(models.Model):
    _name = 'cg.risk'
    _description = 'Cybersecurity Risk'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'score desc, id desc'

    name = fields.Char(string='Risk', required=True, tracking=True)
    reference = fields.Char(readonly=True, copy=False, default='New')
    description = fields.Text()
    threat = fields.Text(string='Threat', help="What could happen, and who or what would cause it.")
    weakness = fields.Text(string='Weakness', help="The gap that makes the threat possible.")
    category = fields.Selection([
        ('technical', 'Technical'),
        ('operational', 'Operational'),
        ('human', 'People'),
        ('third_party', 'Third Party'),
        ('compliance', 'Compliance'),
        ('physical', 'Physical'),
    ], default='technical', required=True, tracking=True)
    owner_id = fields.Many2one('res.users', string='Risk Owner', tracking=True)
    asset_ids = fields.Many2many('cg.asset', 'cg_risk_asset_rel', 'risk_id', 'asset_id', string='Assets')
    vulnerability_ids = fields.Many2many('cg.vulnerability', 'cg_risk_vulnerability_rel', 'risk_id',
                                         'vulnerability_id', string='Vulnerabilities')
    alert_ids = fields.One2many('cg.alert', 'risk_id', string='Alerts')

    # Inherent risk
    likelihood = fields.Selection(SCALE_1_5, required=True, default='3', tracking=True)
    impact = fields.Selection(SCALE_1_5, string='Business Impact', required=True, default='3', tracking=True)
    score = fields.Integer(string='Risk Score', compute='_compute_score', store=True, tracking=True)
    level = fields.Selection(SEVERITY, string='Risk Level', compute='_compute_score', store=True, index=True)

    # Treatment
    treatment = fields.Selection([
        ('mitigate', 'Mitigate'), ('accept', 'Accept'), ('transfer', 'Transfer'), ('avoid', 'Avoid'),
    ], default='mitigate', tracking=True)
    mitigation_plan = fields.Text(string='Mitigation Plan')
    controls = fields.Text(string='Security Controls')
    control_effectiveness = fields.Selection([
        ('none', 'Not Implemented'),
        ('partial', 'Partially Effective'),
        ('substantial', 'Substantially Effective'),
        ('full', 'Fully Effective'),
    ], default='none', tracking=True)
    due_date = fields.Date(string='Treatment Due')

    # Residual risk
    residual_likelihood = fields.Selection(SCALE_1_5, tracking=True)
    residual_impact = fields.Selection(SCALE_1_5, tracking=True)
    residual_score = fields.Integer(compute='_compute_residual', store=True)
    residual_level = fields.Selection(SEVERITY, compute='_compute_residual', store=True)
    risk_reduction = fields.Integer(string='Risk Reduction %', compute='_compute_residual', store=True)

    state = fields.Selection([
        ('identified', 'Identified'),
        ('assessed', 'Assessed'),
        ('treating', 'In Treatment'),
        ('monitoring', 'Monitoring'),
        ('closed', 'Closed'),
    ], default='identified', required=True, index=True, tracking=True)
    last_review_date = fields.Date(readonly=True)
    next_review_date = fields.Date()
    ai_rationale = fields.Text(string='AI Assessment', readonly=True)
    analysis_ids = fields.One2many('cg.ai.analysis', 'risk_id', string='AI Analyses')

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('reference', 'New') == 'New':
                vals['reference'] = self.env['ir.sequence'].next_by_code('cg.risk') or 'New'
        risks = super().create(vals_list)
        if not self.env.context.get('cg_demo'):
            risks._notify_if_critical()
        return risks

    def write(self, vals):
        was_critical = {r.id for r in self if r.level == 'critical'}
        res = super().write(vals)
        if {'likelihood', 'impact'} & set(vals):
            self.filtered(lambda r: r.id not in was_critical)._notify_if_critical()
        return res

    def _notify_if_critical(self):
        """NR05"""
        for risk in self.filtered(lambda r: r.level == 'critical'):
            self.env['cg.notification'].notify(
                'Critical risk: %s' % risk.name,
                'Score %d (likelihood %s x impact %s). Owner: %s.' % (
                    risk.score, risk.likelihood, risk.impact, risk.owner_id.name or 'unassigned'),
                ntype='risk', severity='critical', record=risk,
                group_xmlid='cyberguard_360.group_cg_manager')
        critical = self.filtered(lambda r: r.level == 'critical')
        if critical:
            self.env['cg.automation.rule'].sudo().run_trigger('risk', critical)

    @api.depends('likelihood', 'impact')
    def _compute_score(self):
        for risk in self:
            risk.score = int(risk.likelihood or 0) * int(risk.impact or 0)
            risk.level = score_to_level(risk.score)

    @api.depends('residual_likelihood', 'residual_impact', 'score')
    def _compute_residual(self):
        for risk in self:
            if risk.residual_likelihood and risk.residual_impact:
                risk.residual_score = int(risk.residual_likelihood) * int(risk.residual_impact)
                risk.residual_level = score_to_level(risk.residual_score)
                risk.risk_reduction = round(100 * (risk.score - risk.residual_score) / risk.score) if risk.score else 0
            else:
                risk.residual_score = 0
                risk.residual_level = False
                risk.risk_reduction = 0

    def action_open(self):
        self.ensure_one()
        return {'type': 'ir.actions.act_window', 'res_model': 'cg.risk', 'res_id': self.id, 'view_mode': 'form'}

    # ------------------------------------------------------------------ workflow
    def action_assess(self):
        self.write({'state': 'assessed'})

    def action_treat(self):
        for risk in self:
            if risk.treatment == 'mitigate' and not risk.mitigation_plan:
                raise UserError("Describe the mitigation plan before starting treatment.")
        self.write({'state': 'treating'})

    def action_monitor(self):
        self.write({'state': 'monitoring'})

    def action_close(self):
        self.write({'state': 'closed'})
        for risk in self:
            self.env['cg.activity.log'].log('Risk closed', 'risk', risk)

    def action_reopen(self):
        self.write({'state': 'assessed'})

    def action_calculate_residual(self):
        """RA14: estimate what remains once the recorded controls are in place."""
        for risk in self:
            reduction = CONTROL_REDUCTION.get(risk.control_effectiveness, 0)
            likelihood = max(1, int(risk.likelihood) - reduction)
            # Controls mostly lower likelihood; only fully effective ones also limit impact.
            impact = max(1, int(risk.impact) - (1 if reduction >= 3 else 0))
            risk.write({'residual_likelihood': str(likelihood), 'residual_impact': str(impact)})

    def action_reassess(self):
        """RA13: recalculate after remediation and record the review."""
        today = fields.Date.context_today(self)
        for risk in self:
            before = risk.residual_score or risk.score
            risk.action_calculate_residual()
            risk.last_review_date = today
            risk.message_post(body="Risk reassessed: residual score %d (was %d). Controls: %s." % (
                risk.residual_score, before,
                dict(risk._fields['control_effectiveness'].selection)[risk.control_effectiveness]))
            if risk.state in ('identified', 'assessed'):
                risk.state = 'assessed'

    def action_ai_analysis(self):
        """RA10/RA11: context-aware assessment. A weakness on a critical, internet-facing
        server scores higher than the same weakness on an isolated test machine."""
        self.ensure_one()
        assets, vulns = self.asset_ids, self.vulnerability_ids
        alerts = self.alert_ids | self.env['cg.alert'].search(
            [('asset_id', 'in', assets.ids), ('state', 'in', ('new', 'acknowledged', 'investigating'))], limit=120)
        worst_asset = max((SEV_RANK.get(a.criticality, 2) for a in assets), default=2)
        exposed = any(assets.mapped('internet_facing'))
        max_cvss = max(vulns.mapped('cvss_score'), default=0.0)
        exploited = any(vulns.mapped('exploited'))
        serious_alerts = len(alerts.filtered(lambda a: a.severity in ('high', 'critical')))

        likelihood = 2
        reasons = []
        if exposed:
            likelihood += 1
            reasons.append("at least one affected asset is reachable from the internet (+1 likelihood)")
        if max_cvss >= 7.0:
            likelihood += 1
            reasons.append("a linked vulnerability has CVSS %.1f (+1 likelihood)" % max_cvss)
        if exploited:
            likelihood += 1
            reasons.append("a linked vulnerability is exploited in the wild (+1 likelihood)")
        if serious_alerts:
            likelihood += 1
            reasons.append("%d open high/critical alert(s) on the affected assets show active interest (+1 likelihood)" % serious_alerts)
        if not assets:
            reasons.append("no assets are linked, so exposure could not be measured")
        likelihood = min(5, likelihood)
        impact = min(5, worst_asset + 1)
        reasons.append("the most important affected asset is rated %s (impact %d)" % (
            dict(SEVERITY).get({1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}[worst_asset]).lower(), impact))

        controls = []
        if exposed:
            controls.append("Limit internet exposure: place the service behind a VPN or WAF and allow only required ports.")
        if vulns:
            controls.append("Patch linked vulnerabilities in priority order and verify with a rescan.")
        if serious_alerts:
            controls.append("Investigate the open high-severity alerts and block confirmed malicious sources.")
        controls += ["Enforce multi-factor authentication for administrative access.",
                     "Confirm that tested, offline backups exist for the affected assets.",
                     "Add monitoring rules so recurrence raises an alert automatically."]

        rationale = "Suggested likelihood %d and impact %d (score %d, %s) because %s." % (
            likelihood, impact, likelihood * impact, score_to_level(likelihood * impact), '; '.join(reasons))
        self.write({
            'likelihood': str(likelihood),
            'impact': str(impact),
            'ai_rationale': rationale,
            'controls': self.controls or '\n'.join(controls),
            'state': 'assessed' if self.state == 'identified' else self.state,
        })
        if alerts:
            self.env['cg.ai.analysis'].create_from_alerts(
                alerts, 'risk', title='Risk analysis: %s' % self.name, risk=self)
        self.message_post(body="AI risk analysis applied. %s" % rationale)
        return True

    @api.model
    def cron_review_reminders(self):
        today = fields.Date.context_today(self)
        for risk in self.search([('state', 'in', ('treating', 'assessed')), ('due_date', '<', today)]):
            self.env['cg.notification'].notify(
                'Risk treatment overdue: %s' % risk.name, 'Treatment was due %s.' % risk.due_date,
                ntype='reminder', severity=risk.level, record=risk, users=risk.owner_id,
                group_xmlid=None if risk.owner_id else 'cyberguard_360.group_cg_manager')

    def action_print(self):
        return self.env.ref('cyberguard_360.action_report_risk').report_action(self)
