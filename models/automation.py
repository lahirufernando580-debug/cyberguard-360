import logging

import requests

from odoo import api, fields, models
from odoo.exceptions import UserError

from .common import SEVERITY, SEV_RANK, notify_action, system_write

_logger = logging.getLogger(__name__)

# Wazuh active-response command per action type
WAZUH_COMMANDS = {
    'block_ip': 'firewall-drop0',
    'isolate_host': 'host-deny0',
    'disable_account': 'disable-account0',
    'restart_agent': 'restart-wazuh0',
}


class CgAutomationRule(models.Model):
    _name = 'cg.automation.rule'
    _description = 'Automation Rule'
    _order = 'sequence, id'

    name = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    trigger = fields.Selection([
        ('alert', 'New Alert Imported'),
        ('agent_offline', 'Agent Goes Offline'),
        ('vulnerability', 'New Vulnerability'),
        ('risk', 'Risk Becomes Critical'),
        ('incident_overdue', 'Incident Passes SLA'),
    ], required=True, default='alert')
    min_severity = fields.Selection(SEVERITY, string='Minimum Severity', default='high')
    keyword = fields.Char(string='Description Contains',
                          help="Optional. Only records whose description or rule groups contain this text.")
    repeat_threshold = fields.Integer(
        string='Minimum Occurrences', default=0,
        help="Alerts only: fire when the same rule/agent/source repeats at least this many times in 24h.")
    action = fields.Selection([
        ('notify', 'Send Notification'),
        ('create_incident', 'Create Incident'),
        ('create_risk', 'Create Risk'),
        ('recommend_response', 'Recommend Response Action'),
    ], required=True, default='notify')
    notify_role = fields.Selection([
        ('cyberguard_360.group_cg_analyst', 'Analysts'),
        ('cyberguard_360.group_cg_manager', 'Managers'),
        ('cyberguard_360.group_cg_admin', 'Administrators'),
    ], string='Notify', default='cyberguard_360.group_cg_analyst')
    description = fields.Text()
    run_count = fields.Integer(string='Times Fired', readonly=True)
    last_run = fields.Datetime(readonly=True)

    @api.model
    def run_trigger(self, trigger, records):
        """Evaluate every active rule for ``trigger`` against ``records``."""
        if not records:
            return
        for rule in self.search([('trigger', '=', trigger)]):
            try:
                matched = rule._match(records)
                if matched and rule._execute(matched):
                    rule.write({'run_count': rule.run_count + 1, 'last_run': fields.Datetime.now()})
            except Exception:  # one bad rule must not block alert ingestion
                _logger.exception("Automation rule %s failed", rule.name)

    def _match(self, records):
        self.ensure_one()
        threshold = SEV_RANK.get(self.min_severity, 0)
        keyword = (self.keyword or '').lower()

        def keep(record):
            severity = getattr(record, 'severity', None) or getattr(record, 'level', None) or \
                getattr(record, 'criticality', None)
            if threshold and severity and SEV_RANK.get(severity, 0) < threshold:
                return False
            if keyword:
                text = ' '.join(filter(None, [record.display_name, getattr(record, 'rule_groups', '') or '']))
                if keyword not in text.lower():
                    return False
            if self.trigger == 'alert' and self.repeat_threshold and record.repeat_count < self.repeat_threshold:
                return False
            return True
        return records.filtered(keep)

    def _execute(self, records):
        self.ensure_one()
        if self.action == 'notify':
            self.env['cg.notification'].notify(
                '%s (%d)' % (self.name, len(records)),
                '\n'.join(records[:6].mapped('display_name')),
                ntype='system', severity=self.min_severity or 'medium', record=records[:1],
                group_xmlid=self.notify_role)
            return True
        if self.trigger != 'alert':
            return False
        fired = False
        if self.action == 'create_incident':
            # NR09/NR10: related alerts are grouped into one incident per group key.
            pending = records.filtered(lambda a: not a.incident_id)
            for key in set(pending.mapped('group_key')):
                group = pending.filtered(lambda a, key=key: a.group_key == key)
                existing = self.env['cg.alert'].search(
                    [('group_key', '=', key), ('incident_id', '!=', False),
                     ('incident_id.stage', '!=', 'closed')], limit=1).incident_id
                if existing:
                    group.write({'incident_id': existing.id})
                    continue
                worst = max(group, key=lambda a: a.severity_rank)
                incident = self.env['cg.incident'].create({
                    'name': worst.name,
                    'category': group._guess_category(),
                    'severity': worst.severity,
                    'detected_date': min(group.mapped('timestamp')),
                    'description': 'Created automatically by rule "%s" from %d grouped alert(s).' % (self.name, len(group)),
                    'asset_ids': [(6, 0, group.asset_id.ids)],
                    'reporter_id': self.env.ref('base.user_root').id,
                })
                group.write({'incident_id': incident.id})
                fired = True
        elif self.action == 'create_risk':
            for key in set(records.filtered(lambda a: not a.risk_id).mapped('group_key')):
                records.filtered(lambda a, key=key: a.group_key == key and not a.risk_id).action_create_risk()
                fired = True
        elif self.action == 'recommend_response':
            action_model = self.env['cg.response.action']
            for ip in {a.src_ip for a in records if a.src_ip}:
                if action_model.search_count([('action_type', '=', 'block_ip'), ('target', '=', ip),
                                              ('state', 'in', ('recommended', 'approved', 'executed'))]):
                    continue
                source = records.filtered(lambda a, ip=ip: a.src_ip == ip)
                action_model.create({
                    'name': 'Block %s' % ip, 'action_type': 'block_ip', 'target': ip,
                    'asset_id': source[:1].asset_id.id, 'alert_id': source[:1].id,
                    'incident_id': source[:1].incident_id.id,
                    'reason': 'Rule "%s": %d alert(s) from this address.' % (self.name, len(source)),
                })
                fired = True
        return fired


class CgResponseAction(models.Model):
    _name = 'cg.response.action'
    _description = 'Response Action'
    _inherit = ['cg.system.record', 'mail.thread']
    _order = 'create_date desc, id desc'
    # Recommendations are raised by alerts, incidents and automation rules; managers approve,
    # reject or execute them but nobody types a new one in or deletes it.
    _cg_locked_fields = ('name', 'action_type', 'target', 'asset_id', 'incident_id', 'alert_id', 'reason')

    name = fields.Char(required=True)
    action_type = fields.Selection([
        ('block_ip', 'Block IP Address'),
        ('isolate_host', 'Isolate Host'),
        ('disable_account', 'Disable Account'),
        ('restart_agent', 'Restart Agent'),
        ('custom', 'Manual Action'),
    ], string='Action', required=True, default='block_ip')
    target = fields.Char(required=True, help="IP address, hostname or account the action applies to.")
    asset_id = fields.Many2one('cg.asset', string='Run On Asset')
    alert_id = fields.Many2one('cg.alert', string='Source Alert', ondelete='set null')
    incident_id = fields.Many2one('cg.incident', ondelete='set null')
    reason = fields.Text()
    state = fields.Selection([
        ('recommended', 'Recommended'),
        ('approved', 'Approved'),
        ('executed', 'Executed'),
        ('rejected', 'Rejected'),
        ('failed', 'Failed'),
    ], default='recommended', required=True, tracking=True, index=True)
    requested_by = fields.Many2one('res.users', default=lambda self: self.env.user, readonly=True)
    approved_by = fields.Many2one('res.users', readonly=True, tracking=True)
    executed_date = fields.Datetime(readonly=True)
    result = fields.Text(readonly=True)

    def action_approve(self):
        if not self.env.user.has_group('cyberguard_360.group_cg_manager'):
            raise UserError("Only a manager or administrator can approve response actions.")
        self.filtered(lambda a: a.state == 'recommended').write({'state': 'approved', 'approved_by': self.env.uid})
        for action in self:
            self.env['cg.activity.log'].log('Response action approved', 'automation', action)

    def action_reject(self):
        self.write({'state': 'rejected'})

    def action_execute(self):
        """NR12: only approved actions run, and every execution is logged."""
        config = self.env['cg.wazuh.config'].search([], limit=1)
        for action in self:
            if action.state != 'approved':
                raise UserError("'%s' must be approved before it can be executed." % action.name)
            command = WAZUH_COMMANDS.get(action.action_type)
            agent_id = action.asset_id.wazuh_agent_id
            if not command:
                action.write({'state': 'executed', 'executed_date': fields.Datetime.now(),
                              'result': 'Manual action recorded as completed.'})
            elif not config or not agent_id:
                action.write({'state': 'failed', 'result': 'No Wazuh connection or no agent linked to the asset. '
                                                           'Select an asset with a Wazuh agent and retry.'})
            else:
                try:
                    result = config.run_active_response(command, agent_id, [action.target])
                    action.write({'state': 'executed', 'executed_date': fields.Datetime.now(), 'result': result})
                except (requests.RequestException, UserError) as exc:
                    action.write({'state': 'failed', 'result': str(exc)[:500]})
            self.env['cg.activity.log'].log('Response action %s' % action.state, 'automation', action, action.result)
            if action.incident_id:
                action.incident_id._add_note('Response action "%s": %s' % (action.name, action.state), 'action')
        failed = self.filtered(lambda a: a.state == 'failed')
        if failed:
            return notify_action('Execution failed', failed[0].result, 'danger', sticky=True)
        return notify_action('Response executed', '%d action(s) completed.' % len(self))

    def action_retry(self):
        self.filtered(lambda a: a.state == 'failed').write({'state': 'approved'})
