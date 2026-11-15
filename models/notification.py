from odoo import api, fields, models

from .common import SEVERITY


class CgNotification(models.Model):
    _name = 'cg.notification'
    _inherit = ['cg.system.record']
    _description = 'CyberGuard Notification'
    # Only the read / unread flag is user-editable.
    _cg_locked_fields = ('name', 'message', 'ntype', 'severity', 'user_ids', 'res_model', 'res_id')
    _order = 'create_date desc, id desc'

    name = fields.Char(string='Title', required=True)
    message = fields.Text()
    ntype = fields.Selection([
        ('critical_alert', 'Critical Alert'),
        ('incident', 'New Incident'),
        ('agent_offline', 'Agent Offline'),
        ('vulnerability', 'Vulnerability'),
        ('risk', 'Critical Risk'),
        ('reminder', 'Remediation Reminder'),
        ('escalation', 'Escalation'),
        ('daily_summary', 'Daily AI Summary'),
        ('response', 'Response Action'),
        ('system', 'System'),
    ], string='Type', default='system', required=True, index=True)
    severity = fields.Selection(SEVERITY, default='medium')
    user_ids = fields.Many2many('res.users', 'cg_notification_user_rel', 'notification_id', 'user_id',
                                string='Recipients')
    is_read = fields.Boolean(string='Read', default=False, index=True)
    res_model = fields.Char()
    res_id = fields.Integer()

    @api.model
    def notify(self, title, message='', ntype='system', severity='medium', record=None,
               group_xmlid=None, users=None):
        """Create a notification for a set of users and/or every member of a role."""
        recipients = users or self.env['res.users']
        if group_xmlid:
            group = self.env.ref(group_xmlid, raise_if_not_found=False)
            if group:
                recipients |= group.sudo().all_user_ids if 'all_user_ids' in group._fields else group.sudo().user_ids
        vals = {
            'name': title,
            'message': message,
            'ntype': ntype,
            'severity': severity,
            'user_ids': [(6, 0, recipients.ids)],
        }
        if record:
            vals.update(res_model=record._name, res_id=record[:1].id)
        return self.sudo().create(vals)

    def action_mark_read(self):
        self.write({'is_read': True})

    def action_mark_unread(self):
        self.write({'is_read': False})

    def action_open_record(self):
        self.ensure_one()
        self.is_read = True
        if not self.res_model or not self.res_id or self.res_model not in self.env:
            return False
        return {
            'type': 'ir.actions.act_window',
            'res_model': self.res_model,
            'res_id': self.res_id,
            'view_mode': 'form',
        }
