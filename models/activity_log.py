from odoo import api, fields, models


class CgActivityLog(models.Model):
    _name = 'cg.activity.log'
    _description = 'CyberGuard User Activity Log'
    _order = 'create_date desc, id desc'

    name = fields.Char(string='Action', required=True, readonly=True)
    user_id = fields.Many2one('res.users', string='User', readonly=True,
                              default=lambda self: self.env.user, index=True)
    category = fields.Selection([
        ('auth', 'Authentication'),
        ('asset', 'Assets'),
        ('soc', 'SOC / Wazuh'),
        ('ai', 'AI Analyst'),
        ('vulnerability', 'Vulnerabilities'),
        ('risk', 'Risk'),
        ('incident', 'Incidents'),
        ('threat', 'Threat Intel'),
        ('automation', 'Automation'),
        ('admin', 'Administration'),
    ], default='admin', readonly=True, index=True)
    res_model = fields.Char(string='Model', readonly=True)
    res_id = fields.Integer(string='Record ID', readonly=True)
    res_name = fields.Char(string='Record', readonly=True)
    details = fields.Text(readonly=True)

    @api.model
    def log(self, name, category='admin', record=None, details=None):
        """Record an important user action. Always written with sudo so that
        every role leaves an audit trail without needing write access."""
        vals = {
            'name': name,
            'category': category,
            'user_id': self.env.uid,
            'details': details,
        }
        if record:
            record = record[:1]
            vals.update(res_model=record._name, res_id=record.id, res_name=record.display_name)
        return self.sudo().create(vals)

    def action_open_record(self):
        self.ensure_one()
        if not self.res_model or not self.res_id or self.res_model not in self.env:
            return False
        return {
            'type': 'ir.actions.act_window',
            'res_model': self.res_model,
            'res_id': self.res_id,
            'view_mode': 'form',
        }


class ResUsers(models.Model):
    _inherit = 'res.users'

    cg_role = fields.Char(string='CyberGuard Role', compute='_compute_cg_role')

    def _compute_cg_role(self):
        roles = [
            ('cyberguard_360.group_cg_admin', 'Administrator'),
            ('cyberguard_360.group_cg_manager', 'Manager'),
            ('cyberguard_360.group_cg_analyst', 'Analyst'),
            ('cyberguard_360.group_cg_employee', 'Employee'),
        ]
        for user in self:
            user.cg_role = next((label for xmlid, label in roles if user.has_group(xmlid)), False)

    @api.model
    def _update_last_login(self):
        res = super()._update_last_login()
        self.env['cg.activity.log'].sudo().create({
            'name': 'User logged in',
            'category': 'auth',
            'user_id': self.env.uid,
        })
        return res

    def write(self, vals):
        res = super().write(vals)
        if 'active' in vals and not self.env.context.get('install_mode'):
            for user in self:
                self.env['cg.activity.log'].log(
                    'User %s' % ('reactivated' if vals['active'] else 'deactivated'),
                    'admin', user)
        return res
