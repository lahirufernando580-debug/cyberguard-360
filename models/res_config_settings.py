from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    cg_ai_provider = fields.Selection([
        ('builtin', 'CyberGuard built-in engine (offline)'),
        ('claude', 'Claude (Anthropic API)'),
    ], string='AI Engine', default='builtin', config_parameter='cyberguard_360.ai_provider')
    cg_ai_api_key = fields.Char(string='Anthropic API Key', config_parameter='cyberguard_360.ai_api_key')
    cg_ai_model = fields.Char(string='Claude Model', default='claude-opus-5-5',
                              config_parameter='cyberguard_360.ai_model')
    cg_ti_external_enabled = fields.Boolean(
        string='Allow External Threat Intelligence Lookups',
        config_parameter='cyberguard_360.ti_external_enabled')
    cg_virustotal_api_key = fields.Char(string='VirusTotal API Key',
                                        config_parameter='cyberguard_360.virustotal_api_key')
    cg_nvd_api_key = fields.Char(string='NVD API Key', config_parameter='cyberguard_360.nvd_api_key')

    cg_threatfox_api_key = fields.Char(
        string='abuse.ch ThreatFox Auth-Key',
        config_parameter='cyberguard_360.threatfox_api_key',
        help='Auth-Key for the abuse.ch ThreatFox API. ThreatFox requires it for every request; '
             'it is free at https://auth.abuse.ch/')
