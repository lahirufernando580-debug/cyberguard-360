import logging
from datetime import timedelta

import requests

from odoo import api, fields, models
from odoo.exceptions import UserError

from .common import notify_action, system_write

_logger = logging.getLogger(__name__)
TIMEOUT = 25


class CgWazuhConfig(models.Model):
    _name = 'cg.wazuh.config'
    _description = 'Wazuh Connection'

    name = fields.Char(required=True, default='Wazuh')
    active = fields.Boolean(default=True)
    mode = fields.Selection([
        ('demo', 'Demo Simulator'),
        ('live', 'Live Wazuh Server'),
    ], required=True, default='demo',
        help="Demo mode generates realistic alerts without a Wazuh server, "
             "so the whole workflow can be shown anywhere.")
    # Indexer API (alerts, vulnerability states)
    indexer_url = fields.Char(string='Indexer URL', default='https://localhost:9200')
    indexer_user = fields.Char(string='Indexer User', default='admin')
    indexer_password = fields.Char(string='Indexer Password', groups='cyberguard_360.group_cg_admin')
    index_pattern = fields.Char(string='Alert Index Pattern', default='wazuh-alerts-*')
    # Server API (agents, active response)
    api_url = fields.Char(string='Server API URL', default='https://localhost:55000')
    api_user = fields.Char(string='API User', default='wazuh')
    api_password = fields.Char(string='API Password', groups='cyberguard_360.group_cg_admin')
    verify_ssl = fields.Boolean(string='Verify TLS Certificate', default=True)

    min_level = fields.Integer(string='Minimum Rule Level', default=5,
                               help="Alerts below this Wazuh rule level are not imported.")
    batch_size = fields.Integer(default=500)
    auto_sync = fields.Boolean(string='Scheduled Sync', default=True)
    auto_create_assets = fields.Boolean(
        string='Create Assets for Unknown Agents', default=True)
    history_days = fields.Integer(string='History Window (days)', default=7)

    state = fields.Selection([
        ('not_tested', 'Not Tested'),
        ('connected', 'Connected'),
        ('failed', 'Failed'),
    ], default='not_tested', readonly=True)
    last_message = fields.Char(readonly=True)
    last_sync = fields.Datetime(readonly=True)
    last_alert_timestamp = fields.Char(
        string='Sync Cursor', readonly=True,
        help="Timestamp of the last alert imported. The next sync resumes after it, "
             "which prevents duplicates.")
    alerts_imported = fields.Integer(readonly=True)

    # ------------------------------------------------------------------ HTTP
    def _indexer(self, path, payload=None):
        self.ensure_one()
        sudo = self.sudo()
        if not sudo.indexer_url:
            raise UserError("Set the Wazuh indexer URL first.")
        response = requests.request(
            'POST' if payload else 'GET', sudo.indexer_url.rstrip('/') + path, json=payload,
            auth=(sudo.indexer_user or '', sudo.indexer_password or ''),
            verify=sudo.verify_ssl, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _api_token(self):
        """SOC03: authenticate against the Wazuh server API and return a JWT."""
        self.ensure_one()
        sudo = self.sudo()
        if not sudo.api_url:
            raise UserError("Set the Wazuh server API URL first.")
        response = requests.post(
            sudo.api_url.rstrip('/') + '/security/user/authenticate',
            auth=(sudo.api_user or '', sudo.api_password or ''), params={'raw': 'true'},
            verify=sudo.verify_ssl, timeout=TIMEOUT)
        response.raise_for_status()
        return response.text.strip()

    def _api(self, method, path, params=None, payload=None):
        self.ensure_one()
        response = requests.request(
            method, self.sudo().api_url.rstrip('/') + path, params=params, json=payload,
            headers={'Authorization': 'Bearer %s' % self._api_token()},
            verify=self.sudo().verify_ssl, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _fail(self, exc):
        message = str(exc)[:240]
        self.write({'state': 'failed', 'last_message': message})
        _logger.warning("Wazuh request failed: %s", message)
        return notify_action('Wazuh request failed', message, 'danger', sticky=True)

    # ------------------------------------------------------------------ actions
    def action_test_connection(self):
        """SOC02"""
        self.ensure_one()
        self.env['cg.activity.log'].log('Wazuh connection tested', 'soc', self)
        if self.mode == 'demo':
            self.write({'state': 'connected', 'last_message': 'Demo simulator online.'})
            return notify_action('Connected', 'Demo simulator is online. Switch to Live to use a real Wazuh server.')
        try:
            info = self._indexer('/')
            self._api_token()
        except (requests.RequestException, UserError) as exc:
            return self._fail(exc)
        version = (info.get('version') or {}).get('number', 'unknown')
        self.write({'state': 'connected', 'last_message': 'Indexer %s and server API reachable.' % version})
        return notify_action('Connected', self.last_message)

    def _search_alerts(self, since=None, until=None):
        filters = [{'range': {'rule.level': {'gte': self.min_level}}}]
        if since or until:
            bounds = {}
            if since:
                bounds['gt'] = since
            if until:
                bounds['lte'] = until
            filters.append({'range': {'timestamp': bounds}})
        return self._indexer('/%s/_search' % (self.index_pattern or 'wazuh-alerts-*'), {
            'size': max(1, min(self.batch_size or 500, 5000)),
            'sort': [{'timestamp': {'order': 'asc'}}],
            'query': {'bool': {'filter': filters}},
        }).get('hits', {}).get('hits', [])

    @system_write
    def action_sync_alerts(self):
        """SOC04/SOC05: fetch alerts newer than the sync cursor and import them."""
        self.ensure_one()
        if self.mode == 'demo':
            alerts = self.env['cg.demo'].simulate_alerts()
        else:
            try:
                hits = self._search_alerts(since=self.last_alert_timestamp or 'now-24h')
            except (requests.RequestException, UserError) as exc:
                return self._fail(exc)
            alerts = self.env['cg.alert'].import_wazuh_hits(hits)
            if hits:
                self.last_alert_timestamp = hits[-1].get('_source', {}).get('timestamp')
        self.write({
            'state': 'connected',
            'last_sync': fields.Datetime.now(),
            'alerts_imported': self.alerts_imported + len(alerts),
            'last_message': '%d new alert(s) imported.' % len(alerts),
        })
        self.env['cg.activity.log'].log('Wazuh alerts synchronised', 'soc', self, self.last_message)
        return notify_action('Alerts synchronised', self.last_message)

    @system_write
    def action_fetch_history(self):
        """SOC13: import alerts from a previous period. Duplicates are skipped by Wazuh ID."""
        self.ensure_one()
        if self.mode == 'demo':
            alerts = self.env['cg.demo'].simulate_alerts(count=25, spread_hours=24 * max(1, self.history_days))
        else:
            try:
                hits = self._search_alerts(since='now-%dd' % max(1, self.history_days))
            except (requests.RequestException, UserError) as exc:
                return self._fail(exc)
            alerts = self.env['cg.alert'].import_wazuh_hits(hits)
        self.last_message = '%d historical alert(s) imported.' % len(alerts)
        return notify_action('History imported', self.last_message)

    @system_write
    def action_sync_agents(self):
        """SOC06/SOC07: refresh agent inventory and health."""
        self.ensure_one()
        asset_model = self.env['cg.asset']
        if self.mode == 'demo':
            went_offline = self.env['cg.demo'].simulate_agent_health()
            agents = []
        else:
            try:
                agents = self._api('GET', '/agents', params={'limit': 500}).get('data', {}).get('affected_items', [])
            except (requests.RequestException, UserError) as exc:
                return self._fail(exc)
            went_offline = asset_model
        for agent in agents:
            if agent.get('id') == '000':
                continue  # the manager itself
            status = agent.get('status') if agent.get('status') in (
                'active', 'disconnected', 'never_connected', 'pending') else 'disconnected'
            vals = {
                'agent_status': status,
                'agent_version': agent.get('version'),
                'agent_last_keepalive': (agent.get('lastKeepAlive') or '')[:19].replace('T', ' ') or False,
            }
            asset = asset_model.search([('wazuh_agent_id', '=', agent.get('id'))], limit=1)
            if asset:
                if asset.agent_status == 'active' and status == 'disconnected':
                    went_offline |= asset
                asset.write(vals)
            elif self.auto_create_assets:
                os_info = agent.get('os') or {}
                asset_model.create(dict(
                    vals, name=agent.get('name') or 'Agent %s' % agent.get('id'),
                    hostname=agent.get('name'), ip_address=agent.get('ip'),
                    wazuh_agent_id=agent.get('id'),
                    operating_system=' '.join(filter(None, [os_info.get('name'), os_info.get('version')])),
                    asset_type='server' if 'server' in (os_info.get('name') or '').lower() else 'endpoint'))
        for asset in went_offline:
            self.env['cg.notification'].notify(
                'Agent offline: %s' % asset.name,
                'Wazuh agent %s stopped reporting. The endpoint is no longer monitored.' % (asset.wazuh_agent_id or ''),
                ntype='agent_offline', severity='high', record=asset,
                group_xmlid='cyberguard_360.group_cg_admin')
        if went_offline:
            self.env['cg.automation.rule'].sudo().run_trigger('agent_offline', went_offline)
        self.write({'state': 'connected', 'last_message': 'Agent health refreshed.'})
        return notify_action('Agents synchronised', '%d agent(s) went offline.' % len(went_offline)
                             if went_offline else 'All monitored agents are reporting.')

    @system_write
    def action_sync_vulnerabilities(self):
        """VM11: import Wazuh vulnerability-detection states."""
        self.ensure_one()
        if self.mode == 'demo':
            return notify_action('Vulnerabilities synchronised',
                                 'Demo mode: the vulnerability register already holds sample detections.', 'info')
        try:
            hits = self._indexer('/wazuh-states-vulnerabilities-*/_search', {
                'size': 1000, 'query': {'match_all': {}}}).get('hits', {}).get('hits', [])
        except (requests.RequestException, UserError) as exc:
            return self._fail(exc)
        count = self.env['cg.vulnerability'].import_wazuh_states(hits)
        return notify_action('Vulnerabilities synchronised', '%d vulnerability record(s) updated.' % count)

    @system_write
    def action_sync_all(self):
        self.ensure_one()
        self.action_sync_agents()
        return self.action_sync_alerts()

    @api.model
    @system_write
    def cron_sync(self):
        for config in self.search([('auto_sync', '=', True)]):
            try:
                config.action_sync_agents()
                config.action_sync_alerts()
            except Exception:  # a broken connection must not stop the scheduler
                _logger.exception("Scheduled Wazuh sync failed for %s", config.name)

    def run_active_response(self, command, agent_id, arguments=None):
        """NR12: run an approved active-response command through the Wazuh server API."""
        self.ensure_one()
        if self.mode == 'demo':
            return "Demo mode: '%s' simulated on agent %s." % (command, agent_id)
        result = self._api('PUT', '/active-response', params={'agents_list': agent_id},
                           payload={'command': command, 'arguments': arguments or []})
        return result.get('message') or 'Command sent.'
