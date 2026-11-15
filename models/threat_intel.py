import ipaddress
import logging
import re
from datetime import datetime

import requests

from odoo import api, fields, models
from odoo.exceptions import UserError
from odoo.tools import split_every

from .common import notify_action, system_write

_logger = logging.getLogger(__name__)

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|dev|app|site|online)\b', re.I)
HASH_RE = re.compile(r'\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b', re.I)

# abuse.ch ThreatFox community API, documented at https://threatfox.abuse.ch/api/
THREATFOX_URL = 'https://threatfox-api.abuse.ch/api/v1/'
THREATFOX_DAYS = 3  # the API accepts 1 to 7
THREATFOX_SOURCE = 'abuse.ch ThreatFox'
THREATFOX_IOC_TYPES = {
    'ip:port': 'ip', 'ip': 'ip', 'domain': 'domain',
    'url': 'url', 'md5_hash': 'hash', 'sha1_hash': 'hash',
    'sha256_hash': 'hash',
}
MAX_IOC_LENGTH = 1024  # PostgreSQL cannot index longer values

# The intelligence notes of an indicator are blocks separated by a blank line: the
# local assessment, then one block per external source. A block is recognised by its
# first words, so each source refreshes its own block and leaves the others alone.
THREATFOX_HEADER = 'Source: %s' % THREATFOX_SOURCE
VIRUSTOTAL_HEADER = 'VirusTotal:'
EXTERNAL_HEADERS = (THREATFOX_HEADER, VIRUSTOTAL_HEADER)
REPUTATION_RANK = {'clean': 0, 'unknown': 1, 'suspicious': 2, 'malicious': 3}


def worst_reputation(*reputations):
    return max(reputations, key=lambda reputation: REPUTATION_RANK.get(reputation, 0))


class CgMitreTechnique(models.Model):
    _name = 'cg.mitre.technique'
    _inherit = ['cg.system.record']
    _description = 'MITRE ATT&CK Technique'
    # Reference catalogue: loaded from the MITRE data file or created from Wazuh alerts.
    _cg_locked_fields = ('code', 'name', 'tactic', 'description', 'alert_ids')
    _order = 'code'
    _rec_name = 'code'

    code = fields.Char(string='Technique ID', required=True, index=True)
    name = fields.Char(required=True)
    tactic = fields.Char(help="ATT&CK tactic this technique belongs to.")
    description = fields.Text()
    url = fields.Char(compute='_compute_url')
    alert_ids = fields.Many2many('cg.alert', 'cg_alert_mitre_rel', 'technique_id', 'alert_id', string='Alerts')
    alert_count = fields.Integer(compute='_compute_alert_count')

    _code_unique = models.Constraint('UNIQUE(code)', "This ATT&CK technique already exists.")

    @api.depends('code', 'name')
    def _compute_display_name(self):
        for technique in self:
            technique.display_name = '%s  %s' % (technique.code, technique.name) if technique.name else technique.code

    @api.depends('code')
    def _compute_url(self):
        for technique in self:
            technique.url = 'https://attack.mitre.org/techniques/%s/' % (technique.code or '').replace('.', '/')

    @api.depends('alert_ids')
    def _compute_alert_count(self):
        for technique in self:
            technique.alert_count = len(technique.alert_ids)

    def action_view_alerts(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': self.display_name,
            'res_model': 'cg.alert',
            'view_mode': 'list,form',
            'domain': [('mitre_technique_ids', 'in', self.ids)],
        }


class CgIoc(models.Model):
    _name = 'cg.ioc'
    _description = 'Indicator of Compromise'
    _inherit = ['cg.system.record', 'mail.thread']
    _order = 'score desc, last_seen desc'
    # Extracted from alerts or downloaded from ThreatFox. Reputation, intelligence notes
    # and analyst notes remain editable.
    _cg_locked_fields = ('value', 'ioc_type', 'scope', 'source', 'score', 'first_seen', 'last_seen', 'alert_ids')
    _rec_name = 'value'

    value = fields.Char(string='Indicator', required=True, index=True)
    ioc_type = fields.Selection([
        ('ip', 'IP Address'),
        ('domain', 'Domain'),
        ('hash', 'File Hash'),
        ('url', 'URL'),
        ('email', 'Email'),
    ], string='Type', required=True, default='ip')
    reputation = fields.Selection([
        ('unknown', 'Unknown'),
        ('clean', 'Clean'),
        ('suspicious', 'Suspicious'),
        ('malicious', 'Malicious'),
    ], default='unknown', required=True, tracking=True)
    score = fields.Integer(string='Threat Score', help="0-100, higher is worse.")
    scope = fields.Selection([('external', 'External'), ('internal', 'Internal')], default='external')
    source = fields.Char(default='Extracted from alerts')
    first_seen = fields.Datetime()
    last_seen = fields.Datetime()
    alert_ids = fields.Many2many('cg.alert', 'cg_ioc_alert_rel', 'ioc_id', 'alert_id', string='Related Alerts')
    alert_count = fields.Integer(compute='_compute_alert_count', store=True)
    technique_ids = fields.Many2many('cg.mitre.technique', string='ATT&CK Techniques',
                                     compute='_compute_techniques')
    asset_ids = fields.Many2many('cg.asset', string='Targeted Assets', compute='_compute_techniques')
    enrichment = fields.Text(string='Intelligence Notes')
    notes = fields.Text()

    _value_unique = models.Constraint('UNIQUE(value, ioc_type)', "This indicator is already tracked.")

    @api.depends('alert_ids')
    def _compute_alert_count(self):
        for ioc in self:
            ioc.alert_count = len(ioc.alert_ids)

    @api.depends('alert_ids')
    def _compute_techniques(self):
        for ioc in self:
            ioc.technique_ids = ioc.alert_ids.mitre_technique_ids
            ioc.asset_ids = ioc.alert_ids.asset_id

    # ------------------------------------------------------------------ intelligence notes
    def _intel_blocks(self):
        self.ensure_one()
        return [block.strip() for block in (self.enrichment or '').split('\n\n') if block.strip()]

    def _intel_with_block(self, header, block):
        """Intelligence notes with the block starting with ``header`` replaced by ``block``."""
        return '\n\n'.join([kept for kept in self._intel_blocks() if not kept.startswith(header)] + [block])

    # ------------------------------------------------------------------ extraction
    @api.model
    def extract_from_alerts(self, alerts):
        """TI04: pull IPs, domains and hashes out of structured alert fields and raw logs."""
        found = {}
        for alert in alerts:
            candidates = set()
            if alert.src_ip:
                candidates.add(('ip', alert.src_ip))
            text = alert.full_log or ''
            candidates.update(('ip', ip) for ip in IP_RE.findall(text))
            candidates.update(('domain', d.lower()) for d in DOMAIN_RE.findall(text))
            candidates.update(('hash', h.lower()) for h in HASH_RE.findall(text))
            for key in candidates:
                found.setdefault(key, self.env['cg.alert'])
                found[key] |= alert
        iocs = self.env['cg.ioc']
        for (ioc_type, value), linked in found.items():
            scope = 'external'
            if ioc_type == 'ip':
                try:
                    addr = ipaddress.ip_address(value)
                except ValueError:
                    continue
                if addr.is_loopback or addr.is_unspecified:
                    continue
                # Documentation ranges (RFC 5737) are "private" for ipaddress but
                # stand in for public attackers in demo data, so only RFC 1918 is internal.
                if addr.is_private and not any(value.startswith(p) for p in ('203.0.113.', '198.51.100.', '192.0.2.')):
                    scope = 'internal'
            ioc = self.search([('value', '=', value), ('ioc_type', '=', ioc_type)], limit=1)
            dates = [d for d in linked.mapped('timestamp') if d]
            vals = {
                'alert_ids': [(4, a.id) for a in linked],
                'last_seen': max(dates) if dates else fields.Datetime.now(),
            }
            if ioc:
                ioc.write(vals)
            else:
                vals.update(value=value, ioc_type=ioc_type, scope=scope,
                            first_seen=min(dates) if dates else fields.Datetime.now())
                ioc = self.create(vals)
            iocs |= ioc
        iocs._local_assessment()
        return iocs

    @system_write
    def _local_assessment(self):
        """TI01/TI02: score an indicator from evidence already inside CyberGuard.
        No company data leaves the system."""
        rank = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        for ioc in self:
            alerts = ioc.alert_ids
            worst = max((rank.get(a.severity, 1) for a in alerts), default=0)
            score = min(100, len(alerts) * 3 + worst * 12 + len(alerts.asset_id) * 6
                        + len(alerts.mitre_technique_ids) * 5)
            if ioc.scope == 'internal':
                score = int(score * 0.5)
            reputation = ('malicious' if score >= 70 else 'suspicious' if score >= 35 else 'unknown')
            lines = [
                "Local assessment (evidence held in CyberGuard only):",
                "- Seen in %d alert(s) across %d asset(s)." % (len(alerts), len(alerts.asset_id)),
                "- Highest related alert severity: %s." % (max(alerts.mapped('severity'), key=lambda s: rank.get(s, 0)) if alerts else 'n/a'),
            ]
            if alerts.mitre_technique_ids:
                lines.append("- Associated ATT&CK techniques: %s." % ', '.join(alerts.mitre_technique_ids.mapped('code')))
            if ioc.scope == 'internal':
                lines.append("- Internal address: treat as a possibly compromised or misconfigured host, not an external attacker.")
            # Intelligence from an external source (ThreatFox, VirusTotal) outlives a local
            # re-score: local evidence can raise such a verdict but never erase it.
            external = [block for block in ioc._intel_blocks() if block.startswith(EXTERNAL_HEADERS)]
            if external:
                score = max(score, ioc.score)
                reputation = worst_reputation(reputation, ioc.reputation)
            ioc.write({'score': score, 'reputation': reputation,
                       'enrichment': '\n\n'.join(['\n'.join(lines)] + external)})

    @system_write
    def action_reassess(self):
        self._local_assessment()
        return notify_action('Indicators reassessed', '%d indicator(s) scored from local evidence.' % len(self))

    @system_write
    def action_enrich_external(self):
        """TI05: optional lookup against VirusTotal. Only the indicator value is sent,
        never log content, and only when an administrator has enabled it."""
        params = self.env['ir.config_parameter'].sudo()
        if params.get_param('cyberguard_360.ti_external_enabled') != 'True':
            raise UserError("External threat intelligence lookups are disabled. "
                            "An administrator can enable them in CyberGuard settings.")
        api_key = params.get_param('cyberguard_360.virustotal_api_key')
        if not api_key:
            raise UserError("No VirusTotal API key is configured in CyberGuard settings.")
        paths = {'ip': 'ip_addresses', 'domain': 'domains', 'hash': 'files'}
        for ioc in self:
            if ioc.ioc_type not in paths:
                continue
            if ioc.scope == 'internal':
                raise UserError("%s is an internal address and will not be sent to a third party." % ioc.value)
            try:
                response = requests.get(
                    'https://www.virustotal.com/api/v3/%s/%s' % (paths[ioc.ioc_type], ioc.value),
                    headers={'x-apikey': api_key}, timeout=20)
                response.raise_for_status()
                attributes = response.json().get('data', {}).get('attributes', {})
            except requests.RequestException as exc:
                raise UserError("VirusTotal lookup failed for %s: %s" % (ioc.value, exc)) from exc
            stats = attributes.get('last_analysis_stats', {})
            malicious, suspicious = stats.get('malicious', 0), stats.get('suspicious', 0)
            total = sum(stats.values()) or 1
            vt_score = int(min(100, (malicious * 100 + suspicious * 50) / total * 4))
            reputation = 'malicious' if malicious >= 3 else 'suspicious' if (malicious or suspicious) else 'clean'
            source = 'VirusTotal + local evidence'
            if any(block.startswith(THREATFOX_HEADER) for block in ioc._intel_blocks()):
                # a ThreatFox listing is not cleared because antivirus engines have not caught up yet
                reputation = worst_reputation(reputation, ioc.reputation)
                source = '%s + %s' % (THREATFOX_SOURCE, source)
            ioc.write({
                'score': max(ioc.score, vt_score),
                'reputation': reputation,
                'source': source,
                'enrichment': ioc._intel_with_block(
                    VIRUSTOTAL_HEADER,
                    "VirusTotal: %d malicious / %d suspicious of %d engines. Country: %s. Owner: %s." % (
                        malicious, suspicious, total, attributes.get('country', 'n/a'),
                        attributes.get('as_owner', 'n/a'))),
            })
            self.env['cg.activity.log'].log('External TI lookup', 'threat', ioc)
        return notify_action('Enrichment complete', '%d indicator(s) enriched.' % len(self))

    # ------------------------------------------------------------------ ThreatFox feed
    @api.model
    def _threatfox_datetime(self, value):
        """ThreatFox timestamps look like '2020-12-08 13:36:27 UTC'."""
        try:
            return datetime.strptime(str(value or '')[:19], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return False

    @api.model
    def normalize_threatfox_ioc(self, raw):
        """Normalize one abuse.ch ThreatFox IOC into the existing cg.ioc schema.

        ThreatFox is an external IOC feed; it is not endpoint telemetry.
        Confidence is retained as source evidence and is not treated as a detection.
        Returns False for an entry that is unsupported, malformed or internal.
        """
        if not isinstance(raw, dict):
            return False

        def text(*keys):
            # First non-empty value, on a single line: a blank line would split the notes block.
            for key in keys:
                found = ' '.join(str(raw.get(key) or '').replace('\x00', '').split())
                if found:
                    return found
            return ''

        ioc_type = THREATFOX_IOC_TYPES.get(text('ioc_type').lower())
        value = text('ioc', 'ioc_value')
        if not value or not ioc_type:
            return False
        port = ''
        if ioc_type == 'ip':
            # ThreatFox publishes "203.0.113.5:443" (or "[2001:db8::5]:443"). Alerts are
            # matched on the address, so the port is only kept as a note.
            host = value
            if value.startswith('['):
                host, _bracket, port = value[1:].partition(']')
                port = port.lstrip(':')
            elif value.count(':') == 1:
                host, port = value.split(':')
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return False
            if address.is_private or address.is_loopback or address.is_unspecified:
                return False
            value = str(address)
        elif ioc_type in ('domain', 'hash'):
            value = value.lower()  # same form as the indicators extracted from alerts
        if len(value) > MAX_IOC_LENGTH:
            return False
        try:
            confidence = max(0, min(100, int(raw.get('confidence_level') or 0)))
        except (TypeError, ValueError):
            confidence = 0
        first_seen = self._threatfox_datetime(raw.get('first_seen') or raw.get('first_seen_utc'))
        last_seen = self._threatfox_datetime(raw.get('last_seen') or raw.get('last_seen_utc')) or first_seen
        tags = raw.get('tags') if isinstance(raw.get('tags'), list) else []
        return {
            'value': value,
            'ioc_type': ioc_type,
            'confidence': confidence,
            'reputation': 'malicious' if confidence >= 75 else 'suspicious' if confidence >= 50 else 'unknown',
            'first_seen': first_seen,
            'last_seen': last_seen,
            # lists, because several feed entries can describe the same indicator
            'threatfox_ids': list(filter(None, [text('id', 'threatfox_id')])),
            'threat_types': list(filter(None, [text('threat_type')])),
            'malware': list(filter(None, [text('malware_printable', 'malware')])),
            'ports': list(filter(None, [port])),
            'tags': list(dict.fromkeys(filter(None, (' '.join(str(tag).split()) for tag in tags)))),
        }

    @api.model
    def _threatfox_merge(self, first, second):
        """Combine two feed entries describing the same indicator, e.g. one address
        that ThreatFox lists once per port."""
        best, other = (first, second) if first['confidence'] >= second['confidence'] else (second, first)
        merged = dict(best)
        for key in ('threatfox_ids', 'threat_types', 'malware', 'ports', 'tags'):
            merged[key] = best[key] + [entry for entry in other[key] if entry not in best[key]]
        merged['first_seen'] = min(filter(None, [first['first_seen'], second['first_seen']]), default=False)
        merged['last_seen'] = max(filter(None, [first['last_seen'], second['last_seen']]), default=False)
        return merged

    @api.model
    def _threatfox_block(self, item):
        """The ThreatFox block of the intelligence notes."""
        def listed(entries, limit=12):
            shown = ', '.join(entries[:limit])
            return '%s (+%d more)' % (shown, len(entries) - limit) if len(entries) > limit else shown

        lines = [
            THREATFOX_HEADER,
            'ThreatFox ID: %s' % (listed(item['threatfox_ids']) or 'n/a'),
            'Threat type: %s' % (listed(item['threat_types']) or 'Unspecified'),
            'Malware family: %s' % (listed(item['malware']) or 'Unspecified'),
            'ThreatFox confidence: %d/100' % item['confidence'],
        ]
        if item['ports']:
            lines.append('Observed port: %s' % listed(item['ports']))
        if item['tags']:
            lines.append('Tags: %s' % listed(item['tags']))
        if item['first_seen']:
            lines.append('First seen (UTC): %s' % item['first_seen'])
        if item['last_seen']:
            lines.append('Last seen (UTC): %s' % item['last_seen'])
        return '\n'.join(lines)

    def _threatfox_vals(self, item):
        """Values recording one normalized ThreatFox entry: on this indicator when it
        is already tracked, for a new indicator when ``self`` is empty."""
        block = self._threatfox_block(item)
        if not self:
            return {
                'value': item['value'],
                'ioc_type': item['ioc_type'],
                'scope': 'external',
                'reputation': item['reputation'],
                'score': item['confidence'],
                'source': THREATFOX_SOURCE,
                'enrichment': block,
                'first_seen': item['first_seen'],
                'last_seen': item['last_seen'],
            }
        self.ensure_one()
        source = self.source or ''
        return {
            # The feed adds to what is already known: it never lowers a verdict or a
            # score, and it keeps the local assessment and other sources in the notes.
            'reputation': worst_reputation(self.reputation, item['reputation']),
            'score': max(self.score, item['confidence']),
            'source': source if THREATFOX_SOURCE in source else ' + '.join(filter(None, [THREATFOX_SOURCE, source])),
            'enrichment': self._intel_with_block(THREATFOX_HEADER, block),
            'first_seen': min(filter(None, [self.first_seen, item['first_seen']]), default=False),
            'last_seen': max(filter(None, [self.last_seen, item['last_seen']]), default=False),
        }

    @system_write
    def action_import_threatfox(self):
        """Import the latest three days of public ThreatFox IOCs into cg.ioc.

        Existing records are updated by (value, ioc_type); no alert or asset is
        fabricated. ThreatFox metadata is recorded in the intelligence notes.
        Only the Auth-Key is sent to ThreatFox: no company data leaves the system.
        """
        params = self.env['ir.config_parameter'].sudo()
        if params.get_param('cyberguard_360.ti_external_enabled') != 'True':
            raise UserError("External threat intelligence lookups are disabled. "
                            "An administrator can enable them in CyberGuard settings.")
        api_key = (params.get_param('cyberguard_360.threatfox_api_key') or '').strip()
        if not api_key:
            raise UserError("No abuse.ch ThreatFox Auth-Key is configured in CyberGuard settings. "
                            "ThreatFox requires one for every request; it is free at https://auth.abuse.ch/")
        try:
            response = requests.post(
                THREATFOX_URL, json={'query': 'get_iocs', 'days': THREATFOX_DAYS},
                headers={'Auth-Key': api_key}, timeout=(10, 60))
        except requests.RequestException as exc:
            raise UserError("ThreatFox request failed: %s" % exc) from exc
        if response.status_code in (401, 403):
            raise UserError("ThreatFox rejected the Auth-Key (HTTP %d). "
                            "Check the key in CyberGuard settings." % response.status_code)
        try:
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise UserError("ThreatFox request failed: %s" % exc) from exc
        if not isinstance(payload, dict):
            payload = {}
        status, rows = payload.get('query_status'), payload.get('data')
        if status == 'no_result':
            return notify_action('ThreatFox import',
                                 'ThreatFox returned no IOCs for the last %d days.' % THREATFOX_DAYS, 'info')
        if status != 'ok' or not isinstance(rows, list):
            reason = status or 'unknown status'
            if rows and isinstance(rows, str):
                reason = '%s (%s)' % (reason, rows[:200])
            raise UserError("ThreatFox returned an unsuccessful response: %s" % reason)

        # One entry per indicator: ThreatFox lists an address once per port.
        feed, skipped = {}, 0
        for raw in rows:
            item = self.normalize_threatfox_ioc(raw)
            if not item:
                skipped += 1
                continue
            key = (item['value'], item['ioc_type'])
            feed[key] = self._threatfox_merge(feed[key], item) if key in feed else item

        ioc_model = self.env['cg.ioc']
        tracked = {}
        for values in split_every(1000, {value for value, _ioc_type in feed}):
            for ioc in ioc_model.search([('value', 'in', list(values))]):
                tracked[(ioc.value, ioc.ioc_type)] = ioc
        new_vals, updated, unchanged = [], 0, 0
        for key, item in feed.items():
            ioc = tracked.get(key, ioc_model)
            vals = ioc._threatfox_vals(item)
            if not ioc:
                new_vals.append(vals)
                continue
            changes = {name: new for name, new in vals.items() if ioc[name] != new}
            if changes:
                ioc.write(changes)
                updated += 1
            else:
                unchanged += 1
        # A feed brings thousands of records: no follower and no "created" message for each.
        for batch in split_every(500, new_vals):
            ioc_model.with_context(tracking_disable=True).create(list(batch))

        summary = '%d new, %d updated, %d unchanged, %d skipped (unsupported type or internal address).' % (
            len(new_vals), updated, unchanged, skipped)
        _logger.info("ThreatFox import: %s", summary)
        self.env['cg.activity.log'].log('ThreatFox IOC import', 'threat', False, summary)
        # act_window_close makes the list reload, so the imported indicators show up at once
        return notify_action('ThreatFox import complete', summary,
                             next_action={'type': 'ir.actions.act_window_close'})

    def action_view_alerts(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Alerts for %s' % self.value,
            'res_model': 'cg.alert',
            'view_mode': 'list,form',
            'domain': [('id', 'in', self.alert_ids.ids)],
        }

    def action_threat_report(self):
        """TI06/TI08: investigate everything known about this indicator."""
        self.ensure_one()
        if not self.alert_ids:
            raise UserError("There are no alerts linked to this indicator to investigate.")
        analysis = self.env['cg.ai.analysis'].create_from_alerts(
            self.alert_ids, 'threat', title='Threat investigation: %s' % self.value)
        return analysis.action_open()
