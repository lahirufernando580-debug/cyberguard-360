"""Sample data and the Wazuh demo simulator.

Everything here is fictional. Attacker addresses use the RFC 5737 documentation
ranges (203.0.113.0/24, 198.51.100.0/24) so they can never point at a real host.
"""
import random
import uuid
from collections import Counter
from datetime import timedelta

from odoo import api, fields, models

from .common import system_write

# key: (rule_id, level, description, groups, mitre, decoder, location, log template)
T = {
    'ssh_invalid': ('5710', 5, 'sshd: Attempt to login using a non-existent user', 'syslog, sshd, authentication_failed', ['T1110'], 'sshd', '/var/log/auth.log',
                    'sshd[2241]: Invalid user {user} from {src} port 51522 ssh2'),
    'ssh_fail': ('5716', 5, 'sshd: authentication failed', 'syslog, sshd, authentication_failed', ['T1110'], 'sshd', '/var/log/auth.log',
                 'sshd[2241]: Failed password for {user} from {src} port 40112 ssh2'),
    'ssh_brute': ('5712', 10, 'sshd: brute force trying to get access to the system', 'syslog, sshd, authentication_failures', ['T1110'], 'sshd', '/var/log/auth.log',
                  'sshd[2241]: Failed password for invalid user {user} from {src} port 40290 ssh2 (repeated 12 times)'),
    'ssh_success': ('5715', 3, 'sshd: authentication success', 'syslog, sshd, authentication_success', ['T1078'], 'sshd', '/var/log/auth.log',
                    'sshd[2290]: Accepted password for {user} from {src} port 40377 ssh2'),
    'ssh_fail_success': ('40112', 12, 'Multiple authentication failures followed by a success', 'syslog, attack, authentication_success', ['T1110', 'T1078'], 'sshd', '/var/log/auth.log',
                         'sshd[2290]: Accepted password for {user} from {src} port 40377 ssh2 after 38 failures'),
    'sudo_root': ('5402', 8, 'Successful sudo to ROOT executed', 'syslog, sudo', ['T1548'], 'sudo', '/var/log/auth.log',
                  'sudo: {user} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash'),
    'user_added': ('5902', 8, 'New user added to the system', 'syslog, adduser', ['T1136'], 'useradd', '/var/log/auth.log',
                   'useradd[2410]: new user: name=svc_backup2, UID=1004, GID=1004, home=/home/svc_backup2, shell=/bin/bash'),
    'fim_passwd': ('550', 7, 'Integrity checksum changed', 'ossec, syscheck', ['T1565'], 'syscheck_integrity_changed', 'syscheck',
                   "File '/etc/passwd' modified. Mode: realtime. Changed attributes: size,mtime,md5,sha1,sha256"),
    'sqli': ('31103', 7, 'SQL injection attempt', 'web, accesslog, attack, sql_injection', ['T1190'], 'web-accesslog', '/var/log/nginx/access.log',
             '{src} - - "GET /portal/search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 403 512'),
    'web_200': ('31106', 12, 'A web attack returned code 200 (success)', 'web, accesslog, attack', ['T1190'], 'web-accesslog', '/var/log/nginx/access.log',
                '{src} - - "GET /portal/export?id=1%20OR%201=1 HTTP/1.1" 200 48211'),
    'web_400': ('31151', 10, 'Multiple web server 400 error codes from same source ip', 'web, accesslog, web_scan, recon', ['T1595'], 'web-accesslog', '/var/log/nginx/access.log',
                '{src} - - "GET /.env HTTP/1.1" 404 153'),
    'vt_malware': ('87105', 12, 'VirusTotal: Alert - 46 engines detected this file', 'virustotal, malware', ['T1204'], 'json', 'virustotal',
                   'C:\\Users\\{user}\\Downloads\\Invoice_Q3.exe sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 detected: Trojan.GenericKD'),
    'malware_drop': ('92213', 15, 'Executable file dropped in folder commonly used by malware', 'sysmon, malware, windows', ['T1105'], 'windows_eventchannel', 'EventChannel',
                     'Sysmon EventID 11: C:\\Users\\{user}\\AppData\\Local\\Temp\\svch0st.exe created by WINWORD.EXE'),
    'macro': ('100210', 10, 'Suspicious attachment with macro opened (possible phishing)', 'windows, phishing, office', ['T1566'], 'windows_eventchannel', 'EventChannel',
              'WINWORD.EXE spawned powershell.exe -enc JABzAD0A from Invoice_Q3.docm received from billing@secure-invoice-portal.xyz'),
    'portscan': ('40601', 8, 'Network scan from same source ip (port scan)', 'firewall, recon, portscan', ['T1046'], 'iptables', '/var/log/firewall.log',
                 'DROP IN=wan0 SRC={src} DST={dst} PROTO=TCP DPT=3389 SYN (42 ports in 10s)'),
    'win_fail': ('60122', 5, 'Logon failure - unknown user or bad password', 'windows, authentication_failed', ['T1110'], 'windows_eventchannel', 'EventChannel',
                 'EventID 4625: An account failed to log on. Account: {user} Source Network Address: {src}'),
    'win_multi_fail': ('60204', 10, 'Multiple Windows logon failures', 'windows, authentication_failures', ['T1110'], 'windows_eventchannel', 'EventChannel',
                       'EventID 4625 repeated 14 times for account {user} from {src}'),
    'exfil': ('100300', 13, 'Unusual outbound data transfer volume detected', 'network, exfiltration', ['T1041'], 'json', 'netflow',
              'Outbound 4.2 GB from {dst} to {src}:443 in 11 minutes (baseline 60 MB/h)'),
    'pg_fail': ('100310', 9, 'PostgreSQL: multiple authentication failures', 'postgresql, authentication_failures', ['T1110'], 'postgresql', '/var/log/postgresql/postgresql.log',
                'FATAL: password authentication failed for user "{user}" (client {src})'),
    'log_clear': ('63103', 12, 'Windows audit log was cleared', 'windows, log_clearing', ['T1070'], 'windows_eventchannel', 'EventChannel',
                  'EventID 1102: The audit log was cleared by {user}'),
    # background noise
    'pam_open': ('5501', 3, 'PAM: Login session opened', 'pam, syslog, authentication_success', [], 'pam', '/var/log/auth.log',
                 'pam_unix(cron:session): session opened for user root'),
    'dpkg': ('2902', 7, 'New dpkg (Debian Package) installed', 'syslog, dpkg, config_changed', [], 'dpkg-decoder', '/var/log/dpkg.log',
             'status installed libssl3:amd64 3.0.2-0ubuntu1.18'),
    'ports': ('533', 7, 'Listened ports status (netstat) changed (new port opened or closed)', 'ossec', [], 'ossec', 'netstat listening ports',
              'tcp 0.0.0.0:8443 added'),
    'sca': ('19007', 7, 'CIS benchmark check failed: Ensure password expiration is 365 days or less', 'sca', [], 'sca', 'sca',
            'Policy cis_ubuntu22-04 check 28647 failed'),
    'agent_start': ('503', 3, 'Wazuh agent started', 'ossec', [], 'ossec', 'wazuh-agent', 'Agent started'),
    'win_logon': ('60106', 3, 'Windows logon success', 'windows, authentication_success', ['T1078'], 'windows_eventchannel', 'EventChannel',
                  'EventID 4624: An account was successfully logged on. Account: {user}'),
    'fim_web': ('554', 5, 'File added to the system', 'ossec, syscheck', [], 'syscheck_new_entry', 'syscheck',
                "File '/var/www/portal/uploads/report-{n}.pdf' added"),
}

ATTACKER_SSH = '203.0.113.45'
ATTACKER_WEB = '198.51.100.23'
ATTACKER_SCAN = '198.51.100.77'
EXFIL_DEST = '203.0.113.99'


class CgDemo(models.AbstractModel):
    _name = 'cg.demo'
    _description = 'CyberGuard Demo Data'

    # ------------------------------------------------------------------ helpers
    def _alert_vals(self, key, asset, when, src='', user='', state='new', dst=None):
        rule_id, level, name, groups, mitre, decoder, location, log = T[key]
        techniques = self.env['cg.mitre.technique'].search([('code', 'in', mitre)])
        return {
            'name': name,
            'wazuh_id': 'demo-%s' % uuid.uuid4().hex[:20],
            'timestamp': when,
            'rule_id': rule_id,
            'rule_level': level,
            'rule_groups': groups,
            'agent_id': asset.wazuh_agent_id or False,
            'agent_name': asset.hostname or asset.name,
            'asset_id': asset.id,
            'src_ip': src or False,
            'dst_ip': dst or asset.ip_address,
            'dst_user': user or False,
            'decoder': decoder,
            'location': location,
            'full_log': log.format(src=src, dst=asset.ip_address or '', user=user or 'root',
                                   n=random.randint(100, 999)),
            'mitre_technique_ids': [(6, 0, techniques.ids)],
            'state': state,
        }

    # ------------------------------------------------------------------ install-time data
    @api.model
    @system_write
    def load(self):
        if self.env['cg.asset'].with_context(active_test=False).search_count([]):
            return False
        random.seed(360)
        self = self.with_context(cg_demo=True, tracking_disable=True, mail_create_nolog=True,
                                 mail_notrack=True, no_reset_password=True)
        env = self.env
        now = fields.Datetime.now().replace(microsecond=0)

        # ---- people (no passwords are set; an administrator assigns them)
        def user(name, login, group):
            existing = env['res.users'].with_context(active_test=False).search([('login', '=', login)], limit=1)
            return existing or env['res.users'].create({
                'name': name, 'login': login, 'email': login,
                'group_ids': [(6, 0, [env.ref(group).id])],
            })
        analyst = user('Aisha Rahman', 'aisha.rahman@cyberguard.example', 'cyberguard_360.group_cg_analyst')
        manager = user('Daniel Okoye', 'daniel.okoye@cyberguard.example', 'cyberguard_360.group_cg_manager')
        employee = user('Mia Chen', 'mia.chen@cyberguard.example', 'cyberguard_360.group_cg_employee')
        admin = env.ref('base.user_admin')

        # ---- assets
        cat = {c.code: c.id for c in env['cg.asset.category'].search([])}
        rows = [
            # name, type, cat, ip, os, facing, crit, agent, agent status, dept, owner, location
            ('WEB-PROD-01', 'server', 'SRV', '10.0.1.10', 'Ubuntu 22.04 LTS', True, 'critical', '001', 'active', 'IT', admin, 'DC Rack A'),
            ('DB-PROD-01', 'server', 'SRV', '10.0.1.20', 'Ubuntu 22.04 LTS / PostgreSQL 15', False, 'critical', '002', 'active', 'IT', admin, 'DC Rack A'),
            ('DC-01', 'server', 'SRV', '10.0.1.5', 'Windows Server 2022', False, 'critical', '003', 'active', 'IT', admin, 'DC Rack B'),
            ('MAIL-GW-01', 'server', 'SRV', '10.0.1.30', 'Debian 12', True, 'high', '004', 'active', 'IT', analyst, 'DC Rack B'),
            ('FILE-SRV-01', 'server', 'SRV', '10.0.1.40', 'Windows Server 2019', False, 'high', '005', 'active', 'Operations', analyst, 'DC Rack B'),
            ('FW-EDGE-01', 'network', 'NET', '10.0.0.1', 'FortiOS 7.2', True, 'critical', '006', 'active', 'IT', admin, 'Network Room'),
            ('SW-CORE-01', 'network', 'NET', '10.0.0.2', 'Cisco IOS XE 17', False, 'medium', False, 'none', 'IT', admin, 'Network Room'),
            ('FIN-LT-014', 'endpoint', 'EP', '10.0.3.14', 'Windows 11 Pro', False, 'high', '007', 'active', 'Finance', employee, 'HQ Floor 2'),
            ('HR-LT-007', 'endpoint', 'EP', '10.0.3.44', 'Windows 11 Pro', False, 'medium', '008', 'disconnected', 'HR', employee, 'HQ Floor 2'),
            ('DEV-WS-022', 'endpoint', 'EP', '10.0.4.22', 'Ubuntu 24.04 LTS', False, 'low', '009', 'active', 'Engineering', analyst, 'HQ Floor 3'),
            ('BACKUP-NAS-01', 'server', 'SRV', '10.0.1.60', 'TrueNAS SCALE', False, 'high', '010', 'never_connected', 'IT', admin, 'DC Rack C'),
            ('TEST-VM-03', 'server', 'SRV', '10.0.9.3', 'Windows Server 2008 R2', False, 'low', '011', 'active', 'Engineering', analyst, 'Isolated lab VLAN'),
            ('CRM-CLOUD', 'cloud', 'CLD', '', 'SaaS (vendor hosted)', True, 'high', False, 'none', 'Sales', manager, 'eu-west-1'),
            ('CCTV-NVR-01', 'iot', 'IOT', '10.0.8.10', 'Embedded Linux', False, 'low', False, 'none', 'Facilities', manager, 'Security Office'),
        ]
        assets = {}
        for name, atype, code, ip, os_name, facing, crit, agent, agent_status, dept, owner, location in rows:
            assets[name] = env['cg.asset'].create({
                'name': name, 'hostname': name.lower(), 'asset_type': atype, 'category_id': cat.get(code),
                'ip_address': ip, 'operating_system': os_name, 'internet_facing': facing, 'criticality': crit,
                'wazuh_agent_id': agent, 'agent_status': agent_status, 'department': dept, 'owner_id': owner.id,
                'location': location, 'agent_version': 'Wazuh v4.9.2' if agent else False,
                'agent_last_keepalive': now - timedelta(minutes=random.randint(0, 3)) if agent_status == 'active'
                else now - timedelta(days=2, hours=5) if agent_status == 'disconnected' else False,
                'status': 'active',
            })
        web, db, dc, fin, fw = (assets[k] for k in ('WEB-PROD-01', 'DB-PROD-01', 'DC-01', 'FIN-LT-014', 'FW-EDGE-01'))

        # ---- alerts
        vals = []
        # Background noise over 14 days, slowly rising
        noisy = [assets[k] for k in ('WEB-PROD-01', 'DB-PROD-01', 'DC-01', 'MAIL-GW-01', 'FILE-SRV-01',
                                     'FIN-LT-014', 'DEV-WS-022', 'TEST-VM-03')]
        for day in range(13, -1, -1):
            for _i in range(random.randint(5, 8) + (13 - day) // 3):
                asset = random.choice(noisy)
                windows = 'Windows' in (asset.operating_system or '')
                key = random.choice(['win_logon', 'agent_start', 'ports', 'win_fail'] if windows
                                    else ['pam_open', 'dpkg', 'ports', 'sca', 'agent_start', 'fim_web'])
                when = now - timedelta(days=day, hours=random.randint(0, 22), minutes=random.randint(0, 59))
                if when > now:
                    when = now - timedelta(minutes=random.randint(5, 240))
                vals.append(self._alert_vals(key, asset, when, user='jsmith' if windows else 'root',
                                             src='10.0.3.%d' % random.randint(10, 60) if key == 'win_fail' else '',
                                             state='resolved' if day > 2 else random.choice(['new', 'acknowledged', 'resolved'])))
        # Recurring port scans against the edge firewall
        for day in (9, 6, 4, 2, 1, 0):
            for i in range(random.randint(1, 3)):
                vals.append(self._alert_vals('portscan', fw, now - timedelta(days=day, hours=2 + i, minutes=random.randint(0, 50)),
                                             src=ATTACKER_SCAN, state='acknowledged' if day > 1 else 'new'))
        # E. Internal logon failures against the domain controller (3 days ago)
        base = now - timedelta(days=3, hours=4)
        for i in range(14):
            vals.append(self._alert_vals('win_fail', dc, base + timedelta(minutes=i * 2), src='10.0.3.44', user='administrator', state='acknowledged'))
        e_alerts_at = len(vals)
        vals.append(self._alert_vals('win_multi_fail', dc, base + timedelta(minutes=30), src='10.0.3.44', user='administrator', state='new'))
        # C. Phishing leading to malware on the finance laptop (2 days ago)
        base = now - timedelta(days=2, hours=3)
        c_start = len(vals)
        vals.append(self._alert_vals('macro', fin, base, user='mchen', state='investigating'))
        vals.append(self._alert_vals('malware_drop', fin, base + timedelta(minutes=1), user='mchen', state='investigating'))
        vals.append(self._alert_vals('vt_malware', fin, base + timedelta(minutes=3), user='mchen', state='investigating'))
        c_end = len(vals)
        # B. SQL injection against the customer portal (yesterday)
        base = now - timedelta(hours=27)
        b_start = len(vals)
        for i in range(12):
            vals.append(self._alert_vals('sqli', web, base + timedelta(minutes=i * 3), src=ATTACKER_WEB))
        vals.append(self._alert_vals('web_400', web, base + timedelta(minutes=20), src=ATTACKER_WEB))
        vals.append(self._alert_vals('web_200', web, base + timedelta(minutes=38), src=ATTACKER_WEB))
        b_end = len(vals)
        # A. SSH brute force, then a successful login and persistence (last hours)
        base = now - timedelta(hours=3, minutes=20)
        a_start = len(vals)
        users = ['admin', 'root', 'oracle', 'test', 'deploy', 'ubuntu', 'postgres', 'git']
        for i in range(26):
            vals.append(self._alert_vals('ssh_invalid' if i % 3 else 'ssh_fail', web, base + timedelta(seconds=i * 55),
                                         src=ATTACKER_SSH, user=users[i % len(users)]))
        for i in range(3):
            vals.append(self._alert_vals('ssh_brute', web, base + timedelta(minutes=8 + i * 7), src=ATTACKER_SSH, user='deploy'))
        vals.append(self._alert_vals('ssh_success', web, base + timedelta(minutes=27), src=ATTACKER_SSH, user='deploy'))
        vals.append(self._alert_vals('ssh_fail_success', web, base + timedelta(minutes=27, seconds=2), src=ATTACKER_SSH, user='deploy'))
        vals.append(self._alert_vals('sudo_root', web, base + timedelta(minutes=31), src=ATTACKER_SSH, user='deploy'))
        vals.append(self._alert_vals('user_added', web, base + timedelta(minutes=34), user='root'))
        vals.append(self._alert_vals('fim_passwd', web, base + timedelta(minutes=34, seconds=5), user='root'))
        a_end = len(vals)
        # F. Possible exfiltration from the database server (last hour)
        f_start = len(vals)
        vals.append(self._alert_vals('pg_fail', db, now - timedelta(minutes=95), src='10.0.1.10', user='app_readonly'))
        vals.append(self._alert_vals('exfil', db, now - timedelta(minutes=52), src=EXFIL_DEST, dst=db.ip_address))
        f_end = len(vals)
        vals.append(self._alert_vals('log_clear', assets['FILE-SRV-01'], now - timedelta(days=5, hours=2), user='svc_admin', state='resolved'))

        alerts = env['cg.alert'].create(vals)
        since = now - timedelta(hours=24)
        counts = Counter(a.group_key for a in alerts if a.timestamp >= since)
        for alert in alerts:
            if counts.get(alert.group_key, 0) > 1:
                alert.repeat_count = counts[alert.group_key]
        scenario = {
            'A': alerts[a_start:a_end], 'B': alerts[b_start:b_end], 'C': alerts[c_start:c_end],
            'E': alerts[e_alerts_at - 14:e_alerts_at + 1], 'F': alerts[f_start:f_end],
        }
        env['cg.ioc'].extract_from_alerts(alerts.filtered(lambda a: a.rule_level >= 5))

        # ---- vulnerabilities (real CVE identifiers and CVSS base scores)
        today = fields.Date.context_today(self)
        vulns = [
            # cve, title, cvss, exploited, package, version, fixed, assets, state, detected days ago
            ('CVE-2021-44228', 'Apache Log4j2 JNDI remote code execution (Log4Shell)', 10.0, True, 'log4j-core', '2.14.1', '2.17.1', ['WEB-PROD-01', 'CRM-CLOUD'], 'in_progress', 12),
            ('CVE-2024-21762', 'FortiOS SSL VPN out-of-bounds write allows remote code execution', 9.8, True, 'FortiOS', '7.2.5', '7.2.7', ['FW-EDGE-01'], 'open', 9),
            ('CVE-2024-6387', 'OpenSSH server signal handler race condition (regreSSHion)', 8.1, False, 'openssh-server', '8.9p1', '9.8p1', ['WEB-PROD-01', 'DEV-WS-022', 'MAIL-GW-01'], 'open', 6),
            ('CVE-2023-44487', 'HTTP/2 Rapid Reset denial of service', 7.5, True, 'nginx', '1.18.0', '1.25.3', ['WEB-PROD-01'], 'open', 20),
            ('CVE-2022-22965', 'Spring Framework remote code execution (Spring4Shell)', 9.8, True, 'spring-webmvc', '5.3.17', '5.3.18', ['CRM-CLOUD'], 'open', 15),
            ('CVE-2021-34527', 'Windows Print Spooler remote code execution (PrintNightmare)', 8.8, True, 'Windows Print Spooler', '', 'KB5004945', ['FILE-SRV-01', 'DC-01'], 'in_progress', 25),
            ('CVE-2023-23397', 'Microsoft Outlook elevation of privilege via crafted message', 9.8, True, 'Microsoft Outlook', '16.0.15601', '16.0.16130', ['FIN-LT-014', 'HR-LT-007'], 'open', 40),
            ('CVE-2023-38831', 'WinRAR code execution when opening crafted archive', 7.8, True, 'WinRAR', '6.21', '6.23', ['FIN-LT-014'], 'open', 18),
            ('CVE-2022-0847', 'Linux kernel pipe buffer privilege escalation (Dirty Pipe)', 7.8, True, 'linux-kernel', '5.15.0-25', '5.15.0-27', ['BACKUP-NAS-01'], 'open', 35),
            ('CVE-2019-0708', 'Remote Desktop Services remote code execution (BlueKeep)', 9.8, True, 'Remote Desktop Services', '', 'KB4499175', ['TEST-VM-03'], 'accepted', 60),
            ('CVE-2024-3094', 'Malicious code in xz/liblzma upstream tarballs', 10.0, False, 'xz-utils', '5.6.0', '5.6.2', ['DEV-WS-022'], 'patched', 30),
            ('CVE-2020-1472', 'Netlogon elevation of privilege (Zerologon)', 10.0, True, 'Windows Netlogon', '', 'KB4571694', ['DC-01'], 'patched', 45),
            ('CVE-2023-4863', 'Heap buffer overflow in libwebp', 8.8, True, 'Google Chrome', '116.0.5845.140', '116.0.5845.187', ['FIN-LT-014', 'HR-LT-007', 'DEV-WS-022'], 'patched', 50),
            ('CVE-2023-48795', 'SSH prefix truncation attack (Terrapin)', 5.9, False, 'openssh-server', '8.9p1', '9.6p1', ['DB-PROD-01', 'MAIL-GW-01'], 'open', 14),
            ('CVE-2023-5868', 'PostgreSQL memory disclosure in aggregate function calls', 4.3, False, 'postgresql-15', '15.4', '15.5', ['DB-PROD-01'], 'open', 10),
        ]
        vuln_records = {}
        for cve, title, cvss, exploited, package, version, fixed, names, state, age in vulns:
            record = env['cg.vulnerability'].create({
                'cve_id': cve, 'name': title, 'cvss_score': cvss, 'exploited': exploited,
                'description': title + '.', 'package_name': package, 'package_version': version,
                'fixed_version': fixed, 'asset_ids': [(6, 0, [assets[n].id for n in names])],
                'state': state, 'source': 'wazuh' if 'CLOUD' not in names[0] else 'manual',
                'detected_date': today - timedelta(days=age),
                'resolved_date': today - timedelta(days=random.randint(1, 8)) if state == 'patched' else False,
                'assigned_to': random.choice([analyst.id, admin.id]),
                'references': 'https://nvd.nist.gov/vuln/detail/%s' % cve,
            })
            record.patch_recommendation = record._build_patch_recommendation()
            vuln_records[cve] = record

        # ---- risks
        def risk(name, threat, weakness, category, likelihood, impact, state, owner, asset_names=(), cves=(), **kw):
            return env['cg.risk'].create(dict({
                'name': name, 'threat': threat, 'weakness': weakness, 'category': category,
                'likelihood': str(likelihood), 'impact': str(impact), 'state': state, 'owner_id': owner.id,
                'asset_ids': [(6, 0, [assets[n].id for n in asset_names])],
                'vulnerability_ids': [(6, 0, [vuln_records[c].id for c in cves])],
            }, **kw))
        risk('Compromise of the public web server through unpatched software',
             'An external attacker exploits a known vulnerability to run code on the customer portal.',
             'Internet-facing server running Log4j and nginx versions with known exploited vulnerabilities.',
             'technical', 5, 5, 'treating', admin, ['WEB-PROD-01'], ['CVE-2021-44228', 'CVE-2023-44487', 'CVE-2024-6387'],
             treatment='mitigate', mitigation_plan='Emergency patch window approved. WAF virtual patch applied in the interim.',
             controls='WAF virtual patching\nRestrict SSH to VPN\nWeekly patch cycle', control_effectiveness='partial',
             residual_likelihood='4', residual_impact='5', due_date=today + timedelta(days=5))
        risk('Edge firewall VPN exploited for network access',
             'An attacker exploits the SSL VPN vulnerability to enter the internal network.',
             'FortiOS version affected by an actively exploited remote code execution flaw.',
             'technical', 4, 5, 'assessed', admin, ['FW-EDGE-01'], ['CVE-2024-21762'], due_date=today + timedelta(days=3))
        risk('Ransomware outbreak started by a phishing email',
             'Staff open a malicious attachment that encrypts shared files.',
             'Macros are not blocked and endpoints lack application control.',
             'human', 4, 5, 'treating', manager, ['FIN-LT-014', 'HR-LT-007', 'FILE-SRV-01'], ['CVE-2023-23397', 'CVE-2023-38831'],
             mitigation_plan='Block Office macros from the internet, run phishing simulation, verify offline backups.',
             controls='Macro blocking policy\nEmail attachment sandboxing\nQuarterly phishing training',
             control_effectiveness='substantial', residual_likelihood='2', residual_impact='5',
             due_date=today - timedelta(days=4))
        risk('Loss of confidentiality of the customer database',
             'Customer records are copied out of the production database.',
             'Application account has broader read access than needed; no egress monitoring.',
             'technical', 3, 5, 'assessed', admin, ['DB-PROD-01'], ['CVE-2023-5868'])
        risk('Weak passwords on administrative accounts',
             'Attackers guess or reuse leaked passwords to gain administrative access.',
             'No multi-factor authentication on SSH and domain administrator accounts.',
             'human', 4, 4, 'treating', admin, ['WEB-PROD-01', 'DC-01'],
             mitigation_plan='Roll out MFA to all administrative access by end of month.',
             controls='MFA on VPN\nPassword manager rollout', control_effectiveness='substantial',
             residual_likelihood='2', residual_impact='4', due_date=today + timedelta(days=12))
        risk('Unmonitored endpoints leave attacks undetected',
             'Malicious activity on endpoints without a reporting agent is never seen.',
             'Wazuh agents are disconnected or were never enrolled on some systems.',
             'operational', 4, 3, 'identified', analyst, ['HR-LT-007', 'BACKUP-NAS-01'])
        risk('Backup storage is unpatched and unmonitored',
             'An attacker destroys or encrypts backups before deploying ransomware.',
             'NAS kernel is vulnerable and its agent never connected.',
             'technical', 3, 4, 'assessed', admin, ['BACKUP-NAS-01'], ['CVE-2022-0847'])
        risk('CRM provider outage or breach', 'The SaaS CRM vendor suffers an outage or data breach.',
             'Single provider with no contractual breach-notification window.', 'third_party', 2, 4,
             'monitoring', manager, ['CRM-CLOUD'], ['CVE-2022-22965'], treatment='transfer',
             controls='Cyber insurance policy\nVendor security questionnaire', control_effectiveness='partial',
             residual_likelihood='2', residual_impact='3')
        risk('Legacy test VM runs an unsupported operating system',
             'The test machine is compromised through a legacy remote desktop flaw.',
             'Windows Server 2008 R2 no longer receives security updates.', 'technical', 3, 1,
             'monitoring', analyst, ['TEST-VM-03'], ['CVE-2019-0708'], treatment='accept',
             controls='Isolated lab VLAN with no route to production', control_effectiveness='substantial',
             residual_likelihood='1', residual_impact='1')
        risk('Staff are unaware of current phishing techniques', 'Employees disclose credentials to a fake login page.',
             'Security awareness training was last delivered over a year ago.', 'human', 3, 3,
             'closed', manager, treatment='mitigate', controls='Annual awareness training completed',
             control_effectiveness='full', residual_likelihood='1', residual_impact='2')
        risk('Default credentials on the CCTV recorder', 'An insider or visitor views or deletes camera footage.',
             'Vendor default administrator password was still in use.', 'physical', 2, 2,
             'closed', manager, ['CCTV-NVR-01'], controls='Password changed and admin interface restricted',
             control_effectiveness='full', residual_likelihood='1', residual_impact='1')

        # ---- incidents
        def incident(name, category, severity, stage, detected, alerts_, asset_names, analyst_user=analyst, **kw):
            record = env['cg.incident'].create(dict({
                'name': name, 'category': category, 'severity': severity, 'detected_date': detected,
                'analyst_id': analyst_user.id if analyst_user else False, 'reporter_id': analyst.id,
                'asset_ids': [(6, 0, [assets[n].id for n in asset_names])],
            }, **kw))
            alerts_.write({'incident_id': record.id})
            if stage != 'new':
                record.with_context(cg_demo=True).write(dict(
                    {'stage': stage},
                    **({'contained_date': detected + timedelta(hours=5)} if stage in ('contained', 'eradicated', 'closed') else {}),
                    **({'closed_date': detected + timedelta(days=1, hours=3)} if stage == 'closed' else {})))
            return record
        note = env['cg.incident.note']
        inc_a = incident('SSH brute force followed by successful login on WEB-PROD-01', 'brute_force', 'critical',
                         'investigating', scenario['A'][0].timestamp, scenario['A'], ['WEB-PROD-01'],
                         description='Repeated SSH login failures from one external address ended in a successful '
                                     'login to the deploy account, followed by sudo to root and a new local user.')
        note.create([
            {'incident_id': inc_a.id, 'author_id': analyst.id, 'note_type': 'finding', 'date': now - timedelta(hours=2, minutes=20),
             'content': 'Confirmed with the DevOps lead: nobody on the team logged in as deploy from 203.0.113.45.'},
            {'incident_id': inc_a.id, 'author_id': analyst.id, 'note_type': 'action', 'date': now - timedelta(hours=1, minutes=50),
             'content': 'Requested firewall block for 203.0.113.45 and locked the deploy account.'},
            {'incident_id': inc_a.id, 'author_id': admin.id, 'note_type': 'evidence', 'date': now - timedelta(hours=1, minutes=10),
             'content': 'Exported /var/log/auth.log and bash history of deploy for the affected window.'},
        ])
        incident('Unusual outbound data transfer from DB-PROD-01', 'data_breach', 'critical', 'new',
                 scenario['F'][-1].timestamp, scenario['F'], ['DB-PROD-01'], analyst_user=None,
                 description='4.2 GB left the database server towards an unknown external address in 11 minutes.')
        incident('SQL injection attempts against the customer portal', 'web_attack', 'high', 'triage',
                 scenario['B'][0].timestamp, scenario['B'], ['WEB-PROD-01'],
                 description='A single external address sent SQL injection payloads; one request returned HTTP 200.')
        inc_c = incident('Malware dropped on finance laptop after phishing attachment', 'malware', 'high', 'contained',
                         scenario['C'][0].timestamp, scenario['C'], ['FIN-LT-014'],
                         description='A macro-enabled invoice spawned PowerShell and dropped an executable detected by 46 engines.')
        note.create({'incident_id': inc_c.id, 'author_id': analyst.id, 'note_type': 'action',
                     'date': scenario['C'][0].timestamp + timedelta(hours=4),
                     'content': 'Laptop isolated from the network. User credentials reset.'})
        incident('Repeated logon failures against the domain controller', 'unauthorized_access', 'medium', 'new',
                 scenario['E'][0].timestamp, scenario['E'], ['DC-01', 'HR-LT-007'], analyst_user=None,
                 description='An internal workstation generated repeated administrator logon failures.')
        incident('Phishing campaign targeting the finance team', 'phishing', 'medium', 'closed',
                 now - timedelta(days=9), env['cg.alert'], ['MAIL-GW-01'],
                 description='Six staff received invoice-themed phishing emails.',
                 root_cause='Sender domain was newly registered and passed basic filtering.',
                 resolution='Messages purged from all mailboxes, sender domain blocked, two passwords reset.',
                 lessons_learned='Add a newly-registered-domain rule on the mail gateway.')

        # ---- response actions
        response = env['cg.response.action']
        response.create({'name': 'Block %s' % ATTACKER_SSH, 'action_type': 'block_ip', 'target': ATTACKER_SSH,
                         'asset_id': fw.id, 'incident_id': inc_a.id, 'alert_id': scenario['A'][-5].id,
                         'reason': 'Source of the SSH brute force and the suspicious successful login.',
                         'requested_by': analyst.id})
        response.create({'name': 'Block %s' % ATTACKER_WEB, 'action_type': 'block_ip', 'target': ATTACKER_WEB,
                         'asset_id': fw.id, 'reason': 'Source of SQL injection attempts.', 'state': 'approved',
                         'requested_by': analyst.id, 'approved_by': manager.id})
        response.create({'name': 'Isolate Host: FIN-LT-014', 'action_type': 'isolate_host', 'target': 'FIN-LT-014',
                         'asset_id': fin.id, 'incident_id': inc_c.id, 'reason': 'Malware confirmed on the endpoint.',
                         'state': 'executed', 'requested_by': analyst.id, 'approved_by': manager.id,
                         'executed_date': scenario['C'][0].timestamp + timedelta(hours=4),
                         'result': "Demo mode: 'host-deny0' simulated on agent 007."})

        # ---- AI analyses
        analysis_model = env['cg.ai.analysis'].with_user(analyst)
        analysis_model.create_from_alerts(scenario['A'], 'log_analysis',
                                          title='SSH brute force and account compromise on WEB-PROD-01', incident=inc_a)
        analysis_model.create_from_alerts(scenario['B'], 'threat', title='Threat investigation: %s' % ATTACKER_WEB)
        analysis_model.run_console(mode='daily_summary', hours=24)

        # ---- notifications
        notify = env['cg.notification'].notify
        notify('Critical alert: Unusual outbound data transfer on DB-PROD-01', '4.2 GB sent to %s in 11 minutes.' % EXFIL_DEST,
               'critical_alert', 'critical', scenario['F'][-1], 'cyberguard_360.group_cg_analyst')
        notify('New incident %s' % inc_a.reference, inc_a.name, 'incident', 'critical', inc_a, users=analyst)
        notify('Agent offline: HR-LT-007', 'Wazuh agent 008 stopped reporting 2 days ago.', 'agent_offline', 'high',
               assets['HR-LT-007'], 'cyberguard_360.group_cg_admin')
        notify('New critical vulnerability: CVE-2024-21762', 'Affects FW-EDGE-01. Priority score 100.', 'vulnerability',
               'critical', vuln_records['CVE-2024-21762'], 'cyberguard_360.group_cg_analyst')
        notify('Remediation overdue: CVE-2023-23397', 'Due date passed. Affects 2 assets.', 'reminder', 'critical',
               vuln_records['CVE-2023-23397'], users=analyst)

        # ---- audit trail
        log = env['cg.activity.log']
        for who, text, category, record in [
            (admin, 'Wazuh connection tested', 'soc', False), (analyst, 'Wazuh alerts synchronised', 'soc', False),
            (analyst, 'Incident created from alert', 'incident', inc_a), (manager, 'Response action approved', 'automation', False),
            (analyst, 'AI analysis generated', 'ai', False), (admin, 'Asset registered', 'asset', web),
            (manager, 'Management report generated', 'admin', False),
        ]:
            log.with_user(who).log(text, category, record or None)
        return True

    # ------------------------------------------------------------------ live simulator
    @api.model
    @system_write
    def simulate_alerts(self, count=None, spread_hours=1):
        """Generate fresh alerts so a sync in demo mode behaves like a live Wazuh feed."""
        asset_model = self.env['cg.asset']
        monitored = asset_model.search([('agent_status', '=', 'active')])
        if not monitored:
            return self.env['cg.alert']
        now = fields.Datetime.now().replace(microsecond=0)
        rng = random.Random()
        count = count or rng.randint(5, 11)
        linux = monitored.filtered(lambda a: 'Windows' not in (a.operating_system or '') and a.asset_type == 'server')
        windows = monitored.filtered(lambda a: 'Windows' in (a.operating_system or ''))
        facing = monitored.filtered('internet_facing') or monitored
        plans = []
        burst = rng.random()
        if burst < 0.45 and linux:
            target, src = rng.choice(linux), rng.choice([ATTACKER_SSH, '203.0.113.%d' % rng.randint(60, 90)])
            plans += [('ssh_fail', target, src, rng.choice(['root', 'admin', 'deploy']))] * rng.randint(4, 7)
            plans.append(('ssh_brute', target, src, 'root'))
        elif burst < 0.7:
            target = rng.choice(facing)
            plans += [('portscan', target, ATTACKER_SCAN, '')] * rng.randint(2, 4)
        elif burst < 0.85 and linux:
            plans += [('sqli', rng.choice(linux), ATTACKER_WEB, '')] * rng.randint(2, 5)
        while len(plans) < count:
            asset = rng.choice(monitored)
            is_windows = asset in windows
            key = rng.choice(['win_logon', 'win_fail', 'ports'] if is_windows else ['pam_open', 'dpkg', 'ports', 'sca', 'fim_web'])
            plans.append((key, asset, '10.0.3.%d' % rng.randint(10, 60) if key == 'win_fail' else '', 'jsmith' if is_windows else 'root'))
        vals = [self._alert_vals(key, asset, now - timedelta(seconds=rng.randint(0, max(60, spread_hours * 3600))),
                                 src=src, user=user) for key, asset, src, user in plans[:max(count, len(plans))]]
        alerts = self.env['cg.alert'].create(vals)
        alerts._post_process()
        return alerts

    @api.model
    @system_write
    def simulate_agent_health(self):
        """Refresh keepalives; occasionally an agent drops or recovers."""
        now = fields.Datetime.now()
        asset_model = self.env['cg.asset']
        active = asset_model.search([('agent_status', '=', 'active')])
        active.write({'agent_last_keepalive': now})
        went_offline = asset_model
        rng = random.Random()
        candidates = active.filtered(lambda a: a.criticality in ('low', 'medium'))
        if candidates and rng.random() < 0.2:
            went_offline = rng.choice(candidates)
            went_offline.agent_status = 'disconnected'
        elif rng.random() < 0.15:
            asset_model.search([('agent_status', '=', 'disconnected')], limit=1).write(
                {'agent_status': 'active', 'agent_last_keepalive': now})
        return went_offline
