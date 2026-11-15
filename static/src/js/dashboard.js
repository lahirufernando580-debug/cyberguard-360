import { Component, onWillStart, onWillUnmount, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { browser } from "@web/core/browser/browser";
import {
    formAction,
    formatTime,
    listAction,
    loadTheme,
    relativeTime,
    saveTheme,
} from "@cyberguard_360/js/cg_utils";

const OPEN_ALERTS = [["state", "in", ["new", "acknowledged", "investigating"]]];
const OPEN_VULNS = [["state", "in", ["open", "in_progress"]]];
const REFRESH_MS = 60000;

export class CyberGuardDashboard extends Component {
    static template = "cyberguard_360.Dashboard";
    static props = ["*"];

    setup() {
        this.orm = useService("orm");
        this.action = useService("action");
        this.notification = useService("notification");
        this.state = useState({ data: null, theme: loadTheme(), busy: "" });
        this.formatTime = formatTime;
        this.relativeTime = relativeTime;
        onWillStart(() => this.load());
        // Keep the wall display current without a manual refresh.
        this.timer = browser.setInterval(() => this.load(), REFRESH_MS);
        onWillUnmount(() => browser.clearInterval(this.timer));
    }

    async load() {
        this.state.data = await this.orm.call("cg.dashboard", "get_data", []);
    }

    get d() {
        return this.state.data;
    }

    get greeting() {
        const hour = new Date().getHours();
        return hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
    }

    get postureTone() {
        const score = this.d.posture.score;
        return score >= 70 ? "ok" : score >= 55 ? "medium" : score >= 40 ? "high" : "critical";
    }

    get alertTotalOpen() {
        return this.d.alert_severity.reduce((sum, item) => sum + item.count, 0) || 1;
    }

    get kpis() {
        const k = this.d.kpis;
        const r = this.d.remediation;
        return [
            { key: "assets", label: "Assets", value: k.assets, note: "registered", tone: "" },
            {
                key: "agents",
                label: "Wazuh agents",
                value: k.agents_connected,
                note: k.agents_disconnected ? "offline" : "all reporting",
                noteValue: k.agents_disconnected || "",
                tone: k.agents_disconnected ? "high" : "ok",
            },
            { key: "alerts", label: "Alerts 24h", value: k.alerts_24h, note: "open in total", noteValue: k.alerts_open, tone: "low" },
            {
                key: "critical_alerts",
                label: "Critical alerts",
                value: k.alerts_critical_open,
                note: "need triage",
                tone: k.alerts_critical_open ? "critical" : "ok",
            },
            {
                key: "vulns",
                label: "Vulnerabilities",
                value: k.vulns_open,
                note: "critical",
                noteValue: k.vulns_critical,
                tone: k.vulns_critical ? "critical" : "medium",
            },
            {
                key: "risks",
                label: "Critical risks",
                value: k.risks_critical,
                note: "open risks",
                noteValue: k.risks_open,
                tone: k.risks_critical ? "high" : "ok",
            },
            {
                key: "incidents",
                label: "Open incidents",
                value: k.incidents_open,
                note: k.incidents_overdue ? "past SLA" : "within SLA",
                noteValue: k.incidents_overdue || "",
                tone: k.incidents_overdue ? "critical" : "ok",
            },
            { key: "remediation", label: "Remediation", value: `${r.pct}%`, note: "fixed or closed", tone: "ok" },
        ];
    }

    segHeight(day, severity) {
        return day.total ? `${(day[severity] / day.total) * 100}%` : "0%";
    }

    toggleTheme() {
        this.state.theme = this.state.theme === "dark" ? "light" : "dark";
        saveTheme(this.state.theme);
    }

    // ------------------------------------------------------------ navigation
    open(name, model, domain = [], context = {}) {
        return this.action.doAction(listAction(name, model, domain, context));
    }

    openKpi(key) {
        const routes = {
            assets: () => this.action.doAction("cyberguard_360.cg_asset_action"),
            agents: () => this.action.doAction("cyberguard_360.cg_agent_action"),
            alerts: () => this.open("Open alerts", "cg.alert", OPEN_ALERTS),
            critical_alerts: () => this.open("Critical alerts", "cg.alert", [...OPEN_ALERTS, ["severity", "=", "critical"]]),
            vulns: () => this.action.doAction("cyberguard_360.cg_vulnerability_action"),
            risks: () => this.open("Critical risks", "cg.risk", [["level", "=", "critical"], ["state", "!=", "closed"]]),
            incidents: () => this.action.doAction("cyberguard_360.cg_incident_action"),
            remediation: () => this.open("Patched vulnerabilities", "cg.vulnerability", [["state", "in", ["patched", "accepted"]]]),
        };
        return routes[key]();
    }

    openSeverity(severity) {
        return this.open(`${severity} alerts`, "cg.alert", [...OPEN_ALERTS, ["severity", "=", severity]]);
    }

    openCell(cell) {
        return this.open(`Risks: likelihood ${cell.likelihood}, impact ${cell.impact}`, "cg.risk", [
            ["likelihood", "=", String(cell.likelihood)],
            ["impact", "=", String(cell.impact)],
            ["state", "!=", "closed"],
        ]);
    }

    openInsight(insight) {
        const routes = {
            alerts_ip: () => this.open(`Alerts from ${insight.value}`, "cg.alert", [["src_ip", "=", insight.value]]),
            vulns_p1: () => this.open("Patch first", "cg.vulnerability", [...OPEN_VULNS, ["priority", "=", "p1"]]),
            incidents_overdue: () =>
                this.open("Incidents past SLA", "cg.incident", [["stage", "in", ["new", "triage", "investigating"]]]),
            agents_offline: () =>
                this.open("Offline agents", "cg.asset", [["agent_status", "in", ["disconnected", "never_connected"]]]),
            alerts_repeated: () => this.open("Recurring alerts", "cg.alert", [...OPEN_ALERTS, ["is_repeated", "=", true]]),
            alerts_open: () => this.open("Open alerts", "cg.alert", OPEN_ALERTS),
            asset: () => this.action.doAction(formAction("cg.asset", insight.value)),
        };
        return routes[insight.target] ? routes[insight.target]() : undefined;
    }

    openRecord(model, id) {
        return this.action.doAction(formAction(model, id));
    }

    openAttacker(ip) {
        return this.open(`Alerts from ${ip}`, "cg.alert", [["src_ip", "=", ip]]);
    }

    openTechnique(technique) {
        return this.open(`${technique.code} ${technique.name}`, "cg.alert", [["mitre_technique_ids", "in", [technique.id]]]);
    }

    openStage(stage) {
        return this.open(`Incidents: ${stage.label}`, "cg.incident", [["stage", "=", stage.key]]);
    }

    openConsole() {
        return this.action.doAction("cyberguard_360.cg_ai_console_action");
    }

    // ------------------------------------------------------------ actions
    async sync() {
        this.state.busy = "sync";
        try {
            const result = await this.orm.call("cg.dashboard", "sync_now", []);
            this.notification.add(result.message || "Synchronised.", {
                title: result.ok ? "Wazuh synchronised" : "Wazuh sync failed",
                type: result.ok ? "success" : "danger",
            });
            await this.load();
        } finally {
            this.state.busy = "";
        }
    }

    async report() {
        this.state.busy = "report";
        try {
            const action = await this.orm.call("cg.dashboard", "generate_management_report", []);
            await this.action.doAction(action);
        } finally {
            this.state.busy = "";
        }
    }
}

registry.category("actions").add("cyberguard_360.dashboard", CyberGuardDashboard);
