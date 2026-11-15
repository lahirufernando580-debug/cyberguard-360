import { Component, onWillStart, useRef, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { formAction, formatTime, loadTheme, parseRichText, saveTheme } from "@cyberguard_360/js/cg_utils";

const MODES = [
    { key: "log_analysis", label: "Log analysis", hint: "Explain what happened in the selected events." },
    { key: "threat", label: "Threat investigation", hint: "Attack scenario, sequence and indicators." },
    { key: "daily_summary", label: "Daily summary", hint: "Briefing for the security team." },
    { key: "executive", label: "Executive summary", hint: "Plain-language summary for management." },
    { key: "comparison", label: "Compare periods", hint: "This period against the one before it." },
];
const WINDOWS = [
    { value: 6, label: "Last 6 hours" },
    { value: 24, label: "Last 24 hours" },
    { value: 72, label: "Last 3 days" },
    { value: 168, label: "Last 7 days" },
    { value: 336, label: "Last 14 days" },
];
const SUGGESTIONS = [
    "What should I focus on first?",
    "Who is attacking us?",
    "Summarise our security posture",
    "Which assets are most exposed?",
    "Which vulnerabilities should we patch first?",
];

export class CyberGuardAiConsole extends Component {
    static template = "cyberguard_360.AiConsole";
    static props = ["*"];

    setup() {
        this.orm = useService("orm");
        this.action = useService("action");
        this.notification = useService("notification");
        this.modes = MODES;
        this.windows = WINDOWS;
        this.suggestions = SUGGESTIONS;
        this.formatTime = formatTime;
        this.chatBody = useRef("chatBody");
        this.state = useState({
            theme: loadTheme(),
            mode: "log_analysis",
            hours: 24,
            severity: "",
            assetId: "",
            assets: [],
            running: false,
            report: null,
            question: "",
            thinking: false,
            messages: [
                {
                    role: "bot",
                    lines: parseRichText(
                        "I answer from the security data held in CyberGuard: alerts, incidents, risks, vulnerabilities and assets. I label anything that is my inference as a hypothesis."
                    ),
                    engine: "",
                },
            ],
        });
        onWillStart(async () => {
            this.state.assets = await this.orm.searchRead("cg.asset", [], ["name"], { order: "name" });
        });
    }

    get modeHint() {
        return this.modes.find((mode) => mode.key === this.state.mode).hint;
    }

    get confidenceTone() {
        const confidence = this.state.report.confidence;
        return confidence >= 75 ? "ok" : confidence >= 50 ? "medium" : "high";
    }

    toggleTheme() {
        this.state.theme = this.state.theme === "dark" ? "light" : "dark";
        saveTheme(this.state.theme);
    }

    async run() {
        this.state.running = true;
        try {
            this.state.report = await this.orm.call("cg.ai.analysis", "run_console", [], {
                mode: this.state.mode,
                hours: Number(this.state.hours),
                severity: this.state.severity || false,
                asset_id: this.state.assetId ? Number(this.state.assetId) : false,
            });
        } finally {
            this.state.running = false;
        }
    }

    openReport() {
        return this.action.doAction(formAction("cg.ai.analysis", this.state.report.id));
    }

    async printReport() {
        const action = await this.orm.call("cg.ai.analysis", "action_print", [[this.state.report.id]]);
        return this.action.doAction(action);
    }

    openSaved() {
        return this.action.doAction("cyberguard_360.cg_ai_analysis_action");
    }

    // ------------------------------------------------------------ chat
    async ask(text) {
        const question = (text || this.state.question).trim();
        if (!question || this.state.thinking) {
            return;
        }
        const history = this.state.messages
            .slice(1)
            .map((message) => ({ role: message.role === "user" ? "user" : "assistant", text: message.raw || "" }));
        this.state.messages.push({ role: "user", lines: parseRichText(question), raw: question });
        this.state.question = "";
        this.state.thinking = true;
        this.scrollChat();
        try {
            const result = await this.orm.call("cg.ai.engine", "chat", [question, history]);
            this.state.messages.push({
                role: "bot",
                lines: parseRichText(result.answer),
                raw: result.answer,
                engine: result.engine === "claude" ? "Claude" : "CyberGuard engine",
            });
        } catch {
            this.state.messages.push({
                role: "bot",
                lines: parseRichText("I could not answer that just now. Please try again."),
                engine: "",
            });
        } finally {
            this.state.thinking = false;
            this.scrollChat();
        }
    }

    onKeydown(ev) {
        if (ev.key === "Enter") {
            this.ask();
        }
    }

    scrollChat() {
        requestAnimationFrame(() => {
            const el = this.chatBody.el;
            if (el) {
                el.scrollTop = el.scrollHeight;
            }
        });
    }
}

registry.category("actions").add("cyberguard_360.ai_console", CyberGuardAiConsole);
