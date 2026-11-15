import { Component, onWillStart, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
import { formAction, loadTheme, saveTheme, scoreLevel } from "@cyberguard_360/js/cg_utils";

export class CyberGuardRiskMatrix extends Component {
    static template = "cyberguard_360.RiskMatrix";
    static props = ["*"];

    setup() {
        this.orm = useService("orm");
        this.action = useService("action");
        this.state = useState({ theme: loadTheme(), view: "inherent", risks: [], selected: null });
        onWillStart(async () => {
            this.state.risks = await this.orm.searchRead(
                "cg.risk",
                [["state", "!=", "closed"]],
                ["reference", "name", "likelihood", "impact", "score", "level", "residual_likelihood",
                    "residual_impact", "residual_score", "owner_id", "state"],
                { order: "score desc" }
            );
        });
    }

    /** Position of a risk in the current view; untreated risks keep their inherent position. */
    position(risk) {
        if (this.state.view === "residual" && risk.residual_likelihood && risk.residual_impact) {
            return { likelihood: Number(risk.residual_likelihood), impact: Number(risk.residual_impact) };
        }
        return { likelihood: Number(risk.likelihood), impact: Number(risk.impact) };
    }

    get rows() {
        const rows = [];
        for (let impact = 5; impact >= 1; impact--) {
            const cells = [];
            for (let likelihood = 1; likelihood <= 5; likelihood++) {
                const risks = this.state.risks.filter((risk) => {
                    const pos = this.position(risk);
                    return pos.likelihood === likelihood && pos.impact === impact;
                });
                const score = impact * likelihood;
                const level = scoreLevel(score);
                cells.push({ impact, likelihood, score, tone: level === "low" ? "ok" : level, risks });
            }
            rows.push(cells);
        }
        return rows;
    }

    get listed() {
        const selected = this.state.selected;
        const risks = selected
            ? this.state.risks.filter((risk) => {
                  const pos = this.position(risk);
                  return pos.likelihood === selected.likelihood && pos.impact === selected.impact;
              })
            : this.state.risks;
        return risks.map((risk) => {
            const pos = this.position(risk);
            const score = pos.likelihood * pos.impact;
            const level = scoreLevel(score);
            return { ...risk, shownScore: score, tone: level === "low" ? "ok" : level };
        });
    }

    get totals() {
        const totals = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const risk of this.state.risks) {
            const pos = this.position(risk);
            totals[scoreLevel(pos.likelihood * pos.impact)] += 1;
        }
        return ["critical", "high", "medium", "low"].map((key) => ({
            key,
            count: totals[key],
            tone: key === "low" ? "ok" : key,
        }));
    }

    isSelected(cell) {
        const selected = this.state.selected;
        return selected && selected.likelihood === cell.likelihood && selected.impact === cell.impact;
    }

    select(cell) {
        this.state.selected = this.isSelected(cell) ? null : { likelihood: cell.likelihood, impact: cell.impact };
    }

    setView(view) {
        this.state.view = view;
        this.state.selected = null;
    }

    openRisk(risk) {
        return this.action.doAction(formAction("cg.risk", risk.id));
    }

    openRegister() {
        return this.action.doAction("cyberguard_360.cg_risk_action");
    }

    toggleTheme() {
        this.state.theme = this.state.theme === "dark" ? "light" : "dark";
        saveTheme(this.state.theme);
    }
}

registry.category("actions").add("cyberguard_360.risk_matrix", CyberGuardRiskMatrix);
