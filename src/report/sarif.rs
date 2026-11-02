use super::ScanReport;
use crate::rules::RULES;
use anyhow::Result;
use serde_json::json;

pub fn render(report: &ScanReport) -> Result<String> {
    let rules: Vec<serde_json::Value> = RULES
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "name": rule.title,
                "shortDescription": { "text": rule.title },
                "fullDescription": { "text": rule.description },
                "help": { "text": rule.fix },
                "properties": {
                    "security-severity": rule.severity.as_str(),
                    "layer": rule.layer.as_str(),
                    "owasp": {
                        "llm": rule.llm,
                        "mcp": rule.mcp,
                        "agentic": rule.agentic,
                    }
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.id,
                "level": finding.severity.sarif_level(),
                "message": {
                    "text": format!("{}: {}", finding.title, finding.evidence)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file.replace('\\', "/")
                        },
                        "region": { "startLine": finding.line }
                    }
                }],
                "properties": {
                    "severity": finding.severity.as_str(),
                    "layer": finding.source.as_str(),
                    "client": finding.client,
                    "owasp": finding.owasp,
                    "fingerprint": finding.fingerprint(),
                    "fix": finding.fix,
                }
            })
        })
        .collect();

    let payload = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentsec",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/agentsec/agentsec",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    Ok(format!("{}\n", serde_json::to_string_pretty(&payload)?))
}
