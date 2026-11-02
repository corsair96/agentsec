use super::ScanReport;
use crate::score;

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>agentsec report</title>\n<style>\n");
    out.push_str(
        "body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1f2328}\
         h1{margin-bottom:.25rem}.score{font-size:1.4rem;font-weight:700}\
         .finding{border:1px solid #d0d7de;border-left:5px solid #888;border-radius:6px;padding:1rem;margin:1rem 0}\
         .critical{border-left-color:#cf222e}.high{border-left-color:#d97706}\
         .medium{border-left-color:#bf8700}.low{border-left-color:#0969da}\
         code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}\
         .muted{color:#656d76}",
    );
    out.push_str("\n</style>\n</head>\n<body>\n");
    out.push_str("<h1>agentsec report</h1>\n");
    out.push_str(&format!(
        "<p class=\"score\">Risk score: {:.1}/10 ({})</p>\n",
        report.risk_score,
        escape(score::label(report.risk_score))
    ));
    out.push_str(&format!("<p>{}</p>\n", escape(&report.summary_line())));

    let sources: Vec<String> = report
        .sources
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(layer, count)| format!("{}({count})", layer.as_str()))
        .collect();
    out.push_str(&format!(
        "<p class=\"muted\">Sources scanned: {}</p>\n",
        escape(&if sources.is_empty() {
            "none".to_string()
        } else {
            sources.join(", ")
        })
    ));

    if report.findings.is_empty() {
        out.push_str("<p>No security findings.</p>\n");
    }

    for finding in &report.findings {
        out.push_str(&format!(
            "<div class=\"finding {}\">\n",
            finding.severity.as_str()
        ));
        out.push_str(&format!(
            "<strong>{} {}</strong> <span class=\"muted\">{} · {}</span><br>\n",
            escape(finding.severity.label()),
            escape(&finding.title),
            escape(&finding.id),
            escape(finding.source.as_str())
        ));
        out.push_str(&format!(
            "<div><code>{}:{}</code>{}</div>\n",
            escape(&finding.file),
            finding.line,
            finding
                .client
                .as_ref()
                .map(|client| format!(" <span class=\"muted\">({})</span>", escape(client)))
                .unwrap_or_default()
        ));
        out.push_str(&format!(
            "<p><code>{}</code></p>\n",
            escape(&finding.evidence)
        ));
        if let Some(fix) = &finding.fix {
            out.push_str(&format!("<p><strong>Fix:</strong> {}</p>\n", escape(fix)));
        }
        out.push_str("</div>\n");
    }

    out.push_str("</body>\n</html>\n");
    out
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
