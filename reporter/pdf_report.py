"""Render a finished scan report as a printable PDF.

WeasyPrint turns HTML + CSS into a PDF locally, so this works with the
network cable unplugged. The PDF is built from exactly the same report
data the page shows, which keeps the exported file and the screen in
agreement.
"""

import html


# Order used for the severity summary, most serious first.
SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low']

# Colour used for each severity in the PDF. Kept in one place so the
# cards, badges and summary boxes cannot drift apart.
SEVERITY_COLOURS = {
    'Critical': '#b42318',
    'High': '#c2410c',
    'Medium': '#a16207',
    'Low': '#15803d',
}


def _e(value):
    """Escape a value for safe use in HTML. None becomes an empty string."""
    if value is None:
        return ''
    return html.escape(str(value))


def _severity(value):
    """Normalise a severity name, falling back to Low for unknown values."""
    name = str(value or '').strip().capitalize()
    return name if name in SEVERITY_COLOURS else 'Low'


def _list_items(items):
    """Render a list as bullet points, tolerating a plain string."""
    if not items:
        return '<p class="muted">Not recorded.</p>'
    if isinstance(items, str):
        items = [items]
    rows = ''.join(f'<li>{_e(item)}</li>' for item in items)
    return f'<ul class="bullets">{rows}</ul>'


def _prose(value):
    """Render a text field that may be a string or a list of points."""
    if not value:
        return '<p class="muted">Not recorded.</p>'
    if isinstance(value, (list, tuple)):
        rows = ''.join(f'<li>{_e(item)}</li>' for item in value)
        return f'<ul class="bullets">{rows}</ul>'
    return f'<p>{_e(value)}</p>'


def _steps_block(items):
    """Render reproduction steps exactly as written.

    The steps arrive already numbered and indented (some lines are blank
    spacers), so they are printed as pre-wrapped paragraphs rather than
    list items -- a <ul> would number them a second time.
    """
    if not items:
        return '<p class="muted">Not recorded.</p>'
    if isinstance(items, str):
        items = [items]
    blocks = []
    for item in items:
        text = str(item)
        if text.strip():
            blocks.append(f'<p class="step">{_e(text)}</p>')
        else:
            blocks.append('<p class="step-gap"></p>')
    return ''.join(blocks)


def _summary_rows(vulnerabilities):
    """Count findings per severity, most serious first."""
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in vulnerabilities:
        counts[_severity(finding.get('severity'))] += 1
    return counts


def _finding_card(finding):
    """One finding, rendered as a self-contained block."""
    severity = _severity(finding.get('severity'))
    colour = SEVERITY_COLOURS[severity]

    verified = str(finding.get('verification_status') or '').strip()
    verified_class = 'confirmed' if verified.lower() == 'confirmed' else 'potential'

    detail_rows = [
        ('Vulnerable URL', finding.get('vulnerable_url')),
        ('Input Field', finding.get('input_field')),
        ('Payload Used', finding.get('payload_used')),
        ('CVSS Score', finding.get('cvss_score')),
        ('Confidence', f"{finding.get('confidence')}%"
         if finding.get('confidence') is not None else None),
        ('Status Code', finding.get('status_code')),
        ('Response Time', f"{finding.get('response_time')}s"
         if finding.get('response_time') is not None else None),
        ('Detection Method', finding.get('detection_method')),
        ('Detected At', finding.get('timestamp')),
    ]
    details = ''.join(
        f'<tr><td class="key">{_e(label)}</td>'
        f'<td class="val">{_e(value)}</td></tr>'
        for label, value in detail_rows
    )

    return f"""
    <section class="finding" style="border-left-color: {colour};">
      <div class="finding-head">
        <span class="fid">{_e(finding.get('id'))}</span>
        <span class="ftype">{_e(finding.get('vulnerability_type'))}</span>
        <span class="badge" style="background: {colour};">{_e(severity)}</span>
        <span class="badge status-{verified_class}">{_e(verified or 'Unverified')}</span>
      </div>

      <table class="details">{details}</table>

      <h4>Evidence</h4>
      {_list_items(finding.get('evidence'))}

      <h4>Description</h4>
      {_prose(finding.get('description'))}

      <h4>Impact</h4>
      {_prose(finding.get('impact'))}

      <h4>Reproduction Steps</h4>
      {_steps_block(finding.get('reproduction_steps'))}

      <h4>Recommendation</h4>
      {_prose(finding.get('recommendation'))}
    </section>
    """


STYLES = """
@page {
    size: A4;
    margin: 17mm 15mm 18mm 15mm;
    @bottom-left {
        content: "Intelligent Web Application Security Scanner";
        font-size: 7.5pt;
        color: #7b8794;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 7.5pt;
        color: #7b8794;
    }
}
* { box-sizing: border-box; }
body {
    font-family: "DejaVu Sans", "Liberation Sans", sans-serif;
    font-size: 9.2pt;
    line-height: 1.5;
    color: #1f2933;
    margin: 0;
}
h1 {
    font-size: 19pt;
    margin: 0 0 1mm 0;
    color: #0f3d3e;
}
.subtitle {
    font-size: 9.5pt;
    color: #52606d;
    margin: 0 0 6mm 0;
}
h4 {
    font-size: 9.4pt;
    margin: 3mm 0 1mm 0;
    color: #0f3d3e;
    text-transform: uppercase;
    letter-spacing: 0.4pt;
    page-break-after: avoid;
}
p { margin: 0 0 1.5mm 0; }
.muted { color: #7b8794; }
table.meta {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 6mm;
}
table.meta td {
    padding: 1.7mm 2mm;
    border-bottom: 0.25mm solid #e4e7eb;
    vertical-align: top;
}
table.meta td.key {
    width: 32mm;
    color: #52606d;
    font-weight: bold;
}
table.summary {
    width: 100%;
    border-collapse: separate;
    border-spacing: 2.5mm 0;
    margin: 0 -2.5mm 7mm -2.5mm;
}
table.summary td {
    width: 25%;
    padding: 3mm 2mm;
    text-align: center;
    border: 0.25mm solid #d9e2ec;
    border-radius: 2mm;
    background: #f8fafc;
}
table.summary .num {
    display: block;
    font-size: 16pt;
    font-weight: bold;
}
table.summary .label {
    display: block;
    font-size: 7.6pt;
    text-transform: uppercase;
    letter-spacing: 0.5pt;
    color: #52606d;
}
.finding {
    border: 0.25mm solid #d9e2ec;
    border-left: 1.8mm solid #94a3b8;
    border-radius: 2mm;
    padding: 3.2mm 3.8mm;
    margin-bottom: 4.5mm;
}
.finding-head {
    margin-bottom: 2.4mm;
    padding-bottom: 1.6mm;
    border-bottom: 0.25mm solid #e4e7eb;
    page-break-after: avoid;
}
.fid {
    font-weight: bold;
    font-size: 10.5pt;
    color: #0f3d3e;
    margin-right: 3mm;
}
.ftype {
    font-weight: bold;
    font-size: 10.5pt;
    margin-right: 3mm;
}
.badge {
    display: inline-block;
    padding: 0.6mm 2mm;
    border-radius: 1.5mm;
    color: #ffffff;
    font-size: 7.6pt;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.3pt;
}
.status-confirmed {
    background: #0f766e;
}
.status-potential {
    background: #64748b;
}
table.details {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 2mm;
}
table.details td {
    padding: 1.2mm 2mm;
    border-bottom: 0.2mm solid #eef2f6;
    vertical-align: top;
    word-break: break-word;
}
table.details td.key {
    width: 34mm;
    color: #52606d;
    font-weight: bold;
}
ul.bullets {
    margin: 0 0 1.5mm 0;
    padding-left: 5mm;
}
ul.bullets li {
    margin-bottom: 0.8mm;
    word-break: break-word;
}
p.step {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
}
p.step-gap {
    margin: 0;
    height: 1.6mm;
}
.note {
    margin-top: 7mm;
    padding-top: 3mm;
    border-top: 0.25mm solid #e4e7eb;
    font-size: 7.8pt;
    color: #7b8794;
}
"""


def render_report_html(payload):
    """Build the complete HTML document for one report payload."""
    vulnerabilities = payload.get('vulnerabilities') or []
    target = payload.get('target') or 'Unknown target'
    scanned_at = payload.get('scanned_at') or 'Not recorded'
    finished_at = payload.get('finished_at') or 'Not recorded'
    total = len(vulnerabilities)
    counts = _summary_rows(vulnerabilities)

    summary_cells = ''.join(
        f'<td><span class="num" style="color: {SEVERITY_COLOURS[name]};">'
        f'{counts[name]}</span><span class="label">{name}</span></td>'
        for name in SEVERITY_ORDER
    )

    if vulnerabilities:
        cards = ''.join(_finding_card(finding)
                        for finding in vulnerabilities)
    else:
        cards = ('<p class="muted">No vulnerabilities were detected in this '
                 'scan.</p>')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Scan Report - {_e(target)}</title>
  <style>{STYLES}</style>
</head>
<body>
  <h1>Web Application Security Scan Report</h1>
  <p class="subtitle">Intelligent Web Application Security Scanner</p>

  <table class="meta">
    <tr><td class="key">Target</td><td>{_e(target)}</td></tr>
    <tr><td class="key">Scan started</td><td>{_e(scanned_at)}</td></tr>
    <tr><td class="key">Scan finished</td><td>{_e(finished_at)}</td></tr>
    <tr><td class="key">Findings</td><td>{total}</td></tr>
  </table>

  <table class="summary"><tr>{summary_cells}</tr></table>

  {cards}

  <p class="note">
    Generated by the Intelligent Web Application Security Scanner. Each
    finding lists the evidence that was actually observed during the scan.
    "Confirmed" means the payload produced direct technical proof (for
    example a database error or real command output); "Potential" means the
    signal was weaker and deserves manual verification.
  </p>
</body>
</html>
"""


def render_pdf_bytes(payload):
    """Return the report as PDF bytes (imported lazily to keep startup fast)."""
    from weasyprint import HTML
    return HTML(string=render_report_html(payload)).write_pdf()


def write_pdf(payload, path):
    """Write the report to `path` as a PDF and return the path."""
    from weasyprint import HTML
    HTML(string=render_report_html(payload)).write_pdf(path)
    return path
