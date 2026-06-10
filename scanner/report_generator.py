import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .image_parser import ImageInfo
from .matcher import MatchResult


class ReportGenerator:
    def __init__(self, image_info: ImageInfo, results: List[MatchResult], summary: dict):
        self.image_info = image_info
        self.results = results
        self.summary = summary
        self.generated_at = datetime.now().isoformat()

    def generate_console_report(self) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append(f"  CONTAINER IMAGE VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"  Image:        {self.image_info.full_name}")
        lines.append(f"  Architecture: {self.image_info.architecture}")
        lines.append(f"  OS:           {self.image_info.os_type}")
        lines.append(f"  Distro:       {self.image_info.distro} {self.image_info.distro_version}")
        lines.append(f"  Layers:       {len(self.image_info.layers)}")
        lines.append(f"  Scan Time:    {self.generated_at}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("  VULNERABILITY SUMMARY")
        lines.append("-" * 80)
        lines.append(f"  Total Vulnerabilities:     {self.summary['total_vulnerabilities']}")
        lines.append(f"  CRITICAL:  {self.summary['critical']:>5}")
        lines.append(f"  HIGH:      {self.summary['high']:>5}")
        lines.append(f"  MEDIUM:    {self.summary['medium']:>5}")
        lines.append(f"  LOW:       {self.summary['low']:>5}")
        lines.append(f"  UNKNOWN:   {self.summary['unknown']:>5}")
        lines.append(f"  Unique CVEs:               {self.summary['unique_cves']}")
        lines.append(f"  Affected Packages:         {self.summary['unique_affected_packages']}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("  LAYER RISK DISTRIBUTION")
        lines.append("-" * 80)
        for layer_order, count in sorted(self.summary.get("layer_distribution", {}).items()):
            bar = "#" * min(count, 60)
            lines.append(f"  Layer {layer_order:>3}: {count:>4} vulnerabilities  {bar}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("  VULNERABILITY DETAILS")
        lines.append("-" * 80)

        sorted_results = sorted(self.results, key=lambda r: (-r.cvss_v3_score, r.package_name, r.cve_id))

        for idx, r in enumerate(sorted_results, 1):
            lines.append(f"  [{idx}] {r.cve_id} [{r.severity}]")
            lines.append(f"      CVSS v3: {r.cvss_v3_score}  CVSS v2: {r.cvss_v2_score}")
            lines.append(f"      Package: {r.package_name}@{r.package_version}")
            lines.append(f"      Layer:   {r.layer_order}  Manager: {r.package_manager}")
            if r.description:
                desc = r.description[:200] + "..." if len(r.description) > 200 else r.description
                lines.append(f"      Description: {desc}")
            if r.fixed_version:
                lines.append(f"      Fixed Version: {r.fixed_version}")
            lines.append("")

        lines.append("-" * 80)
        lines.append("  REFERENCES")
        lines.append("-" * 80)
        unique_refs = set()
        for r in sorted_results:
            for ref in r.references[:3]:
                if ref not in unique_refs:
                    unique_refs.add(ref)
                    lines.append(f"  - {ref}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("  END OF REPORT")
        lines.append("=" * 80)
        return "\n".join(lines)

    def generate_html_report(self, output_path: str) -> str:
        from jinja2 import Template

        template = Template(HTML_TEMPLATE)

        severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
        sorted_results = sorted(self.results, key=lambda r: (
            -severity_order.get(r.severity, 0),
            -r.cvss_v3_score,
            r.package_name,
            r.cve_id
        ))

        results_data = [r.to_dict() for r in sorted_results]

        chart_data = {
            "labels": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
            "data": [
                self.summary["critical"],
                self.summary["high"],
                self.summary["medium"],
                self.summary["low"],
                self.summary["unknown"],
            ],
            "colors": ["#dc3545", "#fd7e14", "#ffc107", "#0d6efd", "#6c757d"],
        }

        layer_data = []
        for layer in self.image_info.layers:
            count = self.summary.get("layer_distribution", {}).get(layer.order, 0)
            layer_data.append({
                "order": layer.order,
                "layer_id": layer.layer_id[:12] if layer.layer_id else "N/A",
                "vuln_count": count,
                "size_mb": round(layer.size / (1024 * 1024), 2) if layer.size else 0,
            })

        html = template.render(
            image_name=self.image_info.full_name,
            architecture=self.image_info.architecture,
            distro=f"{self.image_info.distro} {self.image_info.distro_version}",
            total_layers=len(self.image_info.layers),
            scan_time=self.generated_at,
            summary=self.summary,
            results=results_data,
            chart_data=json.dumps(chart_data),
            layer_data=json.dumps(layer_data),
            severity_order=severity_order,
        )

        output_file = Path(output_path)
        output_file.write_text(html, encoding="utf-8")
        return str(output_file.absolute())

    def generate_csv_report(self, output_path: str) -> str:
        output_file = Path(output_path)

        sorted_results = sorted(self.results, key=lambda r: (-r.cvss_v3_score, r.package_name, r.cve_id))

        fieldnames = [
            "cve_id", "severity", "cvss_v3_score", "cvss_v2_score",
            "package_name", "package_version", "layer_order", "package_manager",
            "distro", "fixed_version", "published_date", "description",
            "references", "cpe_matched",
        ]

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()

            for r in sorted_results:
                row = r.to_dict()
                row["references"] = " | ".join(r.references)
                writer.writerow(row)

        return str(output_file.absolute())

    def generate_json_report(self, output_path: str) -> str:
        output_file = Path(output_path)

        report = {
            "metadata": {
                "image": self.image_info.full_name,
                "architecture": self.image_info.architecture,
                "distro": f"{self.image_info.distro} {self.image_info.distro_version}",
                "total_layers": len(self.image_info.layers),
                "scan_time": self.generated_at,
                "scanner_version": "1.0.0",
            },
            "summary": self.summary,
            "vulnerabilities": [r.to_dict() for r in self.results],
            "layers": [
                {
                    "order": layer.order,
                    "layer_id": layer.layer_id,
                    "size_bytes": layer.size,
                    "diff_id": layer.diff_id,
                    "vuln_count": self.summary.get("layer_distribution", {}).get(layer.order, 0),
                }
                for layer in self.image_info.layers
            ],
        }

        output_file.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(output_file.absolute())


HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container Vulnerability Report - {{ image_name }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 24px; }
        .header h1 { font-size: 28px; margin-bottom: 8px; }
        .header .subtitle { opacity: 0.8; font-size: 14px; }
        .header .meta { display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }
        .header .meta-item { display: flex; flex-direction: column; }
        .header .meta-label { font-size: 11px; text-transform: uppercase; opacity: 0.6; }
        .header .meta-value { font-size: 16px; font-weight: 600; }
        .card { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); }
        .card h2 { font-size: 18px; margin-bottom: 16px; color: #1a1a2e; border-bottom: 2px solid #e8ecf1; padding-bottom: 8px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; }
        .summary-card { text-align: center; padding: 20px; border-radius: 8px; background: #f8f9fc; }
        .summary-card .count { font-size: 32px; font-weight: 700; }
        .summary-card .label { font-size: 12px; text-transform: uppercase; color: #666; margin-top: 4px; }
        .summary-card.critical { border-left: 4px solid #dc3545; }
        .summary-card.high { border-left: 4px solid #fd7e14; }
        .summary-card.medium { border-left: 4px solid #ffc107; }
        .summary-card.low { border-left: 4px solid #0d6efd; }
        .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        @media (max-width: 900px) { .charts-grid { grid-template-columns: 1fr; } }
        .chart-container { position: relative; height: 300px; }
        .vuln-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .vuln-table th { text-align: left; padding: 10px 12px; background: #f8f9fc; border-bottom: 2px solid #e8ecf1; font-weight: 600; color: #555; font-size: 11px; text-transform: uppercase; }
        .vuln-table td { padding: 10px 12px; border-bottom: 1px solid #eef0f5; }
        .vuln-table tr:hover { background: #f8f9fc; }
        .severity-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: white; }
        .severity-CRITICAL { background: #dc3545; }
        .severity-HIGH { background: #fd7e14; }
        .severity-MEDIUM { background: #ffc107; color: #333; }
        .severity-LOW { background: #0d6efd; }
        .severity-UNKNOWN { background: #6c757d; }
        .cvss-score { font-weight: 600; }
        .cvss-critical { color: #dc3545; }
        .cvss-high { color: #fd7e14; }
        .cvss-medium { color: #ffc107; }
        .cvss-low { color: #0d6efd; }
        .filter-bar { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
        .filter-bar input, .filter-bar select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px; }
        .filter-bar input { flex: 1; min-width: 200px; }
        .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
        .detail-toggle { cursor: pointer; color: #0d6efd; font-size: 12px; }
        .detail-content { display: none; margin-top: 8px; padding: 12px; background: #f8f9fc; border-radius: 6px; font-size: 12px; }
        .detail-content.show { display: block; }
        .ref-link { display: block; color: #0d6efd; font-size: 12px; word-break: break-all; }
        .code { font-family: 'Courier New', monospace; background: #eef0f5; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Container Vulnerability Scan Report</h1>
            <div class="subtitle">Generated at {{ scan_time }}</div>
            <div class="meta">
                <div class="meta-item">
                    <span class="meta-label">Image</span>
                    <span class="meta-value">{{ image_name }}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Architecture</span>
                    <span class="meta-value">{{ architecture }}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Distribution</span>
                    <span class="meta-value">{{ distro }}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Total Layers</span>
                    <span class="meta-value">{{ total_layers }}</span>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Vulnerability Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="count">{{ summary.total_vulnerabilities }}</div>
                    <div class="label">Total</div>
                </div>
                <div class="summary-card critical">
                    <div class="count">{{ summary.critical }}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card high">
                    <div class="count">{{ summary.high }}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card medium">
                    <div class="count">{{ summary.medium }}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card low">
                    <div class="count">{{ summary.low }}</div>
                    <div class="label">Low</div>
                </div>
                <div class="summary-card">
                    <div class="count">{{ summary.unique_affected_packages }}</div>
                    <div class="label">Affected Packages</div>
                </div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="card">
                <h2>Severity Distribution</h2>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="card">
                <h2>Layer Risk Analysis</h2>
                <div class="chart-container">
                    <canvas id="layerChart"></canvas>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Vulnerability Details</h2>
            <div class="filter-bar">
                <input type="text" id="searchInput" placeholder="Search by CVE ID, package name, or description..." onkeyup="filterTable()">
                <select id="severityFilter" onchange="filterTable()">
                    <option value="">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="UNKNOWN">Unknown</option>
                </select>
                <select id="layerFilter" onchange="filterTable()">
                    <option value="">All Layers</option>
                    {% for i in range(total_layers) %}
                    <option value="{{ i }}">Layer {{ i }}</option>
                    {% endfor %}
                </select>
            </div>
            <div style="overflow-x: auto;">
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>CVSS v3</th>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Layer</th>
                            <th>Fixed</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody id="vulnTableBody">
                        {% for r in results %}
                        <tr data-severity="{{ r.severity }}" data-layer="{{ r.layer_order }}"
                            data-search="{{ r.cve_id }} {{ r.package_name }} {{ r.description }}">
                            <td><strong>{{ r.cve_id }}</strong></td>
                            <td><span class="severity-badge severity-{{ r.severity }}">{{ r.severity }}</span></td>
                            <td>
                                <span class="cvss-score {% if r.cvss_v3_score >= 9 %}cvss-critical{% elif r.cvss_v3_score >= 7 %}cvss-high{% elif r.cvss_v3_score >= 4 %}cvss-medium{% elif r.cvss_v3_score > 0 %}cvss-low{% endif %}">
                                    {{ r.cvss_v3_score }}
                                </span>
                            </td>
                            <td><span class="code">{{ r.package_name }}</span></td>
                            <td>{{ r.package_version }}</td>
                            <td>Layer {{ r.layer_order }}</td>
                            <td>{{ r.fixed_version or '-' }}</td>
                            <td>
                                <span class="detail-toggle" onclick="toggleDetail(this, 'detail-{{ loop.index }}')">Details ▸</span>
                            </td>
                        </tr>
                        <tr id="detail-{{ loop.index }}" class="detail-content">
                            <td colspan="8">
                                <strong>Description:</strong> {{ r.description }}<br><br>
                                <strong>Published:</strong> {{ r.published_date }}<br>
                                <strong>Package Manager:</strong> {{ r.package_manager }}<br>
                                <strong>References:</strong><br>
                                {% for ref in r.references[:5] %}
                                <a href="{{ ref }}" target="_blank" class="ref-link">{{ ref }}</a>
                                {% endfor %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            Container Security Scanner v1.0 | Generated {{ scan_time }}
        </div>
    </div>

    <script>
        function toggleDetail(el, detailId) {
            const detail = document.getElementById(detailId);
            detail.classList.toggle('show');
            el.textContent = detail.classList.contains('show') ? 'Details ▾' : 'Details ▸';
        }

        function filterTable() {
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const layerFilter = document.getElementById('layerFilter').value;
            const rows = document.querySelectorAll('#vulnTableBody tr[data-severity]');
            const detailRows = document.querySelectorAll('#vulnTableBody tr.detail-content');

            detailRows.forEach(dr => dr.classList.remove('show'));

            rows.forEach(row => {
                const severity = row.getAttribute('data-severity');
                const layer = row.getAttribute('data-layer');
                const searchData = row.getAttribute('data-search').toLowerCase();

                let visible = true;
                if (searchText && !searchData.includes(searchText)) visible = false;
                if (severityFilter && severity !== severityFilter) visible = false;
                if (layerFilter && layer !== layerFilter) visible = false;

                row.style.display = visible ? '' : 'none';
            });
        }

        const chartData = JSON.parse('{{ chart_data | safe }}');

        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: chartData.labels,
                datasets: [{
                    data: chartData.data,
                    backgroundColor: chartData.colors,
                    borderWidth: 2,
                    borderColor: '#fff',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right' }
                }
            }
        });

        const layerData = JSON.parse('{{ layer_data | safe }}');

        const layerLabels = layerData.map(l => 'Layer ' + l.order);
        const layerCounts = layerData.map(l => l.vuln_count);

        const bgColors = layerCounts.map(c => {
            if (c > 50) return '#dc3545';
            if (c > 20) return '#fd7e14';
            if (c > 5) return '#ffc107';
            if (c > 0) return '#0d6efd';
            return '#6c757d';
        });

        new Chart(document.getElementById('layerChart'), {
            type: 'bar',
            data: {
                labels: layerLabels,
                datasets: [{
                    label: 'Vulnerabilities',
                    data: layerCounts,
                    backgroundColor: bgColors,
                    borderWidth: 0,
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    </script>
</body>
</html>
"""