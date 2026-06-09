import json
import csv

def export_json(results: list, filename: str):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)

def export_csv(results: list, filename: str):
    if not results: return
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Status', 'Service', 'Vulnerabilities'])
        for res in results:
            vulns = " | ".join(res['vulns']) if res['vulns'] else "None"
            writer.writerow([res['port'], res['status'], res['service'], vulns])

def export_html(results: list, filename: str, target: str):
    html = f"""
    <html>
    <head>
        <title>Scan Report: {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #007bff; color: white; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .vuln {{ color: red; font-weight: bold; }}
            .info {{ color: orange; }}
        </style>
    </head>
    <body>
        <h1>ProLevel PortScan Report</h1>
        <h2>Target: {target}</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Status</th>
                <th>Service Fingerprint</th>
                <th>Vulnerabilities & Notes</th>
            </tr>
    """
    for res in results:
        vulns_html = ""
        for v in res['vulns']:
            if "[VULN]" in v:
                vulns_html += f"<div class='vuln'>{v}</div>"
            else:
                vulns_html += f"<div class='info'>{v}</div>"
        if not vulns_html:
            vulns_html = "None"
            
        html += f"""
            <tr>
                <td>{res['port']}</td>
                <td>{res['status']}</td>
                <td>{res['service']}</td>
                <td>{vulns_html}</td>
            </tr>
        """
        
    html += """
        </table>
    </body>
    </html>
    """
    with open(filename, 'w') as f:
        f.write(html)
