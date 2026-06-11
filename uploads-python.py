import os
import sys
import requests

# Credentials / target come from the environment so no secrets live in the repo.
DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', 'https://demo.defectdojo.org')
DEFECTDOJO_API_KEY = os.environ['DEFECTDOJO_API_KEY']
ENGAGEMENT_ID = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '24')

# scan_type -> report file produced by the CI scan jobs.
REPORTS = {
    'Gitleaks Scan': 'reports/gitleaks-report/gitleaks-report.json',
    'njsscan Scan': 'reports/njsscan-report/njsscan-report.json',
    'Semgrep JSON Report': 'reports/semgrep-report/semgrep-report.json',
}

headers = {
    'Authorization': f'Token {DEFECTDOJO_API_KEY}',
}

url = f'{DEFECTDOJO_URL}/api/v2/import-scan/'


def import_scan(scan_type, report_path):
    if not os.path.isfile(report_path):
        print(f'Report not found, skipping: {report_path}')
        return True

    data = {
        'scan_type': scan_type,
        'verified': 'false',
        'active': 'true',
        'minimum_severity': 'Low',
        'engagement': ENGAGEMENT_ID,
        'close_old_findings': 'true',
    }

    print(f"Importing '{scan_type}' from {report_path} ...")
    with open(report_path, 'rb') as fh:
        response = requests.post(url, headers=headers, data=data, files={'file': fh})

    if response.status_code == 201:
        print(f"  uploaded '{scan_type}' successfully!")
        return True

    print(f"  failed to upload '{scan_type}'. "
          f'Status code: {response.status_code}, Response: {response.text}')
    return False


def main():
    ok = True
    for scan_type, report_path in REPORTS.items():
        if not import_scan(scan_type, report_path):
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
