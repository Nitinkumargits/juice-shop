import os
import sys
import time
import requests

# Gateway/availability errors worth retrying (e.g. demo instance being refreshed).
RETRY_STATUS = {502, 503, 504}
MAX_RETRIES = 4
BACKOFF_BASE = 3  # seconds; waits 3, 6, 12 between attempts

# Credentials / target come from the environment so no secrets live in the repo.
DEFECTDOJO_URL = os.environ.get('DEFECTDOJO_URL', 'https://demo.defectdojo.org')
DEFECTDOJO_API_KEY = os.environ['DEFECTDOJO_API_KEY']
ENGAGEMENT_ID = os.environ.get('DEFECTDOJO_ENGAGEMENT_ID', '14')

# scan_type -> report file produced by the CI scan jobs.
REPORTS = {
    'Gitleaks Scan': 'reports/gitleaks-report/gitleaks-report.json',
    'SARIF': 'reports/njsscan-report/njsscan-report.sarif',
    'Semgrep JSON Report': 'reports/semgrep-report/semgrep-report.json',
    'Retire.js Scan': 'reports/retirejs-report/retirejs-report.json',
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
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with open(report_path, 'rb') as fh:
                response = requests.post(
                    url, headers=headers, data=data, files={'file': fh}, timeout=60
                )
        except requests.exceptions.RequestException as exc:
            status, body = None, str(exc)
        else:
            if response.status_code == 201:
                print(f"  uploaded '{scan_type}' successfully!")
                return True
            status, body = response.status_code, response.text

        retryable = status in RETRY_STATUS or status is None
        if retryable and attempt < MAX_RETRIES:
            wait = BACKOFF_BASE * (2 ** (attempt - 1))
            print(f"  transient error (status={status}) on attempt {attempt}/{MAX_RETRIES}; "
                  f'retrying in {wait}s ...')
            time.sleep(wait)
            continue

        print(f"  failed to upload '{scan_type}'. Status code: {status}, Response: {body}")
        return False

    return False


def main():
    ok = True
    for scan_type, report_path in REPORTS.items():
        if not import_scan(scan_type, report_path):
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
