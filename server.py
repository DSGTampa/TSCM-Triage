#!/usr/bin/env python3
"""
DSG TSCM Triage v1.8.2 — Local Flask Server
Surveillance Specialist Group, LLC
Run: python3 ~/dsg-tscm/server.py
Access: http://127.0.0.1:5555
"""
import os, re, sys, time, json, shutil, glob, socket, subprocess, datetime, platform
from flask import Flask, send_file, jsonify, request, Response

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
RUN_LOG = os.path.expanduser('~/DSG-TSCM/run_log.txt')

# ── Network Validation (Kismet) engine wiring ──────────────────────────────
# The engines package + baseline/session state live alongside server.py so the
# app is self-contained wherever it is deployed (git checkout or runtime dir).
sys.path.insert(0, BASE)
DATA_DIR = os.path.join(BASE, 'data')
REPORTS_DIR = os.path.join(BASE, 'reports')
BASELINE_PATH = os.path.join(DATA_DIR, 'baseline.json')
SESSION_PATH = os.path.join(DATA_DIR, 'validation_session.json')

from engines import kismet_db, net_validation, baseline_mgr, validation_export

_baseline = baseline_mgr.BaselineManager(BASELINE_PATH)
_session = net_validation.ValidationSession(SESSION_PATH)

# Session-setup state: 'new' after a fresh-location reset, else 'resumed'.
_SESSION_TYPE = 'resumed'
_DATA_ARCHIVED = False


def _kismet_running():
    """True if a live Kismet process is present."""
    try:
        return subprocess.run(['pgrep', '-x', 'kismet'],
                              capture_output=True).returncode == 0
    except Exception:
        return False

# Where case output is written. Defaults to ~/DSG-TSCM/cases, but can be
# redirected to an external drive (e.g. a USB stick on a Raspberry Pi) by
# setting CASES_PATH — this spares the SD card from scan/pcap write wear.
DEFAULT_CASES_PATH = os.path.expanduser('~/DSG-TSCM/cases')
CASES_PATH = os.path.expanduser(os.environ.get('CASES_PATH', '').strip() or DEFAULT_CASES_PATH)
CASES_IS_DEFAULT = (os.path.normpath(CASES_PATH) == os.path.normpath(DEFAULT_CASES_PATH))

try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    # Add manual CORS headers if flask_cors not available
    @app.after_request
    def add_cors(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

@app.route('/')
def index():
    return send_file(os.path.join(BASE, 'dsg_tscm_triage.html'))

@app.route('/api/interfaces')
def interfaces():
    # Virtual/internal interfaces to exclude
    EXCLUDE = ('lo', 'docker', 'veth', 'br-', 'virbr', 'vmnet', 'dummy', 'bond', 'ovs')
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        wired = []
        wireless = []
        current = None
        ip_info = None
        for line in result.stdout.split('\n'):
            m = re.match(r'^\d+:\s+(\S+?)[@:]', line)
            if m:
                # Save previous interface before moving on
                if current and not any(current.startswith(ex) for ex in EXCLUDE):
                    if current.startswith('wlan') and not 'mon' in current:
                        wireless.append({'name': current,
                                         'ip': ip_info['ip'] if ip_info else 'no IP',
                                         'subnet': ip_info['subnet'] if ip_info else '',
                                         'type': 'wireless'})
                    elif ip_info and not current.startswith('wlan'):
                        wired.append({'name': current, 'ip': ip_info['ip'],
                                      'subnet': ip_info['subnet'], 'type': 'wired'})
                current = m.group(1)
                ip_info = None
            ip_m = re.match(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if ip_m and current:
                ip = ip_m.group(1)
                pfx = ip_m.group(2)
                parts = ip.split('.')
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{pfx}"
                ip_info = {'ip': ip, 'subnet': subnet}
        # Handle last interface
        if current and not any(current.startswith(ex) for ex in EXCLUDE):
            if current.startswith('wlan') and 'mon' not in current:
                wireless.append({'name': current,
                                 'ip': ip_info['ip'] if ip_info else 'no IP',
                                 'subnet': ip_info['subnet'] if ip_info else '',
                                 'type': 'wireless'})
            elif ip_info and not current.startswith('wlan'):
                wired.append({'name': current, 'ip': ip_info['ip'],
                              'subnet': ip_info['subnet'], 'type': 'wired'})
        return jsonify({'wired': wired, 'wireless': wireless,
                        'interfaces': wired + wireless})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/run', methods=['POST'])
def run_command():
    # Security measure: localhost only. The server also binds to 127.0.0.1,
    # but reject explicitly in case it is ever re-hosted behind a proxy.
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'output': '', 'returncode': -1,
                        'error': 'Forbidden: requests accepted from localhost only'}), 403

    data = request.get_json(silent=True) or {}
    command = (data.get('command') or data.get('cmd') or '').strip()
    if not command:
        return jsonify({'output': '', 'returncode': -1,
                        'error': 'Empty command — nothing to run'}), 400

    # Audit log: timestamp every command execution for case accountability
    try:
        os.makedirs(os.path.dirname(RUN_LOG), exist_ok=True)
        with open(RUN_LOG, 'a') as fh:
            fh.write('[%s] %s\n' % (datetime.datetime.now().isoformat(timespec='seconds'), command))
    except Exception:
        pass  # never fail the run just because logging failed

    try:
        result = subprocess.run(command, shell=True, capture_output=True,
                                text=True, timeout=300)
        output = (result.stdout or '') + (result.stderr or '')
        return jsonify({'output': output, 'returncode': result.returncode, 'error': None})
    except subprocess.TimeoutExpired as e:
        partial = ''
        if e.stdout:
            partial += e.stdout if isinstance(e.stdout, str) else e.stdout.decode('utf-8', 'replace')
        if e.stderr:
            partial += e.stderr if isinstance(e.stderr, str) else e.stderr.decode('utf-8', 'replace')
        return jsonify({'output': partial, 'returncode': -1,
                        'error': 'Command timed out after 300 seconds'})
    except Exception as e:
        return jsonify({'output': '', 'returncode': -1, 'error': str(e)})

@app.route('/api/update', methods=['POST'])
def update():
    # Localhost-only, matching /api/run — this shells out and restarts the server.
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'success': False, 'stdout': '',
                        'stderr': 'Forbidden: requests accepted from localhost only'}), 403
    # update.sh lives in the git checkout (~/dsg-tscm/project) so its
    # `git pull --ff-only` has a work tree to pull into; it then deploys the
    # refreshed files to the runtime dir (~/dsg-tscm) and restarts Flask.
    project_dir = os.path.expanduser('~/dsg-tscm/project')
    try:
        result = subprocess.run(
            ['bash', os.path.join(project_dir, 'update.sh')],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=project_dir
        )
        return jsonify({
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'stdout': '', 'stderr': 'Update timed out after 120 seconds'}), 500
    except Exception as e:
        return jsonify({'success': False, 'stdout': '', 'stderr': str(e)}), 500

@app.route('/api/cases-path')
def cases_path():
    return jsonify({'cases_path': CASES_PATH, 'is_default': CASES_IS_DEFAULT})

@app.route('/api/config')
def config():
    return jsonify({
        'cases_path': CASES_PATH,
        'is_default': CASES_IS_DEFAULT,
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'system': platform.system(),
        'machine': platform.machine(),
    })

@app.route('/api/local-ip')
def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return jsonify({'local_ip': ip})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── NETWORK VALIDATION ─────────────────────────────────────────────────────
@app.route('/validation')
def validation_page():
    return send_file(os.path.join(BASE, 'validation.html'))


@app.route('/api/validation/aps')
def api_validation_aps():
    """Wi-Fi access points for Step 1, plus the saved session for resume.

    Also reports which capture file is being read and its total device count so
    the UI can show the examiner *why* the list may be empty (e.g. a live capture
    that has not accumulated devices yet, or one with no source attached).
    """
    db = kismet_db.open_db()
    session = _session.load()
    capture = kismet_db.resolve_db_path()
    capture_name = os.path.basename(capture) if capture else None
    if db is None or not db.is_available():
        return jsonify({'aps': [], 'session': session,
                        'kismet_connected': False, 'capture': capture_name,
                        'device_count': 0, 'error': 'kismet_disconnected'})
    return jsonify({'aps': net_validation.list_aps(db),
                    'session': session, 'kismet_connected': True,
                    'capture': capture_name,
                    'device_count': db.count_devices()})


@app.route('/api/validation/clients')
def api_validation_clients():
    """Client devices associated with the selected APs (Step 2)."""
    db = kismet_db.open_db()
    session = _session.load()
    if db is None or not db.is_available():
        return jsonify({'clients': [], 'session': session,
                        'kismet_connected': False,
                        'error': 'kismet_disconnected'})
    ap_macs = [m for m in request.args.get('aps', '').split(',') if m]
    clients = net_validation.list_clients(db, ap_macs)
    return jsonify({'clients': clients, 'session': session,
                    'kismet_connected': True})


@app.route('/api/validation/verify', methods=['POST'])
def api_validation_verify():
    """Persist the examiner's checklist so the session can be resumed.

    Accepts either a single-device update ({mac, status, notes}) or an
    access-point selection update ({selected_aps: [...]}); both merge into
    data/validation_session.json.
    """
    body = request.get_json(silent=True) or {}
    if 'selected_aps' in body:
        data = _session.set_aps(body.get('selected_aps') or [])
    elif body.get('mac'):
        data = _session.set_client(body['mac'],
                                   status=body.get('status'),
                                   notes=body.get('notes'))
    else:
        return jsonify({'error': 'nothing to update'}), 400
    return jsonify({'ok': True, 'session': data})


@app.route('/api/validation/enroll', methods=['POST'])
def api_validation_enroll():
    """Enroll every VERIFIED client plus the selected APs into the baseline."""
    session = _session.load()
    verified = [mac for mac, rec in session.get('clients', {}).items()
                if (rec or {}).get('status') == net_validation.STATUS_VERIFIED]
    aps = session.get('selected_aps', [])
    entries = ([{'mac': m, 'category': 'VERIFIED'} for m in verified] +
               [{'mac': m, 'category': 'WIFI_AP'} for m in aps
                if m.upper() not in {v.upper() for v in verified}])
    n = _baseline.add_many(entries) if entries else 0
    return jsonify({'enrolled': n, 'verified_clients': len(verified),
                    'access_points': len(aps),
                    'summary': _baseline.get_summary()})


@app.route('/api/validation/report')
def api_validation_report():
    """Render the network validation sweep to a printable HTML report.

    Returned inline (text/html) so the browser opens it directly for print;
    a timestamped copy is also saved under reports/ for the case file.
    """
    db = kismet_db.open_db()
    session = _session.load()
    ap_macs = session.get('selected_aps', [])
    all_aps = net_validation.list_aps(db)
    ap_set = {m.upper() for m in ap_macs}
    aps = [a for a in all_aps if a['mac'].upper() in ap_set]
    clients = net_validation.list_clients(db, ap_macs)

    capture = kismet_db.resolve_db_path()
    meta = {'generated_ts': int(time.time()),
            'capture': os.path.basename(capture) if capture else None}
    html_doc = net_validation.render_validation_report(aps, clients, session, meta)

    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        fname = 'network-validation-{}.html'.format(time.strftime('%Y%m%d-%H%M%S'))
        with open(os.path.join(REPORTS_DIR, fname), 'w') as f:
            f.write(html_doc)
    except OSError:
        pass  # a save failure must not stop the examiner viewing the report

    return Response(html_doc, mimetype='text/html')


@app.route('/api/validation-report')
def api_validation_report_export():
    """Export the Network Validation sweep as pdf | txt | csv | html.

    GET /api/validation-report?case={CASE_NUMBER}&examiner={NAME}&format=pdf|txt|csv|html

    Every format carries the same SHA256 of the report content. A timestamped
    copy is saved under {CASE_PATH}/reports/ (per-case if a case number is
    given, else the app-level reports/ dir) so it lands in the case file.
    """
    fmt = (request.args.get('format') or 'html').lower()
    if fmt not in ('pdf', 'txt', 'csv', 'html'):
        return jsonify({'error': "format must be one of pdf|txt|csv|html"}), 400
    case = (request.args.get('case') or '').strip()
    examiner = (request.args.get('examiner') or '').strip()

    db = kismet_db.open_db()
    session = _session.load()
    baseline = _baseline.get_all()
    capture = kismet_db.resolve_db_path()
    model = validation_export.build_model(
        db, session, baseline, case=case, examiner=examiner,
        capture=os.path.basename(capture) if capture else None)

    ts = time.strftime('%Y%m%d-%H%M%S')
    fname = 'validation_report_{}.{}'.format(ts, fmt)

    if fmt == 'txt':
        payload, mime = validation_export.render_txt(model).encode('utf-8'), 'text/plain'
    elif fmt == 'csv':
        payload, mime = validation_export.render_csv(model).encode('utf-8'), 'text/csv'
    elif fmt == 'html':
        payload, mime = validation_export.render_html(model).encode('utf-8'), 'text/html'
    else:  # pdf
        pdf_bytes, err = validation_export.render_pdf(model)
        if pdf_bytes is None:
            return jsonify({'error': 'PDF export unavailable: %s' % err}), 501
        payload, mime = pdf_bytes, 'application/pdf'

    # Save a copy into the case's reports/ dir (best-effort — a save failure must
    # not stop the examiner receiving the download).
    reports_dir = (os.path.join(CASES_PATH, case, 'reports') if case else REPORTS_DIR)
    try:
        os.makedirs(reports_dir, exist_ok=True)
        with open(os.path.join(reports_dir, fname), 'wb') as f:
            f.write(payload)
    except OSError:
        pass

    return Response(payload, mimetype=mime,
                    headers={'Content-Disposition': 'attachment; filename="%s"' % fname})


# ── SESSION SETUP (new location / resume) ──────────────────────────────────
@app.route('/api/session/status')
def api_session_status():
    """State the Session Setup modal uses to decide new-vs-resume and to show
    live progress: is Kismet live, how many devices in the newest capture, how
    old that capture is, and whether a baseline is enrolled."""
    capture = kismet_db.resolve_db_path()
    devices, age, mtime = 0, None, None
    if capture and os.path.exists(capture):
        try:
            devices = kismet_db.KismetDB(capture).count_devices()
        except Exception:
            devices = 0
        try:
            mtime = os.path.getmtime(capture)
            age = (time.time() - mtime) / 3600.0
        except OSError:
            pass
    return jsonify({
        'session_type': _SESSION_TYPE,
        'kismet_running': _kismet_running(),
        'devices_found': devices,
        'session_age_hours': round(age, 3) if age is not None else None,
        'capture': os.path.basename(capture) if capture else None,
        'capture_mtime': mtime,
        'data_archived': _DATA_ARCHIVED,
        'baseline_enrolled': _baseline.get_summary().get('total', 0) > 0,
    })


@app.route('/api/session/new', methods=['POST'])
def api_session_new():
    """Start a fresh location: archive the working data dir so nothing is truly
    lost, reset the working files to empty, and hand back the command the
    examiner runs to start a fresh dual-band Kismet capture (the server cannot
    enter monitor mode itself — that needs root)."""
    global _SESSION_TYPE, _DATA_ARCHIVED
    archived = None
    if os.path.isdir(DATA_DIR) and os.listdir(DATA_DIR):
        ts = time.strftime('%Y%m%d-%H%M%S')
        archived = os.path.join(BASE, 'data_archive_' + ts)
        try:
            shutil.move(DATA_DIR, archived)
        except OSError as e:
            return jsonify({'ok': False, 'error': 'archive failed: %s' % e}), 500
    os.makedirs(DATA_DIR, exist_ok=True)
    # Fresh, empty working files (TSCM uses baseline + validation session).
    _baseline.clear()
    _session.save({'selected_aps': [], 'clients': {}})
    _SESSION_TYPE = 'new'
    _DATA_ARCHIVED = bool(archived)
    return jsonify({
        'ok': True,
        'archived_to': os.path.basename(archived) if archived else None,
        'start_command': 'sudo bash %s/start_kismet.sh' % BASE,
    })


if __name__ == '__main__':
    print('\n  DSG TSCM Triage v1.8.4h — Flask Server')
    print('  http://127.0.0.1:5555')
    print('  Cases path: %s%s\n' % (CASES_PATH, '' if CASES_IS_DEFAULT else '  (external)'))
    app.run(host='127.0.0.1', port=5555, debug=False)
