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

# ── Active site (Network Validation Step 0 — Site Identification) ───────────
# The examiner creates/picks a site before anything else; captures, reads and
# reports are then scoped to that site's folder under CASES_PATH. Persisted so
# the active site survives a server restart.
ACTIVE_SITE_PATH = os.path.join(DATA_DIR, 'active_site.json')
_active_site = None


def _load_active_site():
    global _active_site
    try:
        with open(ACTIVE_SITE_PATH) as f:
            _active_site = json.load(f)
    except (OSError, ValueError):
        _active_site = None
    return _active_site


def _set_active_site(meta):
    global _active_site
    _active_site = meta
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(ACTIVE_SITE_PATH, 'w') as f:
            json.dump(meta, f, indent=2)
    except OSError:
        pass


def _site_kismet_glob():
    """Glob for the ACTIVE site's Kismet captures, or None to fall back to the
    engine's default search. Scopes all reads to the current site's folder."""
    if _active_site and _active_site.get('site_path'):
        return os.path.join(_active_site['site_path'],
                            'wireless', 'kismet', '**', '*.kismet')
    return None


def _touch_active_site(device_count=None):
    """Bump the active site's last_sweep (and device_count) in its metadata.json
    so LOAD EXISTING reflects recency. Best-effort — never fails a request."""
    if not (_active_site and _active_site.get('site_path')):
        return
    meta_path = os.path.join(_active_site['site_path'], 'metadata.json')
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        meta['last_sweep'] = datetime.datetime.now().isoformat()
        if device_count is not None:
            meta['device_count'] = device_count
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        _active_site.update(meta)
    except (OSError, ValueError):
        pass


def _find_monitor_iface():
    """Return the name of a monitor-mode wireless interface, or None. Reads
    `iw dev` (no sudo needed); falls back to parsing `airmon-ng`."""
    try:
        out = subprocess.run(['iw', 'dev'], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        out = ''
    iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Interface '):
            iface = line.split(None, 1)[1]
        elif line.startswith('type ') and 'monitor' in line and iface:
            return iface
    try:
        out = subprocess.run(['airmon-ng'], capture_output=True,
                             text=True, timeout=8).stdout
        for line in out.splitlines():
            for tok in line.split():
                if 'mon' in tok and 'wlan' in tok:
                    return tok
    except Exception:
        pass
    return None


_load_active_site()


# We tag our own capture with this --log-title (see start_kismet.sh) so the app
# recognises ITS OWN Kismet and is never fooled by another product's Kismet
# running on the same box — DSG TSCM operates as if nothing else exists.
KISMET_TAG = 'dsg_tscm'


def _kismet_running():
    """True only if OUR tagged Kismet capture is live. A bare `pgrep -x kismet`
    would also match a co-resident capture from a different app and make us read
    a stale DB, so we match our own --log-title specifically."""
    try:
        out = subprocess.run(['pgrep', '-af', 'kismet'],
                             capture_output=True, text=True).stdout
    except Exception:
        return False
    return any(KISMET_TAG in ln for ln in out.splitlines())


def _launch_kismet():
    """Start the dual-band capture as root, without a terminal.

    The server runs as the non-root examiner and cannot enter monitor mode
    itself, so it shells out to `sudo -n /usr/bin/bash start_kismet.sh`. The
    installer grants a scoped NOPASSWD rule for exactly that `bash <script>`
    form (the bare-path form is unreliable when the user also has a blanket
    password-required sudo rule), so no password prompt is needed. Returns
    (ok: bool, status: str) where status is
    one of: already_running | launching | script_missing | spawn_failed |
    launch_failed. 'launch_failed' means the capture exited immediately — the
    passwordless grant is absent (older install) or the script bailed at startup
    (see kismet_launch.log) — and the caller falls back to the manual command."""
    if _kismet_running():
        return True, 'already_running'
    script = os.path.join(BASE, 'start_kismet.sh')
    if not os.path.isfile(script):
        return False, 'script_missing'
    try:
        lf = open(os.path.join(BASE, 'kismet_launch.log'), 'ab')
        proc = subprocess.Popen(['sudo', '-n', '/usr/bin/bash', script],
                                stdout=lf, stderr=lf, stdin=subprocess.DEVNULL,
                                start_new_session=True)
        lf.close()
    except Exception:
        return False, 'spawn_failed'
    # Detect success by outcome, not a pre-check: `sudo -n` with no passwordless
    # grant fails within milliseconds, so the process exits almost immediately.
    # A real launch keeps running (kismet is long-lived). If it's still alive
    # after a short grace period, the capture is starting. (An earlier
    # `sudo -n -l` pre-check was unreliable — it returns 0 for any allowed
    # command when the user has cached creds or blanket sudo, not just NOPASSWD.)
    try:
        proc.wait(timeout=2)
        # Exited early: no passwordless grant, or the capture bailed at startup.
        return False, 'launch_failed'  # details in kismet_launch.log
    except subprocess.TimeoutExpired:
        return True, 'launching'

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
    pattern = _site_kismet_glob()
    db = kismet_db.open_db(pattern)
    session = _session.load()
    capture = kismet_db.resolve_db_path(pattern)
    capture_name = os.path.basename(capture) if capture else None
    if db is None or not db.is_available():
        return jsonify({'aps': [], 'session': session,
                        'kismet_connected': False, 'capture': capture_name,
                        'device_count': 0, 'error': 'kismet_disconnected',
                        'active_site': _active_site})
    dc = db.count_devices()
    _touch_active_site(dc)  # keep last_sweep / device_count current for this site
    return jsonify({'aps': net_validation.list_aps(db),
                    'session': session, 'kismet_connected': True,
                    'capture': capture_name,
                    'device_count': dc,
                    'active_site': _active_site})


@app.route('/api/validation/clients')
def api_validation_clients():
    """Client devices associated with the selected APs (Step 2)."""
    db = kismet_db.open_db(_site_kismet_glob())
    session = _session.load()
    if db is None or not db.is_available():
        return jsonify({'clients': [], 'session': session,
                        'kismet_connected': False,
                        'error': 'kismet_disconnected'})
    ap_macs = [m for m in request.args.get('aps', '').split(',') if m]
    clients = net_validation.list_clients(db, ap_macs)
    return jsonify({'clients': clients, 'session': session,
                    'kismet_connected': True})


@app.route('/api/validation/sites', methods=['GET'])
def api_validation_sites():
    """List every site (CASES_PATH/<case>/<site>/metadata.json), newest sweep
    first, for the LOAD EXISTING table in Step 0."""
    sites = []
    if os.path.isdir(CASES_PATH):
        for case_dir in os.listdir(CASES_PATH):
            case_abs = os.path.join(CASES_PATH, case_dir)
            if not os.path.isdir(case_abs):
                continue
            for site_dir in os.listdir(case_abs):
                meta_path = os.path.join(case_abs, site_dir, 'metadata.json')
                if os.path.isfile(meta_path):
                    try:
                        with open(meta_path) as f:
                            sites.append(json.load(f))
                    except (OSError, ValueError):
                        continue
    sites.sort(key=lambda x: x.get('last_sweep', '') or '', reverse=True)
    return jsonify(sites)


@app.route('/api/validation/create-site', methods=['POST'])
def api_validation_create_site():
    """Create the folder structure + metadata.json for a new site and make it
    the active site."""
    data = request.get_json(silent=True) or {}
    case_number = (data.get('case_number') or '').strip()
    site_name = (data.get('site_name') or '').strip().replace(' ', '_')
    location = (data.get('location') or '').strip()
    examiner = (data.get('examiner') or '').strip()
    if not all([case_number, site_name, location, examiner]):
        return jsonify({'success': False, 'error': 'All fields required'}), 400
    # Keep case/site as single, traversal-safe path segments.
    safe_case = re.sub(r'[^A-Za-z0-9._-]', '_', case_number)
    safe_site = re.sub(r'[^A-Za-z0-9._-]', '_', site_name)
    site_path = os.path.join(CASES_PATH, safe_case, safe_site)
    try:
        for subdir in ('wireless/kismet', 'scans', 'reports'):
            os.makedirs(os.path.join(site_path, subdir), exist_ok=True)
    except OSError as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    now = datetime.datetime.now().isoformat()
    metadata = {
        'case_number': case_number,
        'site_name': site_name,
        'location': location,
        'examiner': examiner,
        'created': now,
        'last_sweep': now,
        'device_count': 0,
        'site_path': site_path,
    }
    with open(os.path.join(site_path, 'metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=2)
    _set_active_site(metadata)
    # Fresh site -> fresh validation session so Step 1/2 don't carry old picks.
    _session.save({'selected_aps': [], 'clients': {}})
    return jsonify({'success': True, 'site_path': site_path, 'metadata': metadata})


@app.route('/api/validation/set-site', methods=['POST'])
def api_validation_set_site():
    """Make an existing site active (LOAD EXISTING) so reads/reports resume from
    its data."""
    data = request.get_json(silent=True) or {}
    site_path = (data.get('site_path') or '').strip()
    meta_path = os.path.join(site_path, 'metadata.json')
    if not (site_path and os.path.isfile(meta_path)):
        return jsonify({'success': False, 'error': 'site not found'}), 404
    try:
        with open(meta_path) as f:
            meta = json.load(f)
    except (OSError, ValueError) as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    _set_active_site(meta)
    return jsonify({'success': True, 'metadata': meta})


@app.route('/api/validation/start-kismet', methods=['POST'])
def api_validation_start_kismet():
    """Launch Kismet writing into the active/selected site's wireless/kismet
    folder. Requires a monitor-mode interface to already exist; tags the
    capture --log-title dsg_tscm so the app recognises its own capture."""
    data = request.get_json(silent=True) or {}
    site_path = (data.get('site_path')
                 or (_active_site or {}).get('site_path') or '').strip()
    if not site_path:
        return jsonify({'success': False, 'error': 'no active site'}), 400
    kismet_dir = os.path.join(site_path, 'wireless', 'kismet')
    try:
        os.makedirs(kismet_dir, exist_ok=True)
    except OSError as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    kismet_prefix = os.path.join(kismet_dir, 'Kismet')

    mon = _find_monitor_iface()
    if not mon:
        return jsonify({'success': False,
                        'error': 'No monitor-mode interface found. '
                                 'Run: sudo airmon-ng start wlan1'}), 400

    # Best-effort stop of any prior capture (needs a pkill grant; ignored if
    # denied), then launch ours tagged and pointed at the site folder.
    try:
        subprocess.run(['sudo', '-n', 'pkill', '-x', 'kismet'],
                       capture_output=True, timeout=8)
        time.sleep(2)
    except Exception:
        pass
    try:
        lf = open(os.path.join(BASE, 'kismet_launch.log'), 'ab')
        subprocess.Popen(
            ['sudo', '-n', 'kismet', '-c', mon, '--no-ncurses',
             '--log-prefix', kismet_prefix, '--log-title', KISMET_TAG],
            stdout=lf, stderr=lf, stdin=subprocess.DEVNULL,
            start_new_session=True)
        lf.close()
    except Exception as e:
        return jsonify({'success': False, 'error': 'spawn failed: %s' % e}), 500
    return jsonify({'success': True, 'interface': mon,
                    'log_prefix': kismet_prefix})


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
    pattern = _site_kismet_glob()
    db = kismet_db.open_db(pattern)
    session = _session.load()
    ap_macs = session.get('selected_aps', [])
    all_aps = net_validation.list_aps(db)
    ap_set = {m.upper() for m in ap_macs}
    aps = [a for a in all_aps if a['mac'].upper() in ap_set]
    clients = net_validation.list_clients(db, ap_macs)

    capture = kismet_db.resolve_db_path(pattern)
    meta = {'generated_ts': int(time.time()),
            'capture': os.path.basename(capture) if capture else None}
    if _active_site:
        meta.update({k: _active_site.get(k) for k in
                     ('case_number', 'site_name', 'location', 'examiner',
                      'created', 'last_sweep')})
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
    # Auto-populate from the active site's metadata when not supplied.
    if _active_site:
        case = case or _active_site.get('case_number', '')
        examiner = examiner or _active_site.get('examiner', '')

    pattern = _site_kismet_glob()
    db = kismet_db.open_db(pattern)
    session = _session.load()
    baseline = _baseline.get_all()
    capture = kismet_db.resolve_db_path(pattern)
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
    lost, reset the working files to empty, and auto-launch a fresh dual-band
    Kismet capture via the scoped NOPASSWD sudoers rule. If that grant is
    missing (older install), the returned start_command lets the examiner run
    it manually."""
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
    launched, kismet_status = _launch_kismet()
    return jsonify({
        'ok': True,
        'archived_to': os.path.basename(archived) if archived else None,
        'start_command': 'sudo bash %s/start_kismet.sh' % BASE,
        'kismet_launched': launched,
        'kismet_launch': kismet_status,
    })


@app.route('/api/kismet/start', methods=['POST'])
def api_kismet_start():
    """Launch the dual-band capture on demand without clearing any data. Used by
    the RESUME path when a prior capture is no longer running. Idempotent:
    returns already_running if Kismet is already up."""
    launched, kismet_status = _launch_kismet()
    return jsonify({
        'ok': launched,
        'kismet_launch': kismet_status,
        'start_command': 'sudo bash %s/start_kismet.sh' % BASE,
    })


if __name__ == '__main__':
    print('\n  DSG TSCM Triage v1.8.5 — Flask Server')
    print('  http://127.0.0.1:5555')
    print('  Cases path: %s%s\n' % (CASES_PATH, '' if CASES_IS_DEFAULT else '  (external)'))
    # threaded: the Kismet launch briefly blocks its request while it confirms
    # the capture stayed up, so serve other requests concurrently.
    app.run(host='127.0.0.1', port=5555, debug=False, threaded=True)
