#!/usr/bin/env python3
"""
DSG TSCM Triage v1.8.2 — Local Flask Server
Surveillance Specialist Group, LLC
Run: python3 ~/dsg-tscm/server.py
Access: http://127.0.0.1:5555
"""
import os, re, socket, subprocess, datetime, platform
from flask import Flask, send_file, jsonify, request

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
RUN_LOG = os.path.expanduser('~/DSG-TSCM/run_log.txt')

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

if __name__ == '__main__':
    print('\n  DSG TSCM Triage v1.8.2 — Flask Server')
    print('  http://127.0.0.1:5555')
    print('  Cases path: %s%s\n' % (CASES_PATH, '' if CASES_IS_DEFAULT else '  (external)'))
    app.run(host='127.0.0.1', port=5555, debug=False)
