#!/usr/bin/env python3
"""
DSG TSCM Triage v1.7.0 — Local Flask Server
Surveillance Specialist Group, LLC
Run: python3 ~/dsg-tscm/server.py
Access: http://127.0.0.1:5555
"""
import os, re, socket, subprocess
from flask import Flask, send_file, jsonify

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))

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
    print('\n  DSG TSCM Triage v1.7.0 — Flask Server')
    print('  http://127.0.0.1:5555\n')
    app.run(host='127.0.0.1', port=5555, debug=False)
