"""
Grimoire - Security Log Analyzer
By Wizardwerks Enterprise Labs

Companion tool to Spellcastr. Analyzes Windows Event Logs for security
threats, failed logins, privilege escalation, and suspicious activity.

Usage:
    Run as Administrator for live log access:
    python app.py
"""

from flask import Flask, render_template, request, jsonify
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'grimoire-wizardwerks-secret'
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB max upload

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/live', methods=['GET'])
def live_logs():
    """Read live Windows Event Logs from the local machine."""
    from utils.reader import read_live_logs
    log_type   = request.args.get('log', 'Security')
    max_events = int(request.args.get('max', 500))
    try:
        events = read_live_logs(log_type, max_events)
        return jsonify({'status': 'ok', 'events': events})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
def upload_log():
    """Accept an uploaded .evtx file and analyze it."""
    from utils.reader import read_evtx_file
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename.endswith('.evtx'):
        return jsonify({'status': 'error', 'message': 'Only .evtx files are supported'}), 400
    path = os.path.join(UPLOAD_FOLDER, f.filename)
    f.save(path)
    try:
        from utils.reader import read_evtx_file
        events = read_evtx_file(path)
        return jsonify({'status': 'ok', 'events': events, 'filename': f.filename})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Run threat analysis on a provided event list."""
    from utils.analyzer import analyze_events
    data   = request.get_json()
    events = data.get('events', [])
    try:
        results = analyze_events(events)
        return jsonify({'status': 'ok', 'results': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("""
  ╔══════════════════════════════════════════╗
  ║   GRIMOIRE — Wizardwerks Ent. Labs      ║
  ║   Security Log Analyzer                  ║
  ║   http://127.0.0.1:5001                  ║
  ╚══════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5001, debug=False)
