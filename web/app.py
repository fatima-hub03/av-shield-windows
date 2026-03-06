from flask import send_from_directory
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import subprocess
import sqlite3
import json
import os

app = Flask(__name__)
CORS(app)

# Chemins
# Chemins (robustes, basés sur l'emplacement du fichier)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(ROOT_DIR, "database", "avshield.db")
QUARANTINE_DIR = os.path.join(ROOT_DIR, "quarantine")
REPORTS_DIR = os.path.join(ROOT_DIR, "reports")
AVSHIELD_BIN = os.path.join(ROOT_DIR, "avshield")
# ============================================
#   FONCTION UTILITAIRE — BASE DE DONNÉES
# ============================================
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

# ============================================
#   PAGE PRINCIPALE — DASHBOARD
# ============================================
@app.route('/')
def index():
    try:
        db = get_db()
        stats = {
            'total_scans'     : db.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            'total_threats'   : db.execute("SELECT COUNT(*) FROM threats").fetchone()[0],
            'total_quarantine': db.execute("SELECT COUNT(*) FROM quarantine WHERE restored=0").fetchone()[0],
            'total_clean'     : db.execute("SELECT SUM(clean_files) FROM scans").fetchone()[0] or 0
        }
        scans = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
        threats = db.execute("SELECT * FROM threats ORDER BY id DESC LIMIT 5").fetchall()
        db.close()
        return render_template('index.html', stats=stats, scans=scans, threats=threats)
    except Exception as e:
        return render_template('index.html', stats={'total_scans':0,'total_threats':0,'total_quarantine':0,'total_clean':0}, scans=[], threats=[])

# ============================================
#   PAGE SCAN
# ============================================
@app.route('/scan')
def scan_page():
    return render_template('scan.html')

# ============================================
#   API — LANCER UN SCAN
# ============================================
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()

    if not data or 'path' not in data:
        return jsonify({'error': 'Chemin manquant'}), 400

    path = data['path'].strip()
    auto = bool(data.get('auto', False))
    want_json = bool(data.get('report', False))   # checkbox "Générer rapport JSON"
    want_html = bool(data.get('html', False))     # checkbox "Générer rapport HTML"

    # Vérifier que le chemin existe
    if not os.path.exists(path):

        # vérifier si le fichier est déjà en quarantaine
        filename = os.path.basename(path)
        if os.path.exists("quarantine"):
            for f in os.listdir("quarantine"):
                if filename in f:
                    return jsonify({
                         "success": True,
                         "message": "Fichier déjà isolé en quarantaine",
                         "quarantine_file": f
                    })

        return jsonify({'error': f'Chemin introuvable: {path}'}), 400

    # Vérifier que le binaire existe
    if not os.path.exists(AVSHIELD_BIN):
        return jsonify({'error': f'Binaire introuvable: {AVSHIELD_BIN}'}), 500

    # Construire la commande
    cmd = [AVSHIELD_BIN, 'scan', path]

    # Toujours générer le rapport JSON pour afficher les détails
    cmd.append('--report')

    # Ne pas passer --html au binaire pour éviter d'écraser --report JSON
    # Le rapport HTML sera cherché séparément
    # if want_html:
    #     cmd.append('--html')

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )
        import time
        time.sleep(1.5)
        report_json = None
        report_json_path = None
        report_html_path = None

        # Chercher le dernier JSON si demandé
        if want_json:
            json_reports = [
                os.path.join(REPORTS_DIR, f)
                for f in os.listdir(REPORTS_DIR)
                if f.startswith("RPT_") and f.endswith(".json")
            ]
            if json_reports:
                report_json_path = max(json_reports, key=os.path.getmtime)
                try:
                    with open(report_json_path, "r") as f:
                        report_json = json.load(f)
                except Exception:
                    report_json = None

        # Chercher le dernier HTML si demandé
        if want_html:
            html_reports = [
                os.path.join(REPORTS_DIR, f)
                for f in os.listdir(REPORTS_DIR)
                if f.startswith("RPT_") and f.endswith(".html")
            ]
            if html_reports:
                report_html_path = max(html_reports, key=os.path.getmtime)

        import re as _re
        import time
        time.sleep(1.5)
        json_path = None
        json_file = None
        _output_clean = _re.sub(r'\x1b\[[0-9;]*m', '', result.stdout + result.stderr)
        # Chercher rapport JSON dans stdout
        _match = _re.search(r'(RPT_\d+_\d+)\.json', _output_clean)
        if not _match:
            # Chercher depuis rapport HTML (meme nom base)
            _match_html = _re.search(r'(RPT_\d+_\d+)\.html', _output_clean)
            if _match_html:
                _match = _match_html
        if _match:
            json_file = _match.group(1) + '.json'
            json_path = os.path.join(REPORTS_DIR, json_file)



        # Trouver dernier HTML
        html_path = None
        html_file = None
        html_reports = [
            f for f in os.listdir(REPORTS_DIR)
            if f.startswith("RPT_") and f.endswith(".html")
        ]
        if html_reports:
            html_path = max(
                (os.path.join(REPORTS_DIR, f) for f in html_reports),
                key=os.path.getmtime
            )
            html_file = os.path.basename(html_path)

        # Chercher si le fichier a été mis en quarantaine (par basename)
        quarantined = False
        quarantine_file = None
        base = os.path.basename(path)

        if os.path.exists(QUARANTINE_DIR):
            for f in os.listdir(QUARANTINE_DIR):
                if f.endswith(".quar") and base in f:
                    quarantined = True
                    quarantine_file = f
                    break

        # Lire le contenu JSON si disponible
        report_data = None
        if json_path and os.path.exists(json_path):
            try:
                with open(json_path, "r") as f:
                    report_data = json.load(f)
            except Exception:
                report_data = None

        return jsonify({
            "success": True,
            "output": result.stdout,
            "errors": result.stderr,
            "quarantined": quarantined,
            "quarantine_file": quarantine_file,
            "report_json_file": json_file,
            "report_html_file": html_file,
            "report_json_url": f"/reports/download/{json_file}" if json_file else None,
            "report_html_url": f"/reports/{html_file}" if html_file else None,
            "report": report_data
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timeout (5 min)"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500
  

# ============================================
#   PAGE QUARANTAINE
# ============================================
@app.route('/reports-page')
def reports_page():
    return render_template('reports.html')

@app.route('/quarantine')
def quarantine_page():
    try:
        db = get_db()
        files = db.execute(
            "SELECT * FROM quarantine WHERE restored=0 ORDER BY id DESC"
        ).fetchall()
        db.close()
        return render_template('quarantine.html', files=files)
    except:
        return render_template('quarantine.html', files=[])

# ============================================
#   API — LISTE QUARANTAINE
# ============================================
@app.route('/api/quarantine', methods=['GET'])
def api_quarantine_list():
    try:
        db = get_db()
        files = db.execute(
            "SELECT * FROM quarantine WHERE restored=0"
        ).fetchall()
        db.close()
        return jsonify([dict(f) for f in files])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
#   API — RESTAURER UN FICHIER
# ============================================
@app.route('/api/quarantine/restore', methods=['POST'])
def api_restore():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Nom manquant'}), 400

    try:
        result = subprocess.run(
            [AVSHIELD_BIN, 'quarantine', 'restore', data['name']],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )
        return jsonify({'success': True, 'output': result.stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
#   API — SUPPRIMER DE LA QUARANTAINE
# ============================================
@app.route('/api/quarantine/delete', methods=['POST'])
def api_delete():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Nom manquant'}), 400

    try:
        result = subprocess.run(
            [AVSHIELD_BIN, 'quarantine', 'delete', data['name']],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.abspath(AVSHIELD_BIN))
        )
        return jsonify({'success': True, 'output': result.stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
#   API — STATISTIQUES
# ============================================
@app.route('/api/stats', methods=['GET'])
def api_stats():
    try:
        db = get_db()
        stats = {
            'total_scans'     : db.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            'total_threats'   : db.execute("SELECT COUNT(*) FROM threats").fetchone()[0],
            'total_quarantine': db.execute("SELECT COUNT(*) FROM quarantine WHERE restored=0").fetchone()[0],
            'total_clean'     : db.execute("SELECT SUM(clean_files) FROM scans").fetchone()[0] or 0,
            'total_malware'   : db.execute("SELECT SUM(malware_files) FROM scans").fetchone()[0] or 0,
            'total_suspicious': db.execute("SELECT SUM(suspicious_files) FROM scans").fetchone()[0] or 0
        }
        db.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
#   API — HISTORIQUE
# ============================================
@app.route('/api/history', methods=['GET'])
def api_history():
    try:
        db = get_db()
        scans = db.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 20"
        ).fetchall()
        db.close()
        return jsonify([dict(s) for s in scans])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
#   API — RAPPORTS
# ============================================
@app.route('/api/reports', methods=['GET'])
def api_reports():
    try:
        reports = []
        if os.path.exists(REPORTS_DIR):
            for f in os.listdir(REPORTS_DIR):
                reports.append({
                    'name': f,
                    'path': os.path.join(REPORTS_DIR, f),
                    'size': os.path.getsize(os.path.join(REPORTS_DIR, f))
                })
        return jsonify(reports)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#============================================
@app.route("/reports/<path:filename>")
def open_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@app.route("/reports/download/<path:filename>")
def download_report(filename):
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)

# ============================================
#   DÉMARRAGE
# ============================================
if __name__ == '__main__':
    print("\n🛡️  AV-Shield Web Interface")
    print("=" * 40)
    print("URL: http://localhost:5000")
    print("=" * 40 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
