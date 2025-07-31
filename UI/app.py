from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
import os
import json
import traceback
import glob
from datetime import datetime
from pathlib import Path
from security_scanner import SecurityScanner
from pdf_generator import PDFReportGenerator
from dotenv import load_dotenv
import threading
import time

# Charger les variables d'environnement AVANT tout le reste
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-key-change-in-production')

# Configuration depuis .env
TEMP_FOLDER = os.getenv('TEMP_FOLDER', 'temp_repos')
RESULTS_FOLDER = os.getenv('RESULTS_FOLDER', 'results')
LOGS_FOLDER = os.getenv('LOGS_FOLDER', 'logs')
SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', '300'))

# Créer les dossiers nécessaires
for folder in [TEMP_FOLDER, RESULTS_FOLDER, LOGS_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(f"✓ Dossier {folder} créé")

ALLOWED_EXTENSIONS = {'.py', '.js', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.cs'}

print(f"🔧 Configuration Flask:")
print(f"   - Dossier temp: {TEMP_FOLDER}")
print(f"   - Dossier résultats: {RESULTS_FOLDER}")
print(f"   - Timeout scan: {SCAN_TIMEOUT}s")

# Dictionnaire global pour stocker les progressions
scan_progress_data = {}

def update_scan_progress(scan_id: str, step: str, progress: int, details: dict = None):
    """Met à jour le progrès d'un scan"""
    scan_progress_data[scan_id] = {
        'step': step,
        'progress': progress,
        'timestamp': time.time(),
        'details': details or {}
    }

@app.route('/')
def index():
    """Page d'accueil avec formulaire de saisie"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_repository():
    """Lance l'analyse de sécurité avec suivi de progression"""
    try:
        scan_type = request.form.get('scan_type')
        
        # Récupérer la cible selon le type de scan
        if scan_type == 'github':
            target = request.form.get('target')
        elif scan_type == 'local':
            target = request.form.get('local_path')
            # Si local_path est vide, essayer target comme fallback
            if not target:
                target = request.form.get('target')
        else:
            target = request.form.get('target')
        
        print(f"🔄 Nouvelle demande de scan: {scan_type} - {target}")
        
        # Validation améliorée
        if not target or target.strip() == '':
            error_msg = 'Please specify a target (GitHub URL or local folder path)'
            print(f"❌ {error_msg}")
            return render_template('error.html', error=error_msg), 400
        
        target = target.strip()
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Initialiser le progrès
        update_scan_progress(scan_id, 'initializing', 5, {'target': target})
        
        # Validation spécifique selon le type
        if scan_type == 'github':
            if not (target.startswith('https://github.com/') or target.startswith('http://github.com/')):
                error_msg = 'Please enter a valid GitHub repository URL (https://github.com/user/repo)'
                print(f"❌ {error_msg}")
                return render_template('error.html', error=error_msg), 400
        elif scan_type == 'local':
            # Amélioration pour les chemins Windows
            # Normaliser les chemins pour Windows
            if '\\' in target or ':' in target:
                # Chemin Windows
                normalized_path = os.path.normpath(target)
            else:
                # Chemin Unix/relatif
                normalized_path = target
            
            # Vérifier l'existence avec plusieurs variantes
            possible_paths = [
                normalized_path,
                os.path.abspath(normalized_path),
                os.path.expanduser(normalized_path)
            ]
            
            path_exists = False
            actual_path = None
            
            for path in possible_paths:
                if os.path.exists(path) and os.path.isdir(path):
                    path_exists = True
                    actual_path = path
                    target = actual_path  # Utiliser le chemin qui fonctionne
                    break
            
            if not path_exists:
                # Messages d'erreur plus détaillés
                paths_tried = '<br>'.join([f'• {p}' for p in possible_paths])
                error_details = f"""
                <div class="space-y-4">
                    <p class="text-lg font-semibold">Local folder not found: <code class="bg-red-100 px-2 py-1 rounded">{target}</code></p>
                    
                    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
                        <h4 class="font-semibold text-yellow-800 mb-2">Troubleshooting suggestions:</h4>
                        <ul class="list-disc list-inside space-y-1 text-sm text-yellow-700">
                            <li>Make sure the folder path exists and is accessible</li>
                            <li>Try using the full absolute path (e.g., <code>C:\\Users\\nadia\\Documents\\GitHub\\AI_experiments\\fine-tuning</code>)</li>
                            <li>Check folder permissions</li>
                            <li>Use forward slashes (/) instead of backslashes (\\)</li>
                            <li>Verify there are no typos in the path</li>
                        </ul>
                    </div>
                    
                    <div class="bg-blue-50 border-l-4 border-blue-400 p-4">
                        <h4 class="font-semibold text-blue-800 mb-2">Alternative methods:</h4>
                        <ul class="list-disc list-inside space-y-1 text-sm text-blue-700">
                            <li>Use the folder picker button in the interface</li>
                            <li>Drag and drop the folder (if supported by your browser)</li>
                            <li>Copy the path from File Explorer</li>
                        </ul>
                    </div>
                    
                    <div class="bg-gray-50 border border-gray-200 rounded p-3">
                        <p class="text-sm text-gray-600">
                            <strong>Paths tried:</strong><br>
                            {paths_tried}
                        </p>
                    </div>
                </div>
                """
                print(f"❌ Local folder not found: {target}")
                print(f"   Tried paths: {possible_paths}")
                return render_template('error.html', error=error_details), 400
        
        # Capturer le contexte de l'application pour le thread
        app_context = app.app_context()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Lancer l'analyse dans un thread séparé
        def run_analysis():
            with app_context:
                try:
                    update_scan_progress(scan_id, 'scanner_init', 10)
                    scanner = SecurityScanner(progress_callback=lambda step, progress, details: 
                                             update_scan_progress(scan_id, step, progress, details))
                    
                    print(f"🚀 Lancement du scan {scan_type} sur: {target}")
                    
                    if scan_type == 'github':
                        results = scanner.scan_github_repo(target)
                    else:
                        results = scanner.scan_local_directory(target)
                    
                    if 'error' not in results:
                        # Sauvegarder les résultats
                        results_file = f'{RESULTS_FOLDER}/scan_{scan_id}.json'
                        results['scan_metadata'] = {
                            'scan_id': scan_id,
                            'scan_type': scan_type,
                            'target': target,
                            'timestamp': datetime.now().isoformat(),
                            'user_agent': user_agent
                        }
                        
                        with open(results_file, 'w', encoding='utf-8') as f:
                            json.dump(results, f, indent=2, ensure_ascii=False)
                        
                        update_scan_progress(scan_id, 'complete', 100, {'results_ready': True})
                        print(f"✓ Scan completed, results saved: {results_file}")
                    else:
                        update_scan_progress(scan_id, 'error', 0, {'error': results['error']})
                        
                except Exception as e:
                    error_msg = f'Scan error: {str(e)}'
                    update_scan_progress(scan_id, 'error', 0, {'error': error_msg})
                    print(f"❌ {error_msg}")
                    print(f"Stack trace: {traceback.format_exc()}")
        
        # Démarrer le thread d'analyse
        analysis_thread = threading.Thread(target=run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
        
        # Rediriger vers la page de progression
        return redirect(url_for('scan_progress_page', scan_id=scan_id))
        
    except Exception as e:
        error_msg = f'Scan error: {str(e)}'
        print(f"❌ {error_msg}")
        print(f"Stack trace: {traceback.format_exc()}")
        return render_template('error.html', error=error_msg), 500

@app.route('/scan/progress/<scan_id>')
def scan_progress_page(scan_id):
    """Page de progression du scan"""
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/api/scan/progress/<scan_id>')
def get_scan_progress(scan_id):
    """API pour récupérer le progrès du scan"""
    if scan_id in scan_progress_data:
        progress_data = scan_progress_data[scan_id]
        
        # Vérifier si le scan est terminé
        if progress_data['step'] == 'complete':
            # Construire l'URL manuellement pour éviter le problème de contexte
            redirect_url = f'/results/{scan_id}'
            return jsonify({
                **progress_data,
                'redirect_url': redirect_url
            })
        elif progress_data['step'] == 'error':
            return jsonify(progress_data)
        
        return jsonify(progress_data)
    
    return jsonify({
        'step': 'not_found',
        'progress': 0,
        'details': {'error': 'Scan not found'}
    }), 404

@app.route('/results/<scan_id>')
def results(scan_id):
    """Affiche les résultats du scan"""
    try:
        results_file = f'{RESULTS_FOLDER}/scan_{scan_id}.json'
        
        if not os.path.exists(results_file):
            return render_template('error.html', error='Résultats non trouvés'), 404
        
        with open(results_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        return render_template('results.html', results=results, scan_id=scan_id)
        
    except Exception as e:
        return render_template('error.html', error=f'Erreur: {str(e)}'), 500

@app.route('/history')
def scan_history():
    """Affiche l'historique des scans"""
    try:
        page = int(request.args.get('page', 1))
        per_page = 12
        
        # Lister tous les fichiers de résultats
        result_files = glob.glob(f'{RESULTS_FOLDER}/scan_*.json')
        result_files.sort(key=os.path.getmtime, reverse=True)
        
        # Pagination
        total_scans = len(result_files)
        total_pages = (total_scans + per_page - 1) // per_page
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        scans = []
        for file_path in result_files[start_idx:end_idx]:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    scan_data = json.load(f)
                
                # Extraire les informations de base
                scan_id = Path(file_path).stem.replace('scan_', '')
                summary = scan_data.get('summary', {})
                
                # Nom de la cible (raccourci)
                target = summary.get('target', 'Unknown')
                if target.startswith('https://github.com/'):
                    target_name = target.split('/')[-1]
                else:
                    target_name = Path(target).name if target else 'Local Folder'
                
                scan_info = {
                    'scan_id': scan_id,
                    'target_name': target_name,
                    'security_score': summary.get('security_score', 0),
                    'date': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M'),
                    'source': scan_data.get('source', {}),
                    **summary.get('severity_breakdown', {})
                }
                
                scans.append(scan_info)
                
            except Exception as e:
                print(f"Erreur lecture scan {file_path}: {str(e)}")
                continue
        
        return render_template('history.html', 
                               scans=scans,
                               current_page=page,
                               total_pages=total_pages,
                               total_scans=total_scans)
        
    except Exception as e:
        return render_template('error.html', error=f'Error loading history: {str(e)}'), 500

@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Supprime un scan de l'historique"""
    try:
        results_file = f'{RESULTS_FOLDER}/scan_{scan_id}.json'
        
        if os.path.exists(results_file):
            os.remove(results_file)
            return jsonify({'success': True, 'message': 'Scan deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/export/<scan_id>/<format>')
def export_results(scan_id, format):
    """Exporte les résultats en différents formats"""
    try:
        results_file = f'{RESULTS_FOLDER}/scan_{scan_id}.json'
        
        if not os.path.exists(results_file):
            return jsonify({'error': 'Results not found'}), 404
        
        with open(results_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        if format == 'json':
            return jsonify(results)
        elif format == 'pdf':
            # Générer le PDF
            pdf_generator = PDFReportGenerator()
            pdf_path = f'temp/report_{scan_id}.pdf'
            
            # Créer le dossier temp s'il n'existe pas
            os.makedirs('temp', exist_ok=True)
            
            if pdf_generator.generate_pdf_report(results, pdf_path):
                return send_file(pdf_path, 
                               mimetype='application/pdf',
                               as_attachment=True,
                               download_name=f'security_report_{scan_id}.pdf')
            else:
                return jsonify({'error': 'Failed to generate PDF'}), 500
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        print(f"Export error: {str(e)}")
        return jsonify({'error': f'Export error: {str(e)}'}), 500

if __name__ == '__main__':
    # Configuration depuis .env
    debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', '5000'))
    
    print(f"🚀 Démarrage Flask - Debug: {debug_mode}, Host: {host}, Port: {port}")
    app.run(debug=debug_mode, host=host, port=port)
