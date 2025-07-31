import os
import ast
import re
import json
import git
import shutil
import stat
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Import mis à jour pour éviter la dépréciation
try:
    from langchain_ollama import OllamaLLM
except ImportError:
    # Fallback pour les anciennes versions
    from langchain.llms import Ollama as OllamaLLM

from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from scanner.prompts import SecurityPrompts

class SecurityScanner:
    def __init__(self, progress_callback=None):
        try:
            # Utiliser les variables d'environnement
            ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
            primary_model = os.getenv('OLLAMA_MODEL_PRIMARY', 'llama3.2:latest')
            max_workers = int(os.getenv('MAX_CONCURRENT_SCANS', '2'))
            max_file_size = int(os.getenv('MAX_FILE_SIZE', '1048576'))
            
            print(f"🔧 Configuration:")
            print(f"   - URL Ollama: {ollama_base_url}")
            print(f"   - Model: {primary_model}")
            print(f"   - Workers max: {max_workers}")
            print(f"   - Max file size: {max_file_size} bytes")
            
            # Initialiser le modèle avec la configuration
            self.llm = OllamaLLM(model=primary_model, base_url=ollama_base_url)
            self.prompts = SecurityPrompts()
            self.vulnerabilities = []
            self.max_workers = max_workers
            self.max_file_size = max_file_size
            self.supported_extensions = {'.py', '.js', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.cs'}
            self.progress_callback = progress_callback
            
        except Exception as e:
            print(f"❌ Erreur initialisation du scanner: {str(e)}")
            raise
    
    def _update_progress(self, step: str, progress: int, details: dict = None):
        """Met à jour le progrès si un callback est défini"""
        if self.progress_callback:
            self.progress_callback(step, progress, details or {})
        
    def _remove_readonly(self, func, path, _):
        """Supprime l'attribut lecture seule et supprime le fichier"""
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    def _safe_rmtree(self, path):
        """Supprime un dossier de manière sécurisée sur Windows"""
        try:
            if os.path.exists(path):
                # Sur Windows, certains fichiers Git peuvent être en lecture seule
                shutil.rmtree(path, onerror=self._remove_readonly)
        except Exception as e:
            print(f"⚠️ Warning: Could not completely clean temp folder: {str(e)}")

    def scan_github_repo(self, repo_url: str) -> Dict[str, Any]:
        """Analyse un dépôt GitHub public"""
        local_path = None
        try:
            # Cloner le dépôt
            repo_name = repo_url.split('/')[-1].replace('.git', '')
            local_path = f"temp_repos/{repo_name}"
            
            # Nettoyer le dossier s'il existe déjà
            self._safe_rmtree(local_path)
            
            # Créer le dossier parent s'il n'existe pas
            os.makedirs("temp_repos", exist_ok=True)
            
            git.Repo.clone_from(repo_url, local_path)
            
            # Analyser le dépôt local
            results = self.scan_local_directory(local_path)
            results['source'] = {'type': 'github', 'url': repo_url}
            
            return results
            
        except git.exc.GitError as e:
            return {'error': f'Git Error: {str(e)}. Verify the URL is correct and the repository is public.'}
        except Exception as e:
            return {'error': f'GitHub scan error: {str(e)}'}
        finally:
            # Nettoyer le dossier temporaire dans tous les cas
            if local_path:
                self._safe_rmtree(local_path)

    def scan_local_directory(self, directory_path: str) -> Dict[str, Any]:
        """Analyse un dossier local avec suivi de progression"""
        try:
            self._update_progress('collecting', 15, {'target': directory_path})
            
            directory_path = Path(directory_path)
            if not directory_path.exists():
                return {'error': f'Dossier non trouvé: {directory_path}'}
            
            # Collecter les fichiers
            code_files = self._collect_code_files(directory_path)
            files_count = len(code_files)
            
            self._update_progress('file_collection', 25, {
                'files_found': files_count,
                'target': str(directory_path)
            })
            
            if not code_files:
                return {'error': 'Aucun fichier de code supporté trouvé'}
            
            # Analyser les fichiers
            vulnerabilities = []
            
            self._update_progress('static_analysis', 35, {
                'files_found': files_count
            })
            
            # Analyse séquentielle pour éviter les problèmes de threading
            for i, file_path in enumerate(code_files):
                try:
                    # Mettre à jour le progrès pour ce fichier
                    files_analyzed = i + 1
                    progress = 35 + int((files_analyzed / files_count) * 30)  # 35-65%
                    
                    self._update_progress('ai_analysis', progress, {
                        'files_analyzed': files_analyzed,
                        'total_files': files_count,
                        'current_file': file_path.name,
                        'vulnerabilities_found': len(vulnerabilities)
                    })
                    
                    # Analyser le fichier
                    file_vulns = self._analyze_file_with_progress(file_path, i, files_count)
                    vulnerabilities.extend(file_vulns)
                    
                except Exception as e:
                    vulnerabilities.append({
                        'type': 'analysis_error',
                        'file': str(file_path),
                        'message': f'Erreur lors de l\'analyse: {str(e)}',
                        'severity': 'low'
                    })
            
            # Analyser les dépendances
            self._update_progress('dependency_check', 75, {
                'vulnerabilities_found': len(vulnerabilities)
            })
            
            dependency_vulns = self._analyze_dependencies(directory_path)
            vulnerabilities.extend(dependency_vulns)
            
            # Générer le rapport
            self._update_progress('generating_report', 90, {
                'vulnerabilities_found': len(vulnerabilities)
            })
            
            report = self._generate_report(vulnerabilities, directory_path)
            
            self._update_progress('complete', 100, {
                'vulnerabilities_found': len(vulnerabilities),
                'security_score': report.get('summary', {}).get('security_score', 0)
            })
            
            return report
            
        except Exception as e:
            error_msg = f'Erreur scan local: {str(e)}'
            self._update_progress('error', 0, {'error': error_msg})
            return {'error': error_msg}
    
    def _collect_code_files(self, directory: Path) -> List[Path]:
        """Collecte tous les fichiers de code à analyser"""
        code_files = []
        
        for file_path in directory.rglob('*'):
            if (file_path.is_file() and 
                file_path.suffix in self.supported_extensions and
                not self._is_excluded_path(file_path)):
                code_files.append(file_path)
        
        return code_files
    
    def _is_excluded_path(self, file_path: Path) -> bool:
        """Vérifie si le chemin doit être exclu"""
        excluded_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'build', 'dist'}
        
        for part in file_path.parts:
            if part in excluded_dirs:
                return True
        
        return False
    
    def _analyze_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyse un fichier pour détecter les vulnérabilités"""
        vulnerabilities = []
        
        try:
            # Vérifier la taille du fichier
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return [{
                    'type': 'file_too_large',
                    'file': str(file_path),
                    'message': f'Fichier trop volumineux ({file_size} bytes)',
                    'severity': 'low'
                }]
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Analyse par règles statiques
            static_vulns = self._static_analysis(file_path, content)
            vulnerabilities.extend(static_vulns)
            
            # Analyse par IA
            ai_vulns = self._ai_analysis(file_path, content)
            vulnerabilities.extend(ai_vulns)
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'error',
                'file': str(file_path),
                'message': f'Erreur lecture fichier: {str(e)}',
                'severity': 'low'
            })
        
        return vulnerabilities
    
    def _analyze_file_with_progress(self, file_path: Path, file_index: int, total_files: int) -> List[Dict[str, Any]]:
        """Analyse un fichier avec mise à jour du progrès"""
        vulnerabilities = []
        
        try:
            # Vérifier la taille du fichier
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return [{
                    'type': 'file_too_large',
                    'file': str(file_path),
                    'message': f'Fichier trop volumineux ({file_size} bytes)',
                    'severity': 'low'
                }]
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Analyse par règles statiques (rapide)
            static_vulns = self._static_analysis(file_path, content)
            vulnerabilities.extend(static_vulns)
            
            # Analyse par IA (plus lente)
            ai_vulns = self._ai_analysis(file_path, content)
            vulnerabilities.extend(ai_vulns)
            
            # Ajouter le contexte de code pour les vulnérabilités
            for vuln in vulnerabilities:
                if 'line' in vuln and vuln['line']:
                    vuln['code_context'] = self._get_code_context(content, vuln['line'])
            
        except Exception as e:
            error_msg = f'Erreur lecture fichier: {str(e)}'
            vulnerabilities.append({
                'type': 'file_error',
                'file': str(file_path),
                'message': error_msg,
                'severity': 'low'
            })
        
        return vulnerabilities
    
    def _get_code_context(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Récupère le contexte de code autour d'une ligne"""
        lines = content.split('\n')
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)
        
        context_lines_list = []
        for i in range(start_line, end_line):
            line_content = lines[i]
            # Marquer la ligne problématique
            if i == line_number - 1:
                context_lines_list.append(f">>> {line_content}")
            else:
                context_lines_list.append(f"    {line_content}")
        
        return '\n'.join(context_lines_list)
    
    def _static_analysis(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Analyse statique avec des règles prédéfinies"""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Patterns de vulnérabilités communes
        patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*\%.*["\']',
                r'query\s*\(\s*["\'].*\+.*["\']',
                r'WHERE.*=.*\+',
            ],
            'xss': [
                r'innerHTML\s*=.*\+',
                r'document\.write\s*\(.*\+',
                r'eval\s*\(',
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api_key\s*=\s*["\'][^"\']{10,}["\']',
                r'secret\s*=\s*["\'][^"\']{8,}["\']',
            ],
            'insecure_crypto': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\s*\(',
            ]
        }
        
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'file': str(file_path),
                            'line': line_num,
                            'code': line.strip(),
                            'severity': self._get_severity(vuln_type),
                            'description': self._get_description(vuln_type)
                        })
        
        return vulnerabilities
    
    def _ai_analysis(self, file_path: Path, content: str) -> List[Dict[str, Any]]:
        """Analyse par IA avec LangChain - version robuste"""
        try:
            # Limiter la taille du contenu pour éviter les timeouts
            max_content_size = min(1000, self.max_file_size // 4)
            if len(content) > max_content_size:
                content = content[:max_content_size] + "\n... (truncated for analysis)"
            
            # Créer le prompt et analyser avec la nouvelle API LangChain
            prompt = PromptTemplate(
                input_variables=["code", "filename"],
                template=self.prompts.get_security_analysis_prompt()
            )
            
            # Utiliser la nouvelle API LangChain (sans warnings de dépréciation)
            try:
                # Nouvelle méthode recommandée : prompt | llm
                chain = prompt | self.llm
                response = chain.invoke({
                    "code": content, 
                    "filename": file_path.name
                })
                
                # Parser la réponse
                return self._parse_ai_response(response, file_path)
                
            except Exception as llm_error:
                # Retourner une analyse vide plutôt qu'une erreur pour ne pas bloquer
                return []
            
        except Exception as e:
            return []
    
    def _parse_ai_response(self, response: str, file_path: Path) -> List[Dict[str, Any]]:
        """Parse la réponse de l'IA"""
        vulnerabilities = []
        
        try:
            # Gestion de la réponse "pas de vulnérabilités"
            if "NO_VULNERABILITIES_FOUND" in response.upper():
                return []
            
            # Parser les vulnérabilités trouvées
            lines = response.split('\n')
            current_vuln = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('TYPE:'):
                    current_vuln['type'] = line.replace('TYPE:', '').strip()
                elif line.startswith('SEVERITY:'):
                    current_vuln['severity'] = line.replace('SEVERITY:', '').strip().lower()
                elif line.startswith('DESCRIPTION:'):
                    current_vuln['description'] = line.replace('DESCRIPTION:', '').strip()
                elif line.startswith('LINE:'):
                    try:
                        current_vuln['line'] = int(line.replace('LINE:', '').strip())
                    except:
                        pass
                elif line == '---' and current_vuln:
                    current_vuln['file'] = str(file_path)
                    vulnerabilities.append(current_vuln)
                    current_vuln = {}
            
            # Ajouter la dernière vulnérabilité si pas de séparateur final
            if current_vuln and 'type' in current_vuln:
                current_vuln['file'] = str(file_path)
                vulnerabilities.append(current_vuln)
                
        except Exception as e:
            print(f"⚠️ Erreur parsing réponse IA: {str(e)}")
        
        return vulnerabilities
    
    def _analyze_dependencies(self, directory: Path) -> List[Dict[str, Any]]:
        """Analyse les dépendances pour des vulnérabilités connues"""
        vulnerabilities = []
        
        # Fichiers de dépendances à analyser
        dep_files = {
            'requirements.txt': 'python',
            'package.json': 'npm',
            'pom.xml': 'maven',
            'Gemfile': 'ruby'
        }
        
        for dep_file, ecosystem in dep_files.items():
            dep_path = directory / dep_file
            if dep_path.exists():
                try:
                    with open(dep_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Analyse simple des versions
                    if ecosystem == 'python':
                        vulns = self._analyze_python_deps(content)
                        vulnerabilities.extend(vulns)
                        
                except Exception as e:
                    vulnerabilities.append({
                        'type': 'dependency_error',
                        'file': str(dep_path),
                        'message': f'Erreur analyse dépendances: {str(e)}',
                        'severity': 'low'
                    })
        
        return vulnerabilities
    
    def _analyze_python_deps(self, content: str) -> List[Dict[str, Any]]:
        """Analyse les dépendances Python"""
        vulnerabilities = []
        
        # Packages Python connus pour avoir des vulnérabilités
        vulnerable_packages = {
            'django': ['<3.2.13', '<4.0.4'],
            'flask': ['<2.2.0'],
            'requests': ['<2.28.0'],
            'urllib3': ['<1.26.5']
        }
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if '==' in line:
                package, version = line.split('==')
                package = package.strip()
                version = version.strip()
                
                if package in vulnerable_packages:
                    vulnerabilities.append({
                        'type': 'vulnerable_dependency',
                        'package': package,
                        'version': version,
                        'severity': 'medium',
                        'description': f'Package {package} version {version} peut avoir des vulnérabilités'
                    })
        
        return vulnerabilities
    
    def _generate_report(self, vulnerabilities: List[Dict[str, Any]], directory: Path) -> Dict[str, Any]:
        """Génère le rapport final avec système de score amélioré"""
        try:
            # Compter par sévérité
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low')
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    # Gérer les sévérités inconnues
                    severity_counts['low'] += 1
            
            # Nouveau système de calcul de score plus réaliste
            total_vulns = len(vulnerabilities)
            security_score = self._calculate_enhanced_security_score(
                severity_counts, total_vulns, directory
            )
            
            # Déterminer le niveau de sécurité
            security_level = self._get_security_level(security_score)
            
            # S'assurer que tous les champs requis sont présents
            try:
                scan_date = datetime.now().isoformat()
            except Exception:
                scan_date = str(datetime.now())
            
            # Nettoyer les vulnérabilités pour éviter les problèmes de sérialisation
            cleaned_vulnerabilities = []
            for vuln in vulnerabilities:
                cleaned_vuln = {
                    'type': str(vuln.get('type', 'unknown')),
                    'severity': str(vuln.get('severity', 'low')),
                    'description': str(vuln.get('description', vuln.get('message', 'No description'))),
                    'file': str(vuln.get('file', 'unknown')),
                }
                
                # Ajouter les champs optionnels s'ils existent
                if 'line' in vuln:
                    try:
                        cleaned_vuln['line'] = int(vuln['line'])
                    except (ValueError, TypeError):
                        pass
                
                if 'code' in vuln:
                    cleaned_vuln['code'] = str(vuln['code'])[:500]  # Limiter la taille
                
                if 'code_context' in vuln:
                    cleaned_vuln['code_context'] = str(vuln['code_context'])[:1000]  # Limiter la taille
                
                cleaned_vulnerabilities.append(cleaned_vuln)
            
            report = {
                'summary': {
                    'total_vulnerabilities': total_vulns,
                    'security_score': security_score,
                    'security_level': security_level,  # Nouveau champ
                    'severity_breakdown': severity_counts,
                    'scan_date': scan_date,
                    'target': str(directory)
                },
                'vulnerabilities': cleaned_vulnerabilities,
                'recommendations': self._generate_recommendations(vulnerabilities),
                'success': True
            }
            
            return report
            
        except Exception as e:
            error_msg = f'Erreur lors de la génération du rapport: {str(e)}'
            return {
                'summary': {
                    'total_vulnerabilities': 0,
                    'security_score': 0,
                    'security_level': 'unknown',
                    'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'scan_date': datetime.now().isoformat(),
                    'target': str(directory)
                },
                'vulnerabilities': [],
                'recommendations': [],
                'error': error_msg,
                'success': False
            }
    
    def _calculate_enhanced_security_score(self, severity_counts: Dict[str, int], 
                                         total_vulns: int, directory: Path) -> int:
        """Calcule un score de sécurité plus réaliste et équitable"""
        # Score de base
        base_score = 100
        
        # Si aucune vulnérabilité, score parfait
        if total_vulns == 0:
            return base_score
        
        # Compter les fichiers analysés pour calculer la densité
        code_files_count = len(self._collect_code_files(directory))
        if code_files_count == 0:
            code_files_count = 1  # Éviter division par zéro
        
        # Nouveaux poids plus réalistes
        weights = {
            'critical': 25,    # Une vulnérabilité critique = -25 points
            'high': 15,        # Une vulnérabilité haute = -15 points  
            'medium': 8,       # Une vulnérabilité moyenne = -8 points
            'low': 3           # Une vulnérabilité basse = -3 points
        }
        
        # Calculer la pénalité de base
        base_penalty = 0
        for severity, count in severity_counts.items():
            base_penalty += count * weights[severity]
        
        # Facteur de densité : plus il y a de vulnérabilités par fichier, plus la pénalité augmente
        density_factor = total_vulns / code_files_count
        
        # Augmenter la pénalité si la densité est élevée
        if density_factor > 0.5:  # Plus d'une vulnérabilité tous les 2 fichiers
            density_multiplier = 1 + (density_factor * 0.3)  # Jusqu'à +30% de pénalité
            base_penalty = int(base_penalty * density_multiplier)
        
        # Pénalité supplémentaire pour les projets avec beaucoup de vulnérabilités critiques/hautes
        high_severity_count = severity_counts['critical'] + severity_counts['high']
        if high_severity_count > 0:
            # Pénalité progressive pour les vulnérabilités graves
            if high_severity_count >= 5:
                base_penalty += 20  # Pénalité supplémentaire pour beaucoup de vulnérabilités graves
            elif high_severity_count >= 3:
                base_penalty += 10
            elif high_severity_count >= 1:
                base_penalty += 5
        
        # Calculer le score final
        final_score = max(0, min(100, base_score - base_penalty))
        
        return final_score
    
    def _get_security_level(self, score: int) -> str:
        """Détermine le niveau de sécurité basé sur le score"""
        if score >= 90:
            return "excellent"
        elif score >= 75:
            return "good"
        elif score >= 60:
            return "acceptable"
        elif score >= 40:
            return "poor"
        elif score >= 20:
            return "critical"
        else:
            return "dangerous"
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Génère des recommandations basées sur les vulnérabilités trouvées"""
        recommendations = []
        
        vuln_types = set(vuln.get('type', '') for vuln in vulnerabilities)
        
        if 'sql_injection' in vuln_types:
            recommendations.append("Utilisez des requêtes préparées pour éviter les injections SQL")
        
        if 'xss' in vuln_types:
            recommendations.append("Validez et échappez toutes les entrées utilisateur")
        
        if 'hardcoded_secrets' in vuln_types:
            recommendations.append("Déplacez les secrets vers des variables d'environnement")
        
        if 'insecure_crypto' in vuln_types:
            recommendations.append("Utilisez des algorithmes de chiffrement sécurisés (SHA-256, AES)")
        
        return recommendations
    
    def _get_severity(self, vuln_type: str) -> str:
        """Retourne la sévérité pour un type de vulnérabilité"""
        severity_map = {
            'sql_injection': 'critical',
            'xss': 'high',
            'hardcoded_secrets': 'high',
            'insecure_crypto': 'medium',
            'vulnerable_dependency': 'medium'
        }
        
        return severity_map.get(vuln_type, 'low')
    
    def _get_description(self, vuln_type: str) -> str:
        """Retourne la description pour un type de vulnérabilité"""
        descriptions = {
            'sql_injection': 'Injection SQL potentielle détectée',
            'xss': 'Vulnérabilité XSS potentielle détectée',
            'hardcoded_secrets': 'Secret en dur détecté dans le code',
            'insecure_crypto': 'Algorithme de chiffrement non sécurisé',
            'vulnerable_dependency': 'Dépendance avec vulnérabilités connues'
        }
        
        return descriptions.get(vuln_type, 'Vulnérabilité détectée')
