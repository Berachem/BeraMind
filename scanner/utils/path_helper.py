"""
Utilitaire pour la gestion des chemins de fichiers et dossiers
"""

import os
import platform
from pathlib import Path
from typing import List, Tuple, Optional

class PathHelper:
    """Classe utilitaire pour gérer les chemins de fichiers de manière robuste"""
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalise un chemin selon l'OS"""
        if not path:
            return path
        
        # Convertir les séparateurs
        if platform.system() == 'Windows':
            # Sur Windows, accepter les deux types de séparateurs
            path = path.replace('/', os.sep)
        
        # Normaliser le chemin
        normalized = os.path.normpath(path)
        
        # Expanduser pour les chemins ~ 
        normalized = os.path.expanduser(normalized)
        
        return normalized
    
    @staticmethod
    def find_existing_path(path: str) -> Tuple[bool, Optional[str], List[str]]:
        """
        Trouve un chemin existant en essayant plusieurs variantes
        
        Returns:
            (existe, chemin_trouvé, chemins_testés)
        """
        if not path or not path.strip():
            return False, None, []
        
        original_path = path.strip()
        
        # Générer les variantes à tester
        variants = [
            original_path,
            PathHelper.normalize_path(original_path),
            os.path.abspath(original_path),
            os.path.expanduser(original_path),
        ]
        
        # Ajouter des variantes avec différents séparateurs si Windows
        if platform.system() == 'Windows':
            variants.extend([
                original_path.replace('/', '\\'),
                original_path.replace('\\', '/'),
            ])
        
        # Supprimer les doublons tout en gardant l'ordre
        tested_paths = []
        for variant in variants:
            if variant not in tested_paths:
                tested_paths.append(variant)
        
        # Tester chaque variante
        for test_path in tested_paths:
            try:
                if os.path.exists(test_path) and os.path.isdir(test_path):
                    return True, os.path.abspath(test_path), tested_paths
            except (OSError, ValueError):
                # Ignorer les erreurs de chemin invalide
                continue
        
        return False, None, tested_paths
    
    @staticmethod
    def validate_directory(path: str, check_permissions: bool = True) -> dict:
        """
        Valide un répertoire et retourne des informations détaillées
        
        Returns:
            {
                'exists': bool,
                'is_dir': bool,
                'readable': bool,
                'writable': bool,
                'absolute_path': str,
                'size_info': dict,
                'suggestions': list
            }
        """
        result = {
            'exists': False,
            'is_dir': False,
            'readable': False,
            'writable': False,
            'absolute_path': '',
            'size_info': {},
            'suggestions': []
        }
        
        exists, found_path, tested_paths = PathHelper.find_existing_path(path)
        
        if not exists:
            # Générer des suggestions
            result['suggestions'] = [
                "Verify the path exists and is correct",
                "Check for typos in the path",
                "Try using an absolute path",
                "Ensure you have access permissions to the folder"
            ]
            
            # Suggestions spécifiques selon l'OS
            if platform.system() == 'Windows':
                result['suggestions'].extend([
                    "Use backslashes (\\) or forward slashes (/)",
                    "Include the drive letter (e.g., C:\\path\\to\\folder)"
                ])
            
            return result
        
        result['exists'] = True
        result['absolute_path'] = found_path
        
        try:
            result['is_dir'] = os.path.isdir(found_path)
            
            if check_permissions:
                result['readable'] = os.access(found_path, os.R_OK)
                result['writable'] = os.access(found_path, os.W_OK)
            
            # Informations sur la taille si c'est un dossier
            if result['is_dir']:
                try:
                    file_count = 0
                    total_size = 0
                    
                    for root, dirs, files in os.walk(found_path):
                        file_count += len(files)
                        for file in files:
                            try:
                                file_path = os.path.join(root, file)
                                total_size += os.path.getsize(file_path)
                            except (OSError, ValueError):
                                continue
                    
                    result['size_info'] = {
                        'file_count': file_count,
                        'total_size_bytes': total_size,
                        'total_size_mb': round(total_size / (1024 * 1024), 2)
                    }
                except (OSError, ValueError):
                    result['size_info'] = {'error': 'Unable to calculate size'}
                    
        except (OSError, ValueError) as e:
            result['suggestions'].append(f"Path access error: {str(e)}")
        
        return result
    
    @staticmethod
    def get_common_project_indicators(path: str) -> List[str]:
        """
        Détecte les indicateurs de projet dans un dossier
        (package.json, requirements.txt, etc.)
        """
        exists, found_path, _ = PathHelper.find_existing_path(path)
        
        if not exists:
            return []
        
        indicators = []
        common_files = [
            'package.json',      # Node.js
            'requirements.txt',  # Python
            'Pipfile',          # Python Pipenv
            'pyproject.toml',   # Python moderne
            'composer.json',    # PHP
            'pom.xml',          # Java Maven
            'build.gradle',     # Java Gradle
            'Cargo.toml',       # Rust
            'go.mod',           # Go
            '.gitignore',       # Git
            'README.md',        # Documentation
            'LICENSE',          # License
        ]
        
        try:
            for item in os.listdir(found_path):
                if item in common_files:
                    indicators.append(item)
        except (OSError, ValueError):
            pass
        
        return indicators
