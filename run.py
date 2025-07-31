#!/usr/bin/env python3
"""
Script de lancement pour BeraMind CLI
"""

import os
import sys
import subprocess
from pathlib import Path

def check_dependencies():
    """Vérifie si les dépendances sont installées"""
    try:
        import langchain
        import requests
        from dotenv import load_dotenv
        return True
    except ImportError as e:
        print(f"❌ Dépendance manquante: {e}")
        print("📦 Installez les dépendances avec:")
        print("   pip install -r requirements.txt")
        return False

def main():
    """Point d'entrée principal pour la version CLI"""
    print("🔍 BeraMind Security Scanner - CLI Version")
    print("   Powered by your Ollama model")
    print("=" * 60)
    
    # Vérifier les dépendances
    if not check_dependencies():
        sys.exit(1)
    
    # Vérifier si le script CLI existe
    cli_script = Path(__file__).parent / 'beramind_cli.py'
    
    if not cli_script.exists():
        print("❌ CLI script not found: beramind_cli.py")
        sys.exit(1)
    
    # Si aucun argument n'est fourni, afficher l'aide
    if len(sys.argv) == 1:
        print("🚀 Starting BeraMind CLI with help...")
        subprocess.run([sys.executable, str(cli_script), '--help'])
    else:
        # Passer tous les arguments au CLI
        args = sys.argv[1:]
        subprocess.run([sys.executable, str(cli_script)] + args)

if __name__ == '__main__':
    main()
