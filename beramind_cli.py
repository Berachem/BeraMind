#!/usr/bin/env python3
"""
BeraMind Security Scanner - CLI Version
Advanced security vulnerability scanner powered by your Ollama model
"""

import os
import sys
import json
import time
import argparse
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from scanner.security_scanner import SecurityScanner
from scanner.utils.pdf_generator import PDFReportGenerator

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ProgressBar:
    """Simple progress bar for CLI"""
    def __init__(self, width=50):
        self.width = width
        self.last_progress = -1
    
    def update(self, progress: int, message: str = ""):
        if progress == self.last_progress:
            return
            
        self.last_progress = progress
        filled = int(self.width * progress / 100)
        bar = '█' * filled + '░' * (self.width - filled)
        
        # Clear line and print progress
        sys.stdout.write(f'\r{Colors.CYAN}[{bar}] {progress}%{Colors.END} {message}')
        sys.stdout.flush()
        
        if progress >= 100:
            print()  # New line when complete

class BeraMindCLI:
    def __init__(self):
        self.scanner = None
        self.progress_bar = ProgressBar()
        self.scan_start_time = None
        self.current_scan_id = None
        
    def print_banner(self):
        """Print the BeraMind banner"""
        banner = f"""
{Colors.GREEN}{Colors.BOLD}
██████╗ ███████╗██████╗  █████╗ ███╗   ███╗██╗███╗   ██╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██████╔╝█████╗  ██████╔╝███████║██╔████╔██║██║██╔██╗ ██║██║  ██║
██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║ 
██████╔╝███████╗██║  ██║██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝ 
{Colors.END}
{Colors.YELLOW}🔍 Advanced Security Vulnerability Scanner powered by your Ollama model{Colors.END}
{Colors.WHITE}Version 1.0 | CLI Interface{Colors.END}
"""
        print(banner)
    
    def check_system_requirements(self) -> bool:
        """Check if system requirements are met"""
        print(f"{Colors.BLUE}🔧 Checking system requirements...{Colors.END}")
        
        # Check Python version
        if sys.version_info < (3, 9):
            print(f"{Colors.RED}❌ Python 3.9+ required, found {sys.version_info.major}.{sys.version_info.minor}{Colors.END}")
            return False
        print(f"{Colors.GREEN}✓ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}{Colors.END}")
        
        # Check Ollama
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=5)
            if response.status_code == 200:
                print(f"{Colors.GREEN}✓ Ollama server running{Colors.END}")
                
                # Check models
                data = response.json()
                models = [model['name'] for model in data.get('models', [])]
                
                if models:
                    print(f"{Colors.GREEN}✓ {len(models)} model(s) available{Colors.END}")
                    # Show the first few models as examples
                    for i, model in enumerate(models[:3]):
                        print(f"   • {model}")
                    if len(models) > 3:
                        print(f"   • ... and {len(models) - 3} more")
                else:
                    print(f"{Colors.YELLOW}⚠️  No models found{Colors.END}")
                    print(f"{Colors.CYAN}   Install a model with: ollama pull <model-name>{Colors.END}")
                    print(f"{Colors.CYAN}   Popular choices: llama3.2, deepseek-r1, codellama{Colors.END}")
                
                return True
            else:
                print(f"{Colors.RED}❌ Ollama server not responding{Colors.END}")
                return False
                
        except requests.RequestException:
            print(f"{Colors.RED}❌ Cannot connect to Ollama server{Colors.END}")
            print(f"{Colors.CYAN}   Make sure Ollama is running: ollama serve{Colors.END}")
            return False
    
    def progress_callback(self, step: str, progress: int, details: Dict = None):
        """Callback for scan progress updates"""
        details = details or {}
        
        # Map steps to user-friendly messages
        step_messages = {
            'initializing': 'Initializing scanner...',
            'collecting': f'Collecting files from {details.get("target", "target")}...',
            'file_collection': f'Found {details.get("files_found", 0)} files to analyze',
            'static_analysis': 'Running static analysis...',
            'ai_analysis': f'AI analyzing {details.get("files_analyzed", 0)}/{details.get("total_files", 0)} files',
            'dependency_check': 'Checking dependencies...',
            'generating_report': 'Generating security report...',
            'complete': f'✅ Scan complete! Found {details.get("vulnerabilities_found", 0)} issues',
            'error': f'❌ Error: {details.get("error", "Unknown error")}'
        }
        
        message = step_messages.get(step, f'{step.replace("_", " ").title()}...')
        
        if step == 'ai_analysis' and 'current_file' in details:
            message = f'AI analyzing: {details["current_file"]}'
        
        self.progress_bar.update(progress, message)
        
        if step == 'complete':
            elapsed = time.time() - self.scan_start_time if self.scan_start_time else 0
            print(f"{Colors.GREEN}🎉 Scan completed in {elapsed:.1f} seconds{Colors.END}")
        elif step == 'error':
            error_msg = details.get('error', 'Unknown error')
            print(f"\n{Colors.RED}❌ Scan failed: {error_msg}{Colors.END}")
    
    def scan_target(self, target: str, scan_type: str, output_format: str = 'json') -> Optional[Dict[str, Any]]:
        """Scan a target (GitHub repo or local directory)"""
        try:
            # Initialize scanner
            print(f"{Colors.BLUE}🚀 Initializing scanner...{Colors.END}")
            self.scanner = SecurityScanner(progress_callback=self.progress_callback)
            
            # Generate scan ID
            self.current_scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.scan_start_time = time.time()
            
            print(f"{Colors.CYAN}📋 Scan Details:{Colors.END}")
            print(f"   Target: {target}")
            print(f"   Type: {scan_type}")
            print(f"   Scan ID: {self.current_scan_id}")
            print(f"   Output: {output_format}")
            print()
            
            # Run scan based on type
            if scan_type == 'github':
                print(f"{Colors.BLUE}🔍 Scanning GitHub repository...{Colors.END}")
                results = self.scanner.scan_github_repo(target)
            else:
                print(f"{Colors.BLUE}🔍 Scanning local directory...{Colors.END}")
                results = self.scanner.scan_local_directory(target)
            
            # Check for errors
            if 'error' in results:
                print(f"{Colors.RED}❌ Scan failed: {results['error']}{Colors.END}")
                return None
            
            # Add metadata
            results['scan_metadata'] = {
                'scan_id': self.current_scan_id,
                'scan_type': scan_type,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'cli_version': '1.0'
            }
            
            return results
            
        except Exception as e:
            print(f"{Colors.RED}❌ Scan error: {str(e)}{Colors.END}")
            return None
    
    def display_results(self, results: Dict[str, Any]):
        """Display scan results in a formatted way"""
        summary = results.get('summary', {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}🛡️  SECURITY SCAN RESULTS{Colors.END}")
        print("=" * 60)
        
        # Summary
        score = summary.get('security_score', 0)
        security_level = summary.get('security_level', 'unknown')
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        # Color code the score with new thresholds
        level_colors = {
            'excellent': Colors.GREEN,
            'good': Colors.CYAN,
            'acceptable': Colors.YELLOW,
            'poor': Colors.MAGENTA,
            'critical': Colors.RED,
            'dangerous': Colors.RED
        }
        
        level_emojis = {
            'excellent': '🟢',
            'good': '🔵', 
            'acceptable': '🟡',
            'poor': '🟠',
            'critical': '🔴',
            'dangerous': '⚫'
        }
        
        level_descriptions = {
            'excellent': 'EXCELLENT SECURITY',
            'good': 'GOOD SECURITY',
            'acceptable': 'ACCEPTABLE SECURITY', 
            'poor': 'POOR SECURITY',
            'critical': 'CRITICAL SECURITY ISSUES',
            'dangerous': 'DANGEROUS - IMMEDIATE ACTION REQUIRED'
        }
        
        score_color = level_colors.get(security_level, Colors.WHITE)
        emoji = level_emojis.get(security_level, '❓')
        description = level_descriptions.get(security_level, 'UNKNOWN SECURITY LEVEL')
        
        print(f"{Colors.BOLD}📊 Summary:{Colors.END}")
        print(f"   Security Score: {score_color}{score}/100{Colors.END}")
        print(f"   Security Level: {emoji} {score_color}{description}{Colors.END}")
        print(f"   Total Issues: {Colors.WHITE}{total_vulns}{Colors.END}")
        print(f"   Scan Date: {summary.get('scan_date', 'Unknown')}")
        print()
        
        # Ajouter un message explicatif pour les scores bas
        if score < 60 and total_vulns > 0:
            print(f"{Colors.YELLOW}⚠️  Security Concerns:{Colors.END}")
            severity_breakdown = summary.get('severity_breakdown', {})
            high_severity = severity_breakdown.get('critical', 0) + severity_breakdown.get('high', 0)
            
            if high_severity > 0:
                print(f"   • {high_severity} high-severity issue(s) detected")
            
            density_info = f"   • {total_vulns} issue(s) found across your codebase"
            print(density_info)
            print(f"   • Consider addressing critical/high severity issues first")
            print()
        
        # Severity breakdown
        severity_breakdown = summary.get('severity_breakdown', {})
        if severity_breakdown:
            print(f"{Colors.BOLD}🔍 Issues by Severity:{Colors.END}")
            severity_colors = {
                'critical': Colors.RED,
                'high': Colors.MAGENTA,
                'medium': Colors.YELLOW,
                'low': Colors.CYAN
            }
            
            for severity, count in severity_breakdown.items():
                if count > 0:
                    color = severity_colors.get(severity, Colors.WHITE)
                    print(f"   {color}● {severity.title()}: {count}{Colors.END}")
            print()
        
        # Detailed vulnerabilities
        if vulnerabilities:
            print(f"{Colors.BOLD}🚨 Detailed Vulnerabilities:{Colors.END}")
            print("-" * 60)
            
            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low')
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            # Display in order: critical, high, medium, low
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_severity:
                    color = severity_colors.get(severity, Colors.WHITE)
                    print(f"\n{color}{Colors.BOLD}{severity.upper()} SEVERITY:{Colors.END}")
                    
                    for i, vuln in enumerate(by_severity[severity], 1):
                        print(f"\n{color}[{severity.upper()}-{i:02d}]{Colors.END} {vuln.get('type', 'Unknown').replace('_', ' ').title()}")
                        print(f"   📁 File: {vuln.get('file', 'Unknown')}")
                        
                        if 'line' in vuln:
                            print(f"   📍 Line: {vuln.get('line')}")
                        
                        print(f"   📝 Description: {vuln.get('description', 'No description')}")
                        
                        if 'code' in vuln:
                            print(f"   💾 Code: {Colors.WHITE}{vuln.get('code')[:100]}{'...' if len(vuln.get('code', '')) > 100 else ''}{Colors.END}")
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            print(f"\n{Colors.BOLD}💡 Security Recommendations:{Colors.END}")
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        
        print(f"\n{Colors.GREEN}✅ Scan analysis complete!{Colors.END}")
    
    def save_results(self, results: Dict[str, Any], base_output_path: str, formats: list):
        """Save results to file(s) in specified format(s)"""
        saved_files = []
        
        for format_type in formats:
            try:
                # Generate the appropriate file extension
                if format_type == 'json':
                    if base_output_path.endswith('.pdf'):
                        output_path = base_output_path.replace('.pdf', '.json')
                    elif not base_output_path.endswith('.json'):
                        output_path = base_output_path + '.json'
                    else:
                        output_path = base_output_path
                elif format_type == 'pdf':
                    if base_output_path.endswith('.json'):
                        output_path = base_output_path.replace('.json', '.pdf')
                    elif not base_output_path.endswith('.pdf'):
                        output_path = base_output_path + '.pdf'
                    else:
                        output_path = base_output_path
                
                # Ensure output directory exists
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                if format_type == 'json':
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2, ensure_ascii=False)
                    print(f"{Colors.GREEN}💾 JSON report saved to: {output_path}{Colors.END}")
                    saved_files.append(str(output_path))
                    
                elif format_type == 'pdf':
                    pdf_generator = PDFReportGenerator()
                    if pdf_generator.generate_pdf_report(results, str(output_path)):
                        print(f"{Colors.GREEN}📄 PDF report saved to: {output_path}{Colors.END}")
                        saved_files.append(str(output_path))
                    else:
                        print(f"{Colors.RED}❌ Failed to generate PDF report{Colors.END}")
                        
            except Exception as e:
                print(f"{Colors.RED}❌ Failed to save {format_type.upper()} results: {str(e)}{Colors.END}")
        
        return saved_files

    def detect_target_type(self, target: str) -> tuple[str, str]:
        """Détecte automatiquement le type de cible (GitHub ou local)"""
        target = target.strip()
        
        # Détecter les URLs GitHub
        github_patterns = [
            'https://github.com/',
            'http://github.com/',
            'github.com/',
            'git@github.com:'
        ]
        
        for pattern in github_patterns:
            if target.startswith(pattern):
                # Normaliser l'URL GitHub
                if target.startswith('git@github.com:'):
                    # Convertir SSH en HTTPS
                    repo_path = target.replace('git@github.com:', '').replace('.git', '')
                    target = f'https://github.com/{repo_path}'
                elif target.startswith('github.com/'):
                    target = f'https://{target}'
                
                # S'assurer que l'URL se termine correctement
                if not target.endswith('.git') and not target.count('/') >= 4:
                    if not target.endswith('/'):
                        target += '.git'
                
                return 'github', target
        
        # Si ce n'est pas GitHub, c'est un chemin local
        # Normaliser le chemin pour Windows/Unix
        if target == '.':
            target = os.getcwd()
        elif target.startswith('~'):
            target = os.path.expanduser(target)
        elif not os.path.isabs(target):
            target = os.path.abspath(target)
        
        return 'local', os.path.normpath(target)

    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description='BeraMind Security Scanner - Advanced vulnerability detection',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s https://github.com/user/repo
  %(prog)s /path/to/project
  %(prog)s . --output report
  %(prog)s github.com/user/repo --format json
  %(prog)s --github https://github.com/user/repo
  %(prog)s --local /path/to/project --output report
            '''
        )
        
        # Argument positionnel pour la cible (optionnel)
        parser.add_argument('target', nargs='?', 
                          help='Target to scan (GitHub URL or local path)')
        
        # Options explicites (pour compatibilité)
        parser.add_argument('--github', '-g', 
                          help='GitHub repository URL to scan')
        parser.add_argument('--local', '-l',
                          help='Local directory path to scan')
        
        # Output options
        parser.add_argument('--output', '-o', 
                          help='Output file path base (default: results/scan_TIMESTAMP)')
        parser.add_argument('--format', '-f', 
                          choices=['json', 'pdf', 'both'], 
                          default='both',
                          help='Output format: json, pdf, or both (default: both)')
        
        # Display options
        parser.add_argument('--no-banner', 
                          action='store_true',
                          help='Skip banner display')
        parser.add_argument('--quiet', '-q',
                          action='store_true', 
                          help='Minimal output (results only)')
        parser.add_argument('--no-progress',
                          action='store_true',
                          help='Disable progress bar')
        
        # Parse arguments
        args = parser.parse_args()
        
        # Show banner unless disabled
        if not args.no_banner:
            self.print_banner()
        
        # Déterminer la cible à scanner
        target = None
        scan_type = None
        
        # Priorité: arguments explicites > argument positionnel
        if args.github:
            target = args.github
            scan_type = 'github'
        elif args.local:
            target = args.local
            scan_type = 'local'
        elif args.target:
            # Détection automatique du type
            scan_type, target = self.detect_target_type(args.target)
            if not args.quiet:
                print(f"{Colors.CYAN}🔍 Auto-detected: {scan_type} target{Colors.END}")
        else:
            # Aucune cible spécifiée, utiliser le répertoire courant
            target = os.getcwd()
            scan_type = 'local'
            if not args.quiet:
                print(f"{Colors.CYAN}🔍 No target specified, scanning current directory{Colors.END}")
        
        # Check system requirements unless quiet
        if not args.quiet:
            if not self.check_system_requirements():
                sys.exit(1)
            print()
        
        # Validation de la cible
        if scan_type == 'local':
            # Amélioration pour les chemins Windows/Unix
            possible_paths = [
                target,
                os.path.abspath(target),
                os.path.expanduser(target)
            ]
            
            path_exists = False
            actual_path = None
            
            for path in possible_paths:
                if os.path.exists(path) and os.path.isdir(path):
                    path_exists = True
                    actual_path = path
                    target = actual_path
                    break
            
            if not path_exists:
                print(f"{Colors.RED}❌ Local path does not exist: {target}{Colors.END}")
                print(f"{Colors.YELLOW}💡 Tip: Use quotes for paths with spaces{Colors.END}")
                sys.exit(1)
        
        # **NEW: Check if trying to scan BeraMind itself**
        if self.is_beramind_repo(target if not scan_type == 'github' else target):
            self.show_funny_beramind_message()
            return
        
        # Generate output path if not specified
        if not args.output:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if scan_type == 'github':
                # Extraire le nom du repo pour l'output
                repo_name = target.rstrip('/').split('/')[-1].replace('.git', '')
                args.output = f'results/{repo_name}_{timestamp}'
            else:
                folder_name = os.path.basename(target.rstrip('/\\'))
                if not folder_name:
                    folder_name = 'scan'
                args.output = f'results/{folder_name}_{timestamp}'
        
        # Determine formats to generate
        if args.format == 'both':
            formats = ['json', 'pdf']
        else:
            formats = [args.format]
        
        # Scan the target
        results = self.scan_target(target, scan_type, args.format)
        
        if not results:
            sys.exit(1)
        
        # Display results unless quiet
        if not args.quiet:
            self.display_results(results)
        
        # Save results in specified format(s)
        saved_files = self.save_results(results, args.output, formats)
        
        # Print final message
        if not args.quiet:
            print(f"\n{Colors.BOLD}🎯 Scan Summary:{Colors.END}")
            print(f"   Target: {target}")
            print(f"   Type: {scan_type.title()}")
            print(f"   Issues Found: {results.get('summary', {}).get('total_vulnerabilities', 0)}")
            print(f"   Security Score: {results.get('summary', {}).get('security_score', 0)}/100")
            print(f"   Reports Generated:")
            for file_path in saved_files:
                print(f"     • {file_path}")

    def is_beramind_repo(self, path):
        """Check if the target is the BeraMind repository itself"""
        # Check if it's the current directory and contains BeraMind files
        if os.path.exists(os.path.join(path, 'beramind_cli.py')) and \
           os.path.exists(os.path.join(path, 'README.md')):
            try:
                with open(os.path.join(path, 'README.md'), 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'BeraMind' in content and 'Security Scanner' in content:
                        return True
            except:
                pass
        
        # Check if it's a GitHub URL pointing to BeraMind
        if isinstance(path, str):
            beramind_patterns = [
                'github.com/Berachem/BeraMind',
                'github.com/berachem/beramind',
                'BeraMind-SecurityScanner',
                'beramind-securityscanner'
            ]
            path_lower = path.lower()
            for pattern in beramind_patterns:
                if pattern.lower() in path_lower:
                    return True
        
        return False

    def show_funny_beramind_message(self):
        """Display a funny message when trying to scan BeraMind itself"""
        print("\n" + "="*70)
        print("🤔 Wait, are you trying to scan BeraMind itself?")
        print()
        print("🎯 What's the point of self-scanning? This project's code is")
        print("   absolutely PERFECT! No vulnerabilities here, haha! 😄")
        print()
        print("💡 Try scanning some other project that actually needs it:")
        print("   • A random GitHub repo: python beramind_cli.py https://github.com/user/repo")
        print("   • Your own project: python beramind_cli.py /path/to/your/code")
        print("   • Any directory: python beramind_cli.py ~/Documents/project")
        print()
        print("🛡️  BeraMind is here to protect OTHER code, not itself!")
        print("="*70)
        print()

if __name__ == '__main__':
    cli = BeraMindCLI()
    try:
        cli.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)
