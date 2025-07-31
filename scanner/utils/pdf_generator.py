from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Configure des styles personnalisés pour le PDF"""
        # Titre principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#2E86AB')
        ))
        
        # Score de sécurité
        self.styles.add(ParagraphStyle(
            name='SecurityScore',
            parent=self.styles['Normal'],
            fontSize=18,
            spaceAfter=20,
            spaceBefore=10,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1F4E79')
        ))
        
        # Sous-titres
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#2E86AB'),
            borderWidth=1,
            borderColor=colors.HexColor('#2E86AB'),
            borderPadding=5
        ))
        
        # Texte de vulnérabilité
        self.styles.add(ParagraphStyle(
            name='VulnText',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            leftIndent=10,
            rightIndent=10
        ))
        
        # Code snippet
        self.styles.add(ParagraphStyle(
            name='CodeSnippet',
            parent=self.styles['Code'],
            fontSize=9,
            leftIndent=20,
            rightIndent=20,
            backColor=colors.HexColor('#F5F5F5'),
            borderWidth=1,
            borderColor=colors.HexColor('#CCCCCC'),
            borderPadding=8
        ))

    def generate_pdf_report(self, results: dict, output_path: str) -> bool:
        """Génère un rapport PDF à partir des résultats du scan"""
        try:
            # Créer le document PDF
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Construire le contenu
            story = []
            
            # En-tête
            story.extend(self._build_header(results))
            
            # Résumé
            story.extend(self._build_summary(results))
            
            # Breakdown par sévérité
            story.extend(self._build_severity_breakdown(results))
            
            # Vulnérabilités détaillées
            story.extend(self._build_detailed_vulnerabilities(results))
            
            # Recommandations
            story.extend(self._build_recommendations(results))
            
            # Générer le PDF
            doc.build(story)
            return True
            
        except Exception as e:
            print(f"Erreur génération PDF: {str(e)}")
            return False
    
    def _build_header(self, results: dict) -> list:
        """Construit l'en-tête du rapport"""
        story = []
        
        # Titre principal
        story.append(Paragraph("🛡️ BeraMind Security Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Informations du scan
        summary = results.get('summary', {})
        scan_metadata = results.get('scan_metadata', {})
        
        scan_info = f"""
        <b>Target:</b> {summary.get('target', 'Unknown')}<br/>
        <b>Scan Date:</b> {summary.get('scan_date', 'Unknown')}<br/>
        <b>Scan Type:</b> {scan_metadata.get('scan_type', 'Unknown').title()}<br/>
        <b>Scan ID:</b> {scan_metadata.get('scan_id', 'Unknown')}
        """
        
        story.append(Paragraph(scan_info, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _build_summary(self, results: dict) -> list:
        """Construit la section résumé"""
        story = []
        summary = results.get('summary', {})
        
        # Titre de section
        story.append(Paragraph("📊 Security Overview", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Score de sécurité avec espacement approprié
        score = summary.get('security_score', 0)
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        # Déterminer la couleur et le message du score
        if score >= 80:
            score_color = colors.green
            security_level = "EXCELLENT SECURITY"
        elif score >= 60:
            score_color = colors.orange
            security_level = "GOOD SECURITY"
        else:
            score_color = colors.red
            security_level = "NEEDS ATTENTION"
        
        # Score avec espacement
        score_text = f'<font color="{score_color.hexval()}"><b>Security Score: {score}/100</b></font>'
        story.append(Paragraph(score_text, self.styles['SecurityScore']))
        story.append(Spacer(1, 0.1*inch))
        
        # Niveau de sécurité avec espacement
        level_text = f'<font color="{score_color.hexval()}"><b>{security_level}</b></font>'
        story.append(Paragraph(level_text, self.styles['SecurityScore']))
        story.append(Spacer(1, 0.2*inch))
        
        # Statistiques
        stats_text = f"""
        <b>Total Issues Found:</b> {total_vulns}<br/>
        <b>Files Analyzed:</b> Multiple source files<br/>
        <b>Analysis Type:</b> Static Analysis + AI-Powered Detection
        """
        
        story.append(Paragraph(stats_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _build_severity_breakdown(self, results: dict) -> list:
        """Construit la répartition par sévérité"""
        story = []
        summary = results.get('summary', {})
        severity_breakdown = summary.get('severity_breakdown', {})
        
        if not any(severity_breakdown.values()):
            return story
        
        story.append(Paragraph("🔍 Issues by Severity", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Créer un tableau simple pour la répartition
        data = [['Severity Level', 'Count', 'Description']]
        
        severity_info = {
            'critical': ('Critical', colors.red, 'Immediate action required'),
            'high': ('High', colors.orange, 'Should be fixed soon'),
            'medium': ('Medium', colors.yellow, 'Moderate priority'),
            'low': ('Low', colors.lightblue, 'Low priority')
        }
        
        for severity, count in severity_breakdown.items():
            if count > 0:
                info = severity_info.get(severity, (severity.title(), colors.gray, 'Unknown'))
                data.append([info[0], str(count), info[2]])
        
        if len(data) > 1:  # S'il y a des données
            table = Table(data, colWidths=[2*inch, 1*inch, 3*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
            ]))
            
            story.append(table)
            story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _build_detailed_vulnerabilities(self, results: dict) -> list:
        """Construit la section des vulnérabilités détaillées sans tableaux complexes"""
        story = []
        vulnerabilities = results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return story
        
        story.append(Paragraph("🚨 Detailed Vulnerabilities", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Grouper par sévérité
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Couleurs pour les sévérités
        severity_colors = {
            'critical': colors.red,
            'high': colors.orange,
            'medium': colors.yellow,
            'low': colors.lightblue
        }
        
        # Afficher dans l'ordre: critical, high, medium, low
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                vulns = by_severity[severity]
                color = severity_colors.get(severity, colors.gray)
                
                # Titre de sévérité
                severity_title = f'<font color="{color.hexval()}"><b>{severity.upper()} SEVERITY ({len(vulns)} issues)</b></font>'
                story.append(Paragraph(severity_title, self.styles['Heading3']))
                story.append(Spacer(1, 0.1*inch))
                
                # Liste des vulnérabilités pour cette sévérité
                for i, vuln in enumerate(vulns, 1):
                    # Titre de la vulnérabilité
                    vuln_title = f"<b>[{severity.upper()}-{i:02d}] {vuln.get('type', 'Unknown').replace('_', ' ').title()}</b>"
                    story.append(Paragraph(vuln_title, self.styles['VulnText']))
                    
                    # Détails de la vulnérabilité
                    details = []
                    
                    if 'file' in vuln:
                        # Raccourcir le chemin si nécessaire
                        file_path = str(vuln['file'])
                        if len(file_path) > 60:
                            file_path = "..." + file_path[-60:]
                        details.append(f"<b>File:</b> {file_path}")
                    
                    if 'line' in vuln:
                        details.append(f"<b>Line:</b> {vuln['line']}")
                    
                    if 'description' in vuln:
                        # Gérer les descriptions longues
                        desc = str(vuln['description'])
                        if len(desc) > 200:
                            desc = desc[:200] + "..."
                        details.append(f"<b>Description:</b> {desc}")
                    
                    # Afficher les détails
                    if details:
                        details_text = "<br/>".join(details)
                        story.append(Paragraph(details_text, self.styles['VulnText']))
                    
                    # Code snippet si disponible
                    if 'code' in vuln and vuln['code']:
                        code = str(vuln['code']).strip()
                        if len(code) > 150:
                            code = code[:150] + "..."
                        
                        # Échapper les caractères spéciaux pour XML
                        code = code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        code_text = f"<b>Code:</b><br/><font name='Courier'>{code}</font>"
                        story.append(Paragraph(code_text, self.styles['CodeSnippet']))
                    
                    story.append(Spacer(1, 0.15*inch))
                
                story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _build_recommendations(self, results: dict) -> list:
        """Construit la section des recommandations"""
        story = []
        recommendations = results.get('recommendations', [])
        
        if not recommendations:
            return story
        
        story.append(Paragraph("💡 Security Recommendations", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        for i, rec in enumerate(recommendations, 1):
            rec_text = f"<b>{i}.</b> {rec}"
            story.append(Paragraph(rec_text, self.styles['VulnText']))
            story.append(Spacer(1, 0.1*inch))
        
        # Footer
        story.append(Spacer(1, 0.3*inch))
        footer_text = f"""
        <i>Report generated by BeraMind Security Scanner<br/>
        Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        return story
