
<div align="center">

```
██████╗ ███████╗██████╗  █████╗ ███╗   ███╗██╗███╗   ██╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗
██████╔╝█████╗  ██████╔╝███████║██╔████╔██║██║██╔██╗ ██║██║  ██║
██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║
██████╔╝███████╗██║  ██║██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
```
  
<img width="717" height="743" alt="471249768-6066435b-768d-4320-9e5d-9f63a45f6cc9" src="https://github.com/user-attachments/assets/e79f6794-5415-49a6-a72b-46d775df0d15" />

</div>
<div align="center">

<br>

**Advanced Security Vulnerability Scanner powered using LangChain & Ollama**

🔍 **Static Analysis** • 🤖 **AI-Powered Detection** • 📊 **Comprehensive Reports**

</div>

<div align="center">

<img width="400" height="225" alt="image" src="https://github.com/user-attachments/assets/ea160768-4e0f-4d8f-8771-e1f3b6d42847" />


</div>



## 🌟 Features

- **🤖 AI-Powered Analysis**: Works with any Ollama model for advanced vulnerability detection
- **📂 Multi-Source Scanning**: Supports GitHub repositories and local directories
- **🔍 Comprehensive Detection**:
  - SQL Injection vulnerabilities
  - Cross-Site Scripting (XSS)
  - Hardcoded secrets and API keys
  - Insecure cryptographic implementations
  - Vulnerable dependencies
- **📊 Smart Reporting**: JSON and PDF output formats with detailed security scores
- **⚡ Fast Processing**: Concurrent analysis with real-time progress tracking
- **🎯 Multi-Language Support**: Python, JavaScript, Java, PHP, Ruby, Go, C/C++, C#

## 📋 Prerequisites

### System Requirements

- **Python 3.9+**
- **Ollama** server running locally
- **Any Ollama model** (recommendations below)

### Installation

1. **Install Ollama**

   ```bash
   # Visit https://ollama.ai for installation instructions
   curl -fsSL https://ollama.ai/install.sh | sh
   ```

2. **Install a Compatible Model**

   Choose one of these popular models for security analysis:

   ```bash
   # Recommended for code analysis
   ollama pull deepseek-r1:14b      # Best for reasoning
   ollama pull codellama:13b        # Specialized for code
   ollama pull llama3.2:latest      # General purpose
   ollama pull qwen2.5-coder:14b    # Code-focused

   # Lightweight options
   ollama pull llama3.2:3b          # Faster, less thorough
   ollama pull codellama:7b         # Smaller code model
   ```

3. **Start Ollama Server**

   ```bash
   ollama serve
   ```

4. **Clone BeraMind**

   ```bash
   git clone https://github.com/your-username/BeraMind.git
   cd BeraMind
   ```

5. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

6. **Configure Your Model** (Optional)

   Create a `.env` file to specify your preferred model:

   ```env
   OLLAMA_MODEL_PRIMARY=deepseek-r1:14b
   # or any other model you prefer
   ```

## 🚀 Quick Start

### Basic Usage (Auto-Detection)

```bash
# Scan a GitHub repository (auto-detects GitHub URL)
python beramind_cli.py https://github.com/user/repository
python beramind_cli.py github.com/user/repository
python beramind_cli.py git@github.com:user/repository.git

# Scan local directory (auto-detects local path)
python beramind_cli.py /path/to/your/project
python beramind_cli.py .
python beramind_cli.py ~/Documents/my-project

# Scan current directory (no arguments)
python beramind_cli.py
```

### Explicit Usage (Original Method)

```bash
# Explicit GitHub scanning
python beramind_cli.py --github https://github.com/user/repository

# Explicit local scanning
python beramind_cli.py --local /path/to/your/project
```

### Advanced Usage

```bash
# Auto-detect with custom output
python beramind_cli.py https://github.com/user/repo --output my_report

# Auto-detect with specific format
python beramind_cli.py . --format json --output security_scan

# Quiet mode with auto-detection
python beramind_cli.py ~/my-project --quiet

# Skip banner and progress bar
python beramind_cli.py /path/to/code --no-banner --no-progress
```

## 📖 Command Line Options

```bash
python beramind_cli.py [target] [OPTIONS]

Positional Arguments:
  target               Target to scan (GitHub URL or local path)
                      If not specified, scans current directory

Explicit Target Options (optional):
  --github, -g URL     GitHub repository URL to scan
  --local, -l PATH     Local directory path to scan

Output Options:
  --output, -o PATH    Output file path base (default: results/TARGET_TIMESTAMP)
  --format, -f FORMAT  Output format: json, pdf, or both (default: both)

Display Options:
  --no-banner         Skip banner display
  --quiet, -q         Minimal output (results only)
  --no-progress       Disable progress bar
  --help, -h          Show help message
```

### Auto-Detection Examples

BeraMind automatically detects the target type:

```bash
# These are all equivalent GitHub scans:
python beramind_cli.py https://github.com/facebook/react
python beramind_cli.py github.com/facebook/react
python beramind_cli.py git@github.com:facebook/react.git

# These are all equivalent local scans:
python beramind_cli.py /home/user/project
python beramind_cli.py ~/project
python beramind_cli.py .
python beramind_cli.py ../parent-folder

# No arguments = scan current directory
python beramind_cli.py
```

## 📊 Output Examples

### Console Output

```
🛡️  SECURITY SCAN RESULTS
============================================================
📊 Summary:
   Security Score: 75/100
   Total Issues: 8
   Scan Date: 2024-01-15T10:30:45

🔍 Issues by Severity:
   ● Critical: 1
   ● High: 2
   ● Medium: 3
   ● Low: 2

🚨 Detailed Vulnerabilities:
------------------------------------------------------------

CRITICAL SEVERITY:
[CRITICAL-01] SQL Injection
   📁 File: src/database.py
   📍 Line: 45
   📝 Description: SQL injection vulnerability detected
   💾 Code: query = "SELECT * FROM users WHERE id = " + user_id
```

### JSON Output Structure

```json
{
  "summary": {
    "total_vulnerabilities": 8,
    "security_score": 75,
    "severity_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 2
    },
    "scan_date": "2024-01-15T10:30:45",
    "target": "/path/to/project"
  },
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": "critical",
      "file": "src/database.py",
      "line": 45,
      "description": "SQL injection vulnerability detected",
      "code": "query = \"SELECT * FROM users WHERE id = \" + user_id"
    }
  ],
  "recommendations": [
    "Use prepared statements to prevent SQL injection",
    "Validate and escape all user inputs"
  ]
}
```

## 🛠️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL_PRIMARY=llama3.2:latest

# Scanner Settings
MAX_CONCURRENT_SCANS=2
MAX_FILE_SIZE=1048576
SCAN_TIMEOUT=300

# Output Settings
RESULTS_FOLDER=results
TEMP_FOLDER=temp_repos
LOGS_FOLDER=logs
```

### Model Recommendations

**For Best Results:**

- `deepseek-r1:14b` - Excellent reasoning capabilities
- `qwen2.5-coder:14b` - Specialized for code analysis
- `codellama:13b` - Meta's code-focused model

**For Faster Scans:**

- `llama3.2:3b` - Good balance of speed and accuracy
- `codellama:7b` - Smaller code-focused model

**Memory Requirements:**

- 7B models: ~4GB RAM
- 13-14B models: ~8GB RAM
- 3B models: ~2GB RAM

### Supported File Types

- **Python**: `.py`
- **JavaScript**: `.js`
- **Java**: `.java`
- **PHP**: `.php`
- **Ruby**: `.rb`
- **Go**: `.go`
- **C/C++**: `.c`, `.cpp`
- **C#**: `.cs`

## 🔍 Vulnerability Detection

### Static Analysis Rules

- **SQL Injection**: Pattern matching for dangerous SQL constructions
- **XSS**: Detection of unsafe DOM manipulation
- **Hardcoded Secrets**: Identification of API keys, passwords, tokens
- **Insecure Crypto**: Weak cryptographic algorithms (MD5, SHA1, DES)

### AI-Powered Analysis

- **Contextual Understanding**: Your chosen model analyzes code context
- **Complex Patterns**: Detection of subtle vulnerability patterns
- **False Positive Reduction**: Intelligent filtering of results
- **Custom Vulnerabilities**: Discovery of application-specific issues

## 📈 Security Scoring

The security score (0-100) uses an **enhanced algorithm** that considers:

### Severity Weights

- **Critical vulnerabilities**: -25 points each
- **High vulnerabilities**: -15 points each
- **Medium vulnerabilities**: -8 points each
- **Low vulnerabilities**: -3 points each

### Additional Factors

- **Density penalty**: Higher penalty when many vulnerabilities per file
- **High-severity bonus penalty**: Extra deduction for projects with multiple critical/high issues
- **Progressive scaling**: Larger codebases with many issues get proportionally higher penalties

### Score Ranges & Security Levels

- 🟢 **90-100**: **Excellent Security** - Minimal to no issues
- 🔵 **75-89**: **Good Security** - Minor issues only
- 🟡 **60-74**: **Acceptable Security** - Some concerns to address
- 🟠 **40-59**: **Poor Security** - Multiple issues need attention
- 🔴 **20-39**: **Critical Security Issues** - Serious problems detected
- ⚫ **0-19**: **Dangerous** - Immediate action required

### Examples

```
Single critical vulnerability in small project:
- Base: 100 points
- Critical penalty: -25 points
- High-severity bonus: -5 points
- Final score: 70/100 (Acceptable)

Multiple high vulnerabilities:
- Base: 100 points
- 3 high vulnerabilities: -45 points
- High-severity bonus: -10 points
- Density factor: -5 points
- Final score: 40/100 (Poor Security)
```

This ensures that even a single critical vulnerability in a small project receives an appropriate security rating.

## 🔧 Troubleshooting

### Common Issues

1. **"Cannot connect to Ollama server"**

   ```bash
   # Start Ollama server
   ollama serve
   ```

2. **"No models found"**

   ```bash
   # Install a model
   ollama pull llama3.2:latest
   # or
   ollama pull deepseek-r1:14b
   ```

3. **"Local path does not exist"**

   - Verify the path is correct
   - Use absolute paths for better reliability
   - Check folder permissions

4. **"Scan timeout"**
   - Increase `SCAN_TIMEOUT` in `.env`
   - Reduce `MAX_FILE_SIZE` for large codebases
   - Try a smaller/faster model

### Performance Optimization

```env
# For faster scans (less thorough)
MAX_CONCURRENT_SCANS=4
MAX_FILE_SIZE=524288
OLLAMA_MODEL_PRIMARY=llama3.2:3b

# For more thorough scans (slower)
MAX_CONCURRENT_SCANS=1
MAX_FILE_SIZE=2097152
OLLAMA_MODEL_PRIMARY=deepseek-r1:14b
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Ollama** for local LLM deployment
- **LangChain** for LLM integration framework
- **Open source AI models** for powering the analysis

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/Berachem/BeraMind-SecurityScanner/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Berachem/BeraMind-SecurityScanner/discussions)
- 📧 **Email**: beramind@berachem.dev

---

<div align="center">
<b>🔐 Secure your code with the power of AI 🔐</b>
</div>
