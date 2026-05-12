# AI Evaluator Pro 🛡️

AI Evaluator Pro is a cutting-edge, mobile-responsive security orchestration tool designed to audit Hugging Face model repositories. It evaluates model supply chain risks, organization trustworthiness via OSINT, and community feedback to provide a comprehensive security report before deploying a model into your infrastructure.

Repository: [https://github.com/giriaryan694-a11y/AI-Evaluator-Pro/](https://github.com/giriaryan694-a11y/AI-Evaluator-Pro/)

---

## 🚀 Key Features

### 🔍 Dual Mode Operations

* **Direct Audit**: Instant security analysis using a Hugging Face repository ID.
* **Model Discovery**: Describe your use case and the system finds + audits the best-fit model automatically.

### ⚙️ Multi-Engine Support

* OpenAI
* Google Gemini
* NVIDIA NIM (recommended)

### 🕵️ OSINT Integration

* Real-time author/org research using DuckDuckGo

### 🧬 Supply Chain Inspection

* Detects unsafe model formats (Pickle/PT)
* Flags SafeTensors as secure alternative

### 🖥️ Modern Dashboard

* Claude-inspired dark UI
* Fully responsive (desktop + mobile)

---

## 💡 Engine Recommendation

**Recommended Provider:** NVIDIA NIM

* High usage limits (near-unlimited feel)
* Best performance for reasoning workloads

**Recommended Model:**

* `openai/gpt-oss-20b` (on NVIDIA)

Fast, accurate, and optimized for security evaluation logic.

---

## ⚠️ Important Usage Notes

* Only use **text/chat models**
* Image or embedding-only models will cause API errors
* Requires valid credentials in configuration files

---

## 🛠️ Installation & Setup

### 1. Clone Repository

```bash
git clone https://github.com/giriaryan694-a11y/AI-Evaluator-Pro.git
cd AI-Evaluator-Pro
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install flask flask-limiter pyfiglet huggingface_hub duckduckgo-search openai google-generativeai requests
```

---

## 🔐 Configuration

### 📄 auth.txt

Create file:

```
username:password
```

Default credentials:

```
admin:admin123
```

---

### 🔑 api.txt

```
nvidia_build_api-key = "YOUR_KEY_HERE"
gemini_api-key = "YOUR_KEY_HERE"
openai_api = "YOUR_KEY_HERE"
```

---

### 🤗 hf_token.txt

* Remove existing text
* Paste your Hugging Face token or API key only

---

## 💻 CLI Usage

```bash
python main.py --help
```

### Options

```
usage: main.py [-h] [--only-me] [--ip IP] [--port PORT]

AI Model Security Evaluator Web Panel

options:
  -h, --help    show this help message and exit

Server Configuration:
  --only-me     Bind to 127.0.0.1 (local only)
  --ip IP       Comma-separated allowed IPs
  --port PORT   Web panel port (default: 5000)
```

---

## 📱 Mobile Support

* Mobile-first responsive UI
* Stacked layout for small screens
* Fully usable from phone/tablet

---

## 🖼️ Screenshots

### 🔍 Model Evaluation Mode

![1](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/1.png)
![2](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/2.png)
![3](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/3.png)
![4](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/4.png)

---

### 🔎 Model Discovery (Find Mode)

![f1](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/f-1.png)
![f2](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/f-2.png)
![f3](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/f-3.png)
![f4](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/f-4.png)
![f5](https://raw.githubusercontent.com/giriaryan694-a11y/AI-Evaluator-Pro/refs/heads/main/screenshots/f-5.png)

---

## 📦 Requirements

```
flask
flask-limiter
pyfiglet
huggingface_hub
duckduckgo-search
openai
google-generativeai
requests
```

---

## 📜 License

Apache-2.0 License

---

## 👨‍💻 Author

Made By Aryan Giri
GitHub: [https://github.com/giriaryan694-a11y](https://github.com/giriaryan694-a11y)

Built for modern AI Security Researchers.

---

## ⚠️ Disclaimer

This tool is intended for **educational and security auditing purposes only**.
Always ensure you have authorization before analyzing private or restricted repositories.

### ⚠️ AI Limitations & Security Notice

* This tool can make mistakes and may produce incorrect or incomplete analysis.
* Results may vary depending on the underlying model selected.
* The system can hallucinate, especially when using less reliable or non-deterministic models.
* It may be vulnerable to **indirect prompt injection attacks** through analyzed content (e.g., model cards, README files, or external metadata).
* Outputs should NOT be treated as a guaranteed source of truth or a complete security verdict.

👉 Treat this system as an **assistive security analysis tool**, not a definitive or 100% reliable solution.

This tool is intended for **educational and security auditing purposes only**.
Always ensure you have authorization before analyzing private or restricted repositories.
