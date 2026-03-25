# AV-Shield Windows — Installation 
 
## Prérequis 
1. Python 3.12 : https://www.python.org/downloads/ 
2. Git : https://git-scm.com/download/win 
 
## Installation 
 
### 1. Cloner le projet 
git clone https://github.com/fatima-hub03/av-shield-windows.git 
cd av-shield-windows 
 
### 2. Installer les dependances Python 
pip install flask flask-cors google-genai watchdog requests 
 
### 3. Creer config_local.py dans le dossier web\ 
Contenu du fichier config_local.py : 
GEMINI_API_KEY = "AIzaSyBwoSfABO6sxFfS7QrnVx5UdMQPo6iOuLw" 
VIRUSTOTAL_API_KEY = "e7035993041914653adbea7608c47ce2aea3be346a90cb387682e71e6809f29f" 
SMTP_HOST = "sandbox.smtp.mailtrap.io" 
SMTP_PORT = 2525 
SMTP_USER = "a6f439e2da724f" 
SMTP_PASS = "6b6de78d5eb1f0" 
ALERT_EMAIL = "fatimaavshield@gmail.com" 
 
### 4. Lancer l'application 
# Terminal 1 - Monitor temps reel 
python web\realtime_monitor.py 
 
# Terminal 2 - Interface web 
python web\app.py 
 
### 5. Ouvrir le navigateur 
http://localhost:5000 
