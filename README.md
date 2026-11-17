# Flask TOTP Authentication

Zwei-Faktor-Authentifizierung (Passwort + Einmalcode / TOTP) mit Python, Flask und Web-Oberfläche.
Kompatibel mit Google Authenticator, Authy, Microsoft Authenticator u. a.

## Features
- Registrierung mit gehashtem Passwort (Werkzeug)
- QR-Code zur Einrichtung der Authenticator-App
- Login in zwei Schritten: Passwort, dann 6-stelliger Code
- SQLite-Speicherung (`users.db`)

## Installation
```bash
git clone https://github.com/<DEIN-USERNAME>/<REPO-NAME>.git
cd <REPO-NAME>
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Dann http://127.0.0.1:5000 öffnen.

## Ablauf
1. `/register`: Konto anlegen
2. `/setup`: QR-Code scannen und ersten Code bestätigen
3. `/login`: Passwort, dann `/verify`: Einmalcode

## Produktion
- HTTPS verwenden und `SECRET_KEY` als Umgebungsvariable setzen
- Rate-Limiting für `/login` und `/verify` (z. B. Flask-Limiter)
- TOTP-Secrets verschlüsselt speichern, Backup-Codes anbieten
- `debug=True` in `app.py` entfernen

## Lizenz
MIT
