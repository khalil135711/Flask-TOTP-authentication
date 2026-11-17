"""
TOTP (one-time password) authentication with Flask.

Install:  pip install flask pyotp "qrcode[pil]"
Run:      python app.py   ->  http://127.0.0.1:5000
"""
import base64
import io
import os
import sqlite3

import pyotp
import qrcode
from flask import Flask, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))
DB = "users.db"
ISSUER = "MyApp"


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


with db() as con:
    con.execute(
        """CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            totp_active INTEGER NOT NULL DEFAULT 0)"""
    )

BASE = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OTP Auth</title>
<style>
 body{font-family:system-ui,sans-serif;background:#f3f4f6;display:grid;place-items:center;min-height:100vh;margin:0}
 .card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 20px #0001;width:340px}
 input,button{width:100%;padding:.7rem;margin:.4rem 0;box-sizing:border-box;font-size:1rem;border-radius:8px;border:1px solid #ccc}
 button{background:#2563eb;color:#fff;border:0;cursor:pointer}
 .err{color:#b91c1c}.ok{color:#15803d} img{width:100%} a{color:#2563eb}
 .code{letter-spacing:.4em;text-align:center;font-size:1.4rem}
</style></head><body><div class="card">{{ body|safe }}</div></body></html>
"""


def page(body, **ctx):
    body = render_template_string(body, **ctx)
    return render_template_string(BASE, body=body)


@app.route("/")
def index():
    if session.get("user"):
        return page(
            "<h2>Welcome, {{u}}</h2><p class='ok'>Logged in with 2FA.</p>"
            "<a href='{{ url_for(\"logout\") }}'>Log out</a>",
            u=session["user"],
        )
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if len(u) < 3 or len(p) < 8:
            error = "Username min 3 chars, password min 8 chars."
        else:
            try:
                with db() as con:
                    con.execute(
                        "INSERT INTO users VALUES (?,?,?,0)",
                        (u, generate_password_hash(p), pyotp.random_base32()),
                    )
                session.clear()
                session["setup_user"] = u
                return redirect(url_for("setup"))
            except sqlite3.IntegrityError:
                error = "Username already taken."
    return page(
        """<h2>Register</h2>
        <form method="post">
          <input name="username" placeholder="Username" required>
          <input name="password" type="password" placeholder="Password (min 8)" required>
          <button>Create account</button>
        </form>
        <p class="err">{{error}}</p>
        <a href="{{ url_for('login') }}">Already have an account?</a>""",
        error=error,
    )


@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Show QR code and activate 2FA once the user proves they scanned it."""
    u = session.get("setup_user")
    if not u:
        return redirect(url_for("login"))
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    totp = pyotp.TOTP(row["totp_secret"])
    error = ""
    if request.method == "POST":
        if totp.verify(request.form["code"].strip(), valid_window=1):
            with db() as con:
                con.execute("UPDATE users SET totp_active=1 WHERE username=?", (u,))
            session.clear()
            return redirect(url_for("login", activated=1))
        error = "Wrong code, try again."

    uri = totp.provisioning_uri(name=u, issuer_name=ISSUER)
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    qr = base64.b64encode(buf.getvalue()).decode()
    return page(
        """<h2>Set up 2FA</h2>
        <p>Scan with your authenticator app:</p>
        <img src="data:image/png;base64,{{qr}}" alt="QR code">
        <p>Or enter manually:<br><code>{{secret}}</code></p>
        <form method="post">
          <input class="code" name="code" maxlength="6" inputmode="numeric"
                 placeholder="000000" autocomplete="one-time-code" required>
          <button>Verify &amp; activate</button>
        </form><p class="err">{{error}}</p>""",
        qr=qr, secret=row["totp_secret"], error=error,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        with db() as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["pw_hash"], p):
            session.clear()
            if not row["totp_active"]:
                session["setup_user"] = u
                return redirect(url_for("setup"))
            session["pending_user"] = u  # password OK, OTP still required
            return redirect(url_for("verify"))
        error = "Invalid username or password."
    return page(
        """<h2>Login</h2>
        {% if ok %}<p class="ok">2FA activated. Please log in.</p>{% endif %}
        <form method="post">
          <input name="username" placeholder="Username" required>
          <input name="password" type="password" placeholder="Password" required>
          <button>Continue</button>
        </form><p class="err">{{error}}</p>
        <a href="{{ url_for('register') }}">Create account</a>""",
        error=error, ok=request.args.get("activated"),
    )


@app.route("/verify", methods=["GET", "POST"])
def verify():
    u = session.get("pending_user")
    if not u:
        return redirect(url_for("login"))
    error = ""
    if request.method == "POST":
        with db() as con:
            row = con.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if pyotp.TOTP(row["totp_secret"]).verify(request.form["code"].strip(), valid_window=1):
            session.clear()
            session["user"] = u
            return redirect(url_for("index"))
        error = "Invalid code."
        # Production: rate-limit attempts here (e.g. Flask-Limiter) to stop brute force.
    return page(
        """<h2>Enter code</h2>
        <form method="post">
          <input class="code" name="code" maxlength="6" inputmode="numeric"
                 placeholder="000000" autocomplete="one-time-code" autofocus required>
          <button>Verify</button>
        </form><p class="err">{{error}}</p>""",
        error=error,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
