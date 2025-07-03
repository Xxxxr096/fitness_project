from flask import Flask, render_template, request, url_for, flash, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin,
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_bcrypt import Bcrypt
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
import re
import logging
from logging.handlers import RotatingFileHandler
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf
import cloudinary
import cloudinary.uploader

load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
)


app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
# app.config["SESSION_COOKIE_SECURE"] = True  # only works with HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.permanent_session_lifetime = timedelta(minutes=30)

db = SQLAlchemy(app)
bycrypt = Bcrypt(app)

if not os.path.exists("logs"):
    os.mkdir("logs")
file_handler = RotatingFileHandler("logs/app.log", maxBytes=10240, backupCount=5)
file_handler.setLevel(logging.WARNING)
app.logger.addHandler(file_handler)

csrf = CSRFProtect(app)


UPLOAD_FOLDER = os.path.join(basedir, "static/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


ALLOWED_EXTENSIONS = {"pdf"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Secure headers
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

limiter = Limiter(
    get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    prenom = db.Column(db.String(100), nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, default=False)


class ProgrammeDemande(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    poids = db.Column(db.Integer, nullable=False)
    taille = db.Column(db.Integer, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    objectif = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    fichier = db.Column(db.String(200))  # chemin vers le fichier réponse

    user = db.relationship("User", backref="demandes")


def generate_reset_token(email):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email, salt="reset-password")


def verify_reset_token(token, max_age=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="reset-password", max_age=max_age)
    except:
        return None
    return email


# Charger utilisateur
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def hello_world():
    return render_template("home.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        prenom = request.form["prenom"]
        nom = request.form["nom"]
        email = request.form["email"]
        message = request.form["message"]

        corps = f"""
            Nom : {prenom}, {nom}
            Email : {email}
            
            Message :
            {message}
        """
        msg = MIMEText(corps)
        msg["Subject"] = "Nouveau message de contact - GRINDZONE"
        msg["From"] = os.getenv("MAIL_USERNAME")
        msg["To"] = os.getenv("MAIL_USERNAME")

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
                smtp.send_message(msg)
                flash("Message envoyé avec succés !", "success")
        except Exception as e:
            print("Erreur:", e)
            flash("Erreur lors de l'envoi du message.", "error")
        return redirect(url_for("contact"))

    return render_template("contact.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        prenom = request.form["prenom"]
        nom = request.form["nom"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm"]
        if not is_valid_email(email):
            flash("Adresse email invalide.", "error")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Les mots de passe ne correspondent pas.")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Un compte existe déja avec cet email.")
            return redirect(url_for("register"))
        hashed_pw = bycrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(prenom=prenom, nom=nom, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        token = generate_confirmation_token(email)
        confirm_url = url_for("confirm_email", token=token, _external=True)

        message = MIMEText(
            f"""
        Bienvenue sur GRINDZONE 💪,

        Clique ici pour confirmer ton adresse email :
        {confirm_url}

        Ce lien expire dans 1h.

        L'équipe GRINDZONE
        """
        )
        message["Subject"] = "Confirmation de ton compte – GRINDZONE"
        message["From"] = os.getenv("MAIL_USERNAME")
        message["To"] = email

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
                smtp.send_message(message)
        except Exception as e:
            flash("Erreur lors de l'envoi de l'email de confirmation", "error")

        flash(
            "Ton compte a bien été créé ! Un email de confirmation t’a été envoyé. Clique sur le lien pour activer ton compte.",
            "success",
        )
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)

    if not email:
        flash("Lien invalide ou expiré.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("login"))

    if user.confirmed:
        flash("Ton compte est déjà confirmé.", "info")
    else:
        user.confirmed = True
        db.session.commit()
        flash("Ton compte a été confirmé avec succès.", "success")

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and bycrypt.check_password_hash(user.password, password):
            login_user(user)
            # 👇 Rediriger vers admin s'il est admin
            if user.is_admin:
                return redirect(url_for("admin"))
            return redirect(url_for("dashboard"))
        else:
            flash("Email ou mot de passe incorrect", "error")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/programmes", methods=["GET", "POST"])
@login_required
def programmes():
    if request.method == "POST":
        poids = request.form["poids"]
        taille = request.form["taille"]
        age = request.form["age"]
        objectif = request.form["objectif"]
        type_prog = request.form["type"]

        demande = ProgrammeDemande(
            user_id=current_user.id,
            poids=poids,
            taille=taille,
            age=age,
            objectif=objectif,
            type=type_prog,
        )
        db.session.add(demande)
        db.session.commit()
        flash(
            "Ta demande a été enregistrée. Tu recevras ton programme ici même !",
            "success",
        )
        return redirect(url_for("programmes"))

    demandes = (
        ProgrammeDemande.query.filter_by(user_id=current_user.id)
        .order_by(ProgrammeDemande.date.desc())
        .all()
    )
    return render_template("programmes.html", demandes=demandes)


from flask import send_file, Response, redirect


@app.route("/telecharger-programme/<int:demande_id>")
@login_required
def telecharger_programme(demande_id):
    demande = ProgrammeDemande.query.get_or_404(demande_id)

    if demande.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if not demande.fichier:
        flash("Aucun fichier disponible pour cette demande.", "error")
        return redirect(url_for("programmes"))

    # Construction d’un nom de fichier propre
    nom_client = current_user.nom.replace(" ", "_").lower()
    programme_type = demande.type.replace(" ", "_").lower()
    nom_fichier = f"{programme_type}_{nom_client}_{demande.id}.pdf"

    # Redirection vers l’URL Cloudinary avec nom forcé
    url_pdf = f"{demande.fichier}&response-content-disposition=attachment;filename={nom_fichier}"

    return redirect(url_pdf)


# ----------- ADMIN ------------ #
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)

    total_users = User.query.count()
    total_demandes = ProgrammeDemande.query.count()
    total_contacts = 0

    # Montrer seulement les demandes SANS fichier (non traitées)
    demandes = (
        ProgrammeDemande.query.filter_by(fichier=None)
        .order_by(ProgrammeDemande.date.desc())
        .all()
    )

    return render_template(
        "admin.html",
        user=current_user,
        total_users=total_users,
        total_demandes=total_demandes,
        total_contacts=total_contacts,
        demandes=demandes,
    )


@limiter.limit("5 per minute")
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        if not is_valid_email(email):
            flash("Adresse email invalide.", "error")
            return redirect(url_for("forgot_password"))
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for("reset_password", token=token, _external=True)
            message = MIMEText(
                f"Bonjour,\n\nClique sur ce lien pour réinitialiser ton mot de passe :\n\n{reset_url}\n\nCe lien est valable 1h.\n\n— GRINDZONE"
            )
            message["Subject"] = "Réinitialisation de mot de passe – GRINDZONE"
            message["From"] = os.getenv("MAIL_USERNAME")
            message["To"] = user.email

            try:
                with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                    smtp.starttls()
                    smtp.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
                    smtp.send_message(message)
                    flash(
                        "Un lien de réinitialisation t’a été envoyé par e-mail.",
                        "success",
                    )
            except Exception as e:
                print("Erreur d’envoi email :", e)
                flash(
                    "Erreur lors de l’envoi de l’e-mail. Réessaie plus tard.", "error"
                )
            print("➡️ Lien de réinitialisation :", reset_url)
        else:
            flash("Aucun compte ne correspond à cet email.", "error")
        return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash("Lien invalide ou expiré", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form["confirm"]
        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
            return redirect(request.url)

        user = User.query.filter_by(email=email).first()
        if user:
            hashed_pw = bycrypt.generate_password_hash(password).decode("utf-8")
            user.password = hashed_pw
            db.session.commit()
            flash("Mot de passe mis à jour. Tu peux te connecter.", "success")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


UPLOAD_FOLDER = os.path.join(basedir, "static/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

from urllib.parse import urlencode


@app.route("/admin/repondre/<int:id>", methods=["GET", "POST"])
@login_required
def repondre(id):
    if not current_user.is_admin:
        abort(403)

    demande = ProgrammeDemande.query.get_or_404(id)

    if request.method == "POST":
        fichier = request.files.get("pdf")

        if fichier and fichier.filename.endswith(".pdf"):
            try:
                nom_client = demande.user.nom.replace(" ", "_").lower()
                programme_type = demande.type.replace(" ", "_").lower()
                filename = secure_filename(
                    f"{programme_type}_{nom_client}_{demande.id}.pdf"
                )
                public_id = filename.rsplit(".", 1)[0]

                # Upload vers Cloudinary en RAW et avec metadata
                result = cloudinary.uploader.upload(
                    fichier,
                    resource_type="raw",
                    folder="grindzone_programmes",
                    public_id=public_id,
                    use_filename=True,
                    unique_filename=False,
                    overwrite=True,
                    format="pdf",  # Ajouté pour s'assurer de l'extension
                    context={"alt": "Programme GRINDZONE", "mime": "application/pdf"},
                )

                # Création d’une URL avec `fl_attachment` + nom de fichier
                download_url = result["secure_url"].replace(
                    "/upload/", "/upload/fl_attachment/"
                )
                download_url += (
                    f"&response-content-disposition=attachment;filename={filename}"
                )

                demande.fichier = download_url
                db.session.commit()
                flash("Programme envoyé avec succès.", "success")
                return redirect(url_for("admin"))
            except Exception as e:
                print("Cloudinary error:", e)
                flash("Erreur lors de l'envoi vers Cloudinary.", "error")
        else:
            flash("Seuls les fichiers PDF sont autorisés.", "error")

    return render_template("admin_repondre.html", demande=demande)


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


def generate_confirmation_token(email):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email, salt="confirm-email")


def confirm_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="confirm-email", max_age=expiration)
    except:
        return None
    return email


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


if __name__ == "__main__":
    app.run()
