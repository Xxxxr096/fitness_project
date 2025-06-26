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
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename

load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{os.path.join(basedir, 'database.db')}"
)
app.config["SECRET_KEY"] = "1234 "

db = SQLAlchemy(app)
bycrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    prenom = db.Column(db.String(100), nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


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
        flash("Compte crée avec succés. Connecte-toi !")
        return redirect(url_for("login"))
    return render_template("register.html")


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


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
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


# ✅ Route pour l'admin qui envoie le programme PDF
@app.route("/admin/repondre/<int:id>", methods=["GET", "POST"])
@login_required
def repondre(id):
    if not current_user.is_admin:
        abort(403)

    demande = ProgrammeDemande.query.get_or_404(id)

    if request.method == "POST":
        fichier = request.files.get("pdf")
        if fichier and fichier.filename.endswith(".pdf"):
            filename = secure_filename(f"{demande.user.nom}_{demande.id}.pdf")
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            fichier.save(filepath)

            demande.fichier = filename
            db.session.commit()
            flash("Programme envoyé avec succès.", "success")
            return redirect(url_for("admin"))
        else:
            flash("Seuls les fichiers PDF sont autorisés.", "error")

    return render_template("admin_repondre.html", demande=demande)


if __name__ == "__main__":
    app.run(debug=True)
