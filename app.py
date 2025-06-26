from flask import Flask, render_template, request, url_for, flash, redirect
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

load_dotenv()
app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
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
        msg["Form"] = os.getenv("MAIL_USERNAME")
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


@app.route("/programmes", methods=["GET"])
@login_required
def programmes():
    return render_template("programmes.html")


if __name__ == "__main__":
    app.run(debug=True)
