# create_admin.py
from app import db, User, app
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

with app.app_context():
    pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
    admin = User(
        prenom="Amine",
        nom="chabane",
        email="amine.chabane006@gmail.com",
        password=pw,
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    print("✔ Admin créé avec succès !")
