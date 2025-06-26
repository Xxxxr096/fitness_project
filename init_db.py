# init_db.py
from app import db, app, User

with app.app_context():
    db.create_all()
    print(User.__table__.columns.keys())
    print("Base de données initialisée.")
