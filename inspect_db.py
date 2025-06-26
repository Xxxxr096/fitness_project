from app import db, User, ProgrammeDemande, app

with app.app_context():
    users = User.query.all()
    for user in users:
        print(f"{user.id} - {user.prenom} {user.nom} ({user.email})")

    demandes = ProgrammeDemande.query.all()
    for d in demandes:
        print(f"Demande #{d.id} – {d.user.nom} – {d.objectif} ({d.type})")
