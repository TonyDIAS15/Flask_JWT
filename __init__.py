from flask import Flask, render_template, jsonify, request, make_response
from flask_jwt_extended import (
    create_access_token, get_jwt_identity,
    jwt_required, JWTManager, get_jwt
)
from datetime import timedelta

app = Flask(__name__)

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]           # Précise que le token sera stocké dans un cookie
app.config["JWT_COOKIE_NAME"] = "access_token_cookie"     #Nom du cookie personnalisé
jwt = JWTManager(app)

# Utilisateurs fictifs pour l'exemple
USERS = {
    "admin": {"password": "admin", "role": "admin"},
    "test": {"password": "test", "role": "user"}
}

# Route pour afficher le formulaire HTML
@app.route('/formulaire')
def formulaire():
    return render_template('formulaire.html')

# Route de connexion qui génère un token JWT stocké dans un cookie sécurisé
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # Création du token avec les rôles
    access_token = create_access_token(identity=username, additional_claims={"role": user["role"]})

    # Réponse avec le token stocké dans le cookie nommé "access_token_cookie"
    response = make_response(jsonify({"msg": "Connexion réussie"}))
    response.set_cookie(
        "access_token_cookie",  # Nouveau nom du cookie
        access_token,
        httponly=True,
        secure=False,  # Utilise `secure=True` uniquement avec HTTPS
        samesite='Strict'
    )
    return response

#Middleware personnalisé pour vérifier les rôles
def role_required(required_role):
    def wrapper(fn):
        @jwt_required(locations=["cookies"])  # Spécifie la recherche du token dans les cookies
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") != required_role:
                return jsonify({"msg": "Accès refusé : permissions insuffisantes"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

#Route protégée accessible via le cookie JWT
@app.route("/protected", methods=["GET"])
@jwt_required(locations=["cookies"])
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

#Route protégée accessible uniquement aux administrateurs
@app.route("/admin", methods=["GET"])
@role_required("admin")
def admin():
    return jsonify({"msg": "Bienvenue sur la page administrateur !"})

if __name__ == "__main__":
    app.run(debug=True)
