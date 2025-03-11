from flask import Flask 
from flask import render_template, jsonify, request
from flask_jwt_extended import (
    create_access_token, get_jwt_identity,
    jwt_required, JWTManager, get_jwt
)
from datetime import timedelta

app = Flask(__name__)

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"  # Ma clé privée
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)  # Expiration du token après 1h
jwt = JWTManager(app)

# Utilisateurs fictifs pour l'exemple
USERS = {
    "admin": {"password": "admin", "role": "admin"},
    "user": {"password": "user", "role": "user"}
}

@app.route('/')  # Test
def hello_world():
    return render_template('accueil.html')

# Route de connexion qui génère un token JWT avec les rôles
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"msg": "Mauvais utilisateur ou mot de passe"}), 401

    # Ajout du rôle dans les "claims" du token
    access_token = create_access_token(identity=username, additional_claims={"role": user["role"]})
    return jsonify(access_token=access_token)

# Middleware personnalisé pour vérifier les rôles
def role_required(required_role):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") != required_role:
                return jsonify({"msg": "Accès refusé : vous n'avez pas les permissions nécessaires"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Route protégée accessible uniquement aux administrateurs
@app.route("/admin", methods=["GET"])
@role_required("admin")
def admin():
    return jsonify({"msg": "Bienvenue sur la page administrateur !"})

# Route protégée accessible à tous les utilisateurs authentifiés
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == "__main__":
    app.run(debug=True)
