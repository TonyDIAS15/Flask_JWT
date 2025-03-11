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
jwt = JWTManager(app)

# Utilisateurs fictifs pour l'exemple
USERS = {
    "admin": {"password": "admin", "role": "admin"},
    "user": {"password": "user", "role": "user"}
}

@app.route('/') 
def hello_world():
    return render_template('formulaire.html')

# Route de connexion qui génère un token JWT dans un cookie sécurisé
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

    # Réponse avec un cookie contenant le token JWT
    response = make_response(jsonify({"msg": "Connexion réussie"}))
    response.set_cookie(
        "access_token", 
        access_token, 
        httponly=True, 
        secure=True, 
        samesite='Strict'
    )
    return response

# Route protégée accessible via le cookie JWT
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == "__main__":
    app.run(debug=True)
