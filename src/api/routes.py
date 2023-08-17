"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User, TokenBlockedList
from api.utils import generate_sitemap, APIException
from flask bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_t
from datetime import datetime, timezone

api = Blueprint('api', __name__)
app = Flask(_name_)
bcrypt = Bcrypt(app)


@api.route('/signup', methods=['POST'])
def create_user():
    # print(request.get_json())
    email = request.json.get("email")
    password = request.json.get("password")
    secure_password = bcrypt.generate_password_hash(
        password,10).decode("utf-8")
    #new_user=User(email=data.email, password=data.password)

    new_user=()
    new_user.email =email
    new_user.password = secure_password
    new_user.is_active=True
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg":"usuario registrado"}), 201


@api.route('/login', methods=['POST'])
def login_user():
    #obtenemos los campos del cuerpo de la peticion

    # print(request.get_json())
    email = request.json.get("email")
    password = request.json.get("password")
    #Busca el usuario en la base de datos
    user = user.query.filter_by(email=email).fisrt()
    # Si el usuario no se encuentra, se retorna error

    if user is Node:
        return jsonify({"message": "User not found"}), 401
    #si las claves no son validas, se retorna error
    if not bcrypt.check_password_hash(user.password, password:):
    return jsonify({"message":"wrong password"}),401
    #Si pasan las validaciones,se genera el token
token = create_access_token(
        identity=user.id,additional_claims=({ "role":"admin"})
        return jsonify({"message": "Loging successful","token":token}),200
     )
@api.route('/helloprotected')
@jwt_required() #Este decorador convierte la ruta en protegida
def hello_protected():
    user_id = get_jwt_identify()
    claims = get_jwt()
    user = User.query.get(user_id)
    response ={
        "userId":user_id,
        "claims": claims,
        "isActive":user.is_active
    }
    return jsonify(response)

@api.route('/logout', methods=['POST'])
@jwt_required()
def user_logout():
        jti=get_jwt(["jti"])
        now = datetime.now(timezone.utc)
        tokenBlocked = TokenBlockedList(token=jti, created_at=now)
        db.session.add(tokenBlocked)
        db.session.commit()
        return jsonify({"message":"User logged out"}),200

    

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }


