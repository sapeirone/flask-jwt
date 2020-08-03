from utils import hash_password, check_password
from database.user import User
from pony import orm
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                jwt_refresh_token_required, get_jwt_identity)


auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    with orm.db_session():
        hashed_passwd = hash_password(username, password)
        User(username=username, password=hashed_passwd)
        orm.commit()

    return jsonify(result="User registered"), 200


@auth.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    exists = False
    with orm.db_session():
        u = User.get(username=username)
        if u is not None and check_password(password, u.password):
            exists = True

    if not exists:
        return jsonify({"msg": "The user does not exist"}), 400

    return jsonify({
        'access_token': create_access_token(identity=username),
        'refresh_token': create_refresh_token(identity=username)
    }), 200


@auth.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200
