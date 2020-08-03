from datetime import timedelta

from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from pony import orm

from database import db
from database.user import User

from utils import hash_password, check_password

# database setup
db.bind(provider='sqlite', filename='db.sqlite', create_db=True)
db.generate_mapping(create_tables=True)
orm.set_sql_debug(True)

app = Flask(__name__)

# setup of jwt flask extension
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=1)
jwt = JWTManager(app)


@app.route('/register', methods=['POST'])
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


@app.route('/login', methods=['POST'])
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

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run()
