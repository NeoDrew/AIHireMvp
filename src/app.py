
from flask import Flask, request, abort, jsonify, session
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from flask_session import Session
from config import ApplicationConfig
from models import db, User

app = Flask(__name__)
app.config.from_object(ApplicationConfig)

Bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
server_session = Session(app)
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/@me', methods=['GET'])
def get_current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(id=user_id).first()

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"id": user.id,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "email": user.email})

@app.route('/register', methods=['POST'])
def register_user():
    email = request.json.get('email')
    password = request.json.get('password')
    first_name = request.json.get('firstName')
    last_name = request.json.get('lastName')

    user_exists = User.query.filter_by(email=email).first() is not None

    if user_exists:
        abort(409)

    hashed_password = Bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(email=email, password=hashed_password, firstName=first_name, lastName=last_name)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"id": new_user.id,
                    "email": new_user.email})

@app.route('/login', methods=['POST'])
def login_user():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"error": "Unauthorized"}), 404

    if not Bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401
    
    session["user_id"] = user.id

    return jsonify({"id": user.id,
                    "email": user.email})

if __name__ == '__main__':
    app.run(host='localhost', debug=True, port=5000)