# backend/app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_cors import CORS
from d3graph import d3graph, vec2adjmat
import pandas as pd
import os

app = Flask(__name__, static_folder='../frontend/build', static_url_path='/')
app.secret_key = 'replace-with-a-secure-secret'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

users = {}

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(username):
    if username in users:
        user = User()
        user.id = username
        return user
    return None

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    users[data['username']] = pw_hash
    return jsonify(success=True)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    pw_hash = users.get(data['username'])
    if pw_hash and bcrypt.check_password_hash(pw_hash, data['password']):
        user = User()
        user.id = data['username']
        login_user(user)
        return jsonify(success=True)
    return jsonify(success=False), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify(success=True)

@app.route('/api/graph', methods=['GET'])
@login_required
def graph():
    source = ['node A','node F','node B','node B','node B','node A','node C','node Z']
    target = ['node F','node B','node J','node F','node F','node M','node M','node A']
    weight = [5.56,0.5,0.64,0.23,0.9,3.28,0.5,0.45]
    adjmat = vec2adjmat(source, target, weight=weight)
    d3 = d3graph()
    d3.graph(adjmat)
    filepath = 'static/graph.html'
    d3.show(filepath=filepath)
    return send_from_directory('static', 'graph.html')

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    app.run(debug=True)