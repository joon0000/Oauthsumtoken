import json
import time
import secrets
#import ssl
import urllib.parse as urlparse
import jwt

from auth import (RESOURCE_PATH, generate_refresh_token,
                  generate_access_token, generate_authorization_code, 
                  verify_authorization_code, verify_token, decode_token,
                  JWT_LIFE_SPAN_ACCESS_TOKEN, JWT_LIFE_SPAN_REFRESH_TOKEN)

from flask import Flask, jsonify, redirect, render_template, request

from urllib.parse import urlencode
from passlib.context import CryptContext
import bcrypt
from flask_sqlalchemy import SQLAlchemy
# Import the seed_data function from seed.py

ISSUER = 'sample-auth-server'

app = Flask(__name__)
    
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100))
    birthday = db.Column(db.Date)
    email = db.Column(db.String(100), unique=True)
    phone_number = db.Column(db.String(100))
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean, default=False)  # เพิ่มคอลัมน์ admin และกำหนดให้มีค่าเริ่มต้นเป็น False

    def __init__(self, email, password, username, name=None, birthday=None, phone_number=None, admin=False):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.name = name
        self.birthday = birthday
        self.phone_number = phone_number
        self.admin = admin  # เพิ่มการกำหนดค่า admin ใน constructor
        
    def verify_password(self, password):
      return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))
        
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100),nullable=False,unique=True)
    ttl = db.Column(db.Integer)
    permissions = db.Column(db.String(100))

    def __init__(self, name, ttl=None, permissions=None):
        self.name = name
        self.ttl = ttl
        self.permissions = permissions

# class Code(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     code = db.Column(db.String(100),nullable=False,unique=True)
#     exp = db.Column(db.Float)
#     iat = db.Column(db.Float)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
#     user = db.relationship('User', backref=db.backref('codes', lazy=True))
    
#     role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
#     role = db.relationship('Role', backref=db.backref('codes', lazy=True))
    
#     def __init__(self, code, role_id, iat=None, exp=None,user_id=None):
#         self.code = code
#         self.iat = iat
#         self.exp   = exp
#         self.user_id = user_id
#         self.role_id = role_id
        
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(100), nullable=False, unique=True)
    client_secret = db.Column(db.String(100), unique=True)
    redirect_url = db.Column(db.String(100))
    
    def __init__(self, client_id, client_secret, redirect_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_url = redirect_url
        
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    #1 code
    code = db.Column(db.String(100),nullable=False,unique=True)
    iat = db.Column(db.Float)
    exp = db.Column(db.Float)
    #refresh token
    token = db.Column(db.String(100))
    scope = db.Column(db.String(100))
    #1 code
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('access_logs', lazy=True))
    #refresh token
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'))
    client = db.relationship('Client', backref=db.backref('access_logs', lazy=True))
    #1 code
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('access_logs', lazy=True))
    
    def __init__(self, code, role_id, iat=None, exp=None, user_id=None, client_id=None, token=None, scope=None):
        self.code = code
        self.role_id=role_id
        self.iat=iat
        self.token = token
        self.scope = scope
        self.exp = exp
        self.client_id = client_id
        self.user_id = user_id

with app.app_context():
    db.create_all()

# check client, redir same in database?
def verify_client_info(client_id, redirect_url):
  client = Client.query.filter_by(client_id=client_id).first()
  if client and client.redirect_url == redirect_url:
    return True
  else:
    return False    

def verify_scope(scope):
  scopes = scope.split()
  valid_scopes = ['openid', 'email', 'phone_number', 'name', 'birthday', 'READ', 'WRITE','READWRITE','admin']
  for s in scopes:
      if s not in valid_scopes:
          return False, f"Invalid scope: {s}"
  return True, "ok"
        
@app.route('/auth')
def auth():
  # Describe the access request of the client and ask user for approval
  client_id = request.args.get('client_id')
  redirect_url = request.args.get('redirect_url')
  scope = request.args.get('scope')
  
  if None in [ client_id, redirect_url, scope]:
    return json.dumps({
      "error": "invalid_request",
      'client_id': client_id,
      'redirect_url': redirect_url,
      'scope': scope
    }), 400
    
  state, msg = verify_scope(scope)
  if not state:
     return json.dumps({
      "error": msg
    }), 400
    
  if not verify_client_info(client_id, redirect_url):
    return json.dumps({
      "error": "invalid_client"
    }), 400

  return render_template('AC_grant_access.html',
                         client_id = client_id,
                         redirect_url = redirect_url,
                         scope = scope
                         )

def process_redirect_url(redirect_url, authorization_code):
  # Prepare the redirect URL
  url_parts = list(urlparse.urlparse(redirect_url))
  queries = dict(urlparse.parse_qsl(url_parts[4]))
  queries.update({ "authorization_code": authorization_code })
  url_parts[4] = urlencode(queries)
  url = urlparse.urlunparse(url_parts)
  return url

def authenticate_user_credentials(username, password):
  user = User.query.filter_by(username=username).first()
  if user and user.verify_password(password):
            return True
  return False

user_login = {}  

# def recordaccesslog(username, client_id, scope):
#   client = Client.query.filter_by(client_id=client_id).first()
#   user = User.query.filter_by(username=username).first()
  
#   old_log = AccessLog.query.filter_by(client_id=client.id,user_id=user.id).first()
#   if old_log:
#     db.session.delete(old_log)
    
#   log = AccessLog(client_id=client.id,scope=scope,user_id=user.id)
  
#   db.session.add(log)
#   db.session.commit()
#   print(AccessLog.query.all())
 
@app.route('/signin', methods=['POST'])
def signin():
    username = request.form.get('username')
    password = request.form.get('password')
    client_id = request.form.get('client_id')
    redirect_url = request.form.get('redirect_url')
    code_org = request.form.get('code')
    scope = request.form.get('scope')
    
    client = Client.query.filter_by(client_id=client_id).first()

    if None in [username, password, client_id, redirect_url, code_org]:
        return json.dumps({"error": "invalid_request"}), 400

    if not verify_client_info(client_id, redirect_url):
        return json.dumps({"error": "invalid_client"}), 400

    if not authenticate_user_credentials(username, password):
        return json.dumps({'error': 'access_denied'}), 401

    code = AccessLog.query.filter_by(code=code_org).first()
    if not code:
        return json.dumps({"error": "invalid_code"}), 400

    if code.user_id is None:
        user = User.query.filter_by(username=username).first()
        code.user_id = user.id
        db.session.commit()
        print(f'userinLog = {code.user}')
    else:
 
        if code.user.username != username:
            return json.dumps({"error": "invalid_code_owner"}), 401

    scope = code.role.permissions
    code.client_id = client.id
    code.scope = scope
    db.session.commit()
 
    authorization_code = generate_authorization_code(client_id, redirect_url)

    redirect_url = process_redirect_url(redirect_url, authorization_code)
    
    return redirect(redirect_url, code=303)


def authenticate_client(client_id, client_secret):
  client = Client.query.filter_by(client_id=client_id).first()
  if client and client.client_secret == client_secret:
    return True
  else:
    return False
  
def store_refresh_token(clientid_in_log ,refresh_token, username):
    user = User.query.filter_by(username=username).first()
    log = AccessLog.query.filter_by(client_id=clientid_in_log,user_id=user.id).first()
    if log:
        log.token = refresh_token
    else:
        print('session not found')
    db.session.add(log)
    db.session.commit()
    
with open('private.pem', 'rb') as file:
  private_key = file.read()
    
def generate_id_token(log, client_id):
    scope = log.scope
    user = User.query.filter_by(id=log.user_id).first()
    if not user:
        raise ValueError("Invalid user ID")

    scopes = scope.split()

    payload = {
        'iss': ISSUER,
        'sub': log.user.username,
        'aud': client_id,
        'iat': time.time(),
        'exp': time.time() + JWT_LIFE_SPAN_ACCESS_TOKEN
    }

    # เพิ่มข้อมูลผู้ใช้ลงใน payload ตาม scope
    for s in scopes:
        if s == 'email':
            payload['email'] = user.email
        elif s == 'phone_number':
            payload['phone_number'] = user.phone_number
        elif s == 'name':
            payload['name'] = user.name
        elif s == 'birthday':
            payload['birthday'] = user.birthday

    # สร้าง id_token
    id_token = jwt.encode(payload, private_key, algorithm='RS256')
    return id_token


@app.route('/token', methods = ['POST'])
def exchange_for_token():
  # Issues access token
  authorization_code = request.form.get('authorization_code')
  client_id = request.form.get('client_id')
  client_secret = request.form.get('client_secret')
  redirect_url = request.form.get('redirect_url')
  client = Client.query.filter_by(client_id=client_id).first()
  clientid_in_log = client.id
  
  log = AccessLog.query.filter(AccessLog.client_id == client.id).order_by(AccessLog.id.desc()).first()
  username = log.user.username
  scope = log.scope
  exp = log.exp

  if None in [ authorization_code, client_id, client_secret, redirect_url ]:
    return json.dumps({
      "error": "invalid_request"
    }), 400

  if not authenticate_client(client_id, client_secret):
    return json.dumps({
      "error": "invalid_client"
    }), 400

  if not verify_authorization_code(authorization_code, client_id, redirect_url):
    return json.dumps({
      "error": "access_denied"
    }), 400
  
  refresh_token = generate_refresh_token(exp)
  access_token  = generate_access_token(username,client_id,scope)
  id_token      = generate_id_token(log, client_id)
  
  store_refresh_token(clientid_in_log ,refresh_token, username)
  
  return json.dumps({ 
    "refresh_token": refresh_token,
    "access_token" : access_token,
    "id_token"     : id_token,
    "token_type"   : "JWT",
    "expires_in"   : JWT_LIFE_SPAN_ACCESS_TOKEN,
    #for show in client
    "exp"          : time.time() + JWT_LIFE_SPAN_ACCESS_TOKEN
  })
  
def verify_client_id(client_id):
  client = Client.query.filter_by(client_id=client_id).first()
  if client:
    return True
  else:
    return False
    
@app.route('/auth/refresh', methods = ['POST'])
def refresh_for_token():
  # Issues access token
  grant_type = request.form.get('grant_type')
  client_id = request.form.get('client_id')
  refresh_token = request.form.get('refresh_token')
  
  if None in [ grant_type, client_id, refresh_token ]:
    return json.dumps({
      "error": "invalid_request"
    }), 400
    
  if grant_type != 'refresh_token':
    return json.dumps({
      "error": "invalid grant type"
    }), 400

  if not verify_client_id(client_id):
    return json.dumps({
      "error": "invalid_client"
    }), 400
    
  state, msg = verify_token(refresh_token)
  if not state:
    return json.dumps({
      "error": msg
    }), 400
    
  client = Client.query.filter_by(client_id=client_id).first()
  log = AccessLog.query.filter_by(client_id=client.id, token=refresh_token).first()
  if not log:
    return json.dumps({
      "error": 'client or refresh token invalid'
    }), 400
    
  username = log.user.username
  scope = log.scope

  access_token  = generate_access_token(username,client_id,scope)
  
  return json.dumps({ 
    "access_token" : access_token,
    "token_type"   : "Bearer",
    "expires_in"   : JWT_LIFE_SPAN_ACCESS_TOKEN,
    "refresh_token": refresh_token,
    #for show in client
    "exp"          : time.time() + JWT_LIFE_SPAN_ACCESS_TOKEN
  })
  
def delete_expired_code():
    current_timestamp = time.time()
    expired_codes = AccessLog.query.filter(AccessLog.exp.isnot(None), AccessLog.exp < current_timestamp).all()
    for code in expired_codes:
        db.session.delete(code)
    db.session.commit()
    # print('del exp')
  
def before_request():
    # Checks if the access token is present and valid.
    auth_header = request.headers.get('Authorization')
    if 'Bearer' not in auth_header:
        return json.dumps({'error': 'Access token does not exist.'}), 400
      
    access_token = auth_header[7:]

    delete_expired_code()
    
    state, token = decode_token(access_token)
    if state:
        # Check if the HTTP method is allowed
        if request.method not in ['GET', 'POST']:  
            return json.dumps({'error': 'Method not allowed.'}), 405

        scope = token.get('scope')
        print(scope)
        if scope != 'admin':
            return json.dumps({'error': 'Forbidden.'}), 403
    
    else:
        return json.dumps({'error': 'Access token is invalid.'}), 401

def seconds_to_hours_minutes(seconds):
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return hours, minutes

@app.route('/admin', methods=['GET'])
def admin():
    error_response = before_request()
    if error_response:
        return error_response

    logs = AccessLog.query.all()
    logs_data = []  # สร้างลิสต์เปล่าเพื่อเก็บข้อมูลทั้งหมด
    for log in logs:
        log_data = {  # สร้าง dictionary สำหรับข้อมูลแต่ละรายการ
            'id': log.id,
            'code': log.code,
            'iat': log.iat,            
            'exp': log.exp,
            'token': log.token,
            'scope':log.scope,
            'role': log.role.name,            
            'user': log.user.username if log.user else None,
            'client': log.client.client_id if log.client else None
        }
        logs_data.append(log_data)  # เพิ่มข้อมูลแต่ละรายการลงในลิสต์
    return jsonify({'codes': logs_data})

@app.route('/admin/role')
def role():
  error_response = before_request()
  if error_response:
      return error_response
  roles = Role.query.all()
  roles_data = []
  for role in roles:
    role_data = {
      'id': role.id,
      'name': role.name,
      'ttl': role.ttl,
      'permissions': role.permissions
    }
    roles_data.append(role_data)
  return jsonify({'roles': roles_data})

@app.route('/admin/role', methods=['POST'])
def create_role():
    error_response = before_request()
    if error_response:
        return error_response
    name = request.form.get('name')
    ttl = int(request.form.get('ttl'))
    permissions = request.form.get('permissions')
    
    print(f'name: {name}')
    print(f'ttl: {ttl}')
    print(f'per: {permissions}')
        
    if None in [ name, ttl, permissions ]:
      return json.dumps({
        "error": "invalid_request"
      }), 400
      
    if ttl < 0:
      return json.dumps({
        "error": "invalid_request"
      }), 400
    
    role = Role(
                  name=name,
                  ttl=ttl,
                  permissions=permissions
                )
    db.session.add(role)
    db.session.commit()
    
    role =  Role.query.filter_by(name=name).first()
    if not role:
      return json.dumps({
          'error': 'role not found'
      }), 500
    
    url = 'http://127.0.0.1:5004/role'
    return redirect(url, code = 201)

def generate_role_code(length=32):
    # สร้าง Random String ที่มีความยาวตามที่กำหนด (ค่าเริ่มต้นคือ 32 ตัวอักษร)
    code = secrets.token_urlsafe(length)
    return code

@app.route('/admin/code', methods=['POST'])
def create_code():
    error_response = before_request()
    if error_response:
        return error_response
    role = request.form.get('role')
    quantity = int(request.form.get('quantity'))
    
    if None in [ role, quantity ]:
      return json.dumps({
        "error": "invalid_request"
      }), 400
      
    role = Role.query.filter_by(name=role).first()
      
    if not role:
      return json.dumps({
        "error": "invalid_request"
      }), 400
    
    # data = {
    #         'roleid' : role.id,
    #         'code ': generate_role_code()
    # }
    exp = time.time() + role.ttl
    iat = time.time()
    codes_created = []
    for _ in range(quantity):
        code = generate_role_code()
        code_obj = AccessLog(code=code, role_id=role.id, exp=exp, iat=iat)
        db.session.add(code_obj)
        codes_created.append(code)
    
    db.session.commit()
    
    url = 'http://127.0.0.1:5004/'
    return redirect(url, code = 201)
  
# Route เพื่อลบ code โดยใช้ HTTP DELETE method
@app.route('/admin/revoke/<int:log_id>', methods=['DELETE'])
def delete_access_log(log_id):
    log = AccessLog.query.filter_by(id=log_id).first()  # หา code จาก code_id
    if log is None:
        return jsonify({'message': 'code not found'}), 404
    # codes = {  # สร้าง dictionary สำหรับข้อมูลแต่ละรายการ
    #     'id': code.id,
    #     'code': code.code,
    #     'user': code.user.username if code.user else None,
    #     'role': code.role.name,
    #     'exp': code.exp,
    #     'iat': code.iat
    # } # เพิ่มข้อมูลแต่ละรายการลงในลิสต์
    # return jsonify({'codes': codes})
    # data = {'code':code}
    # ลบ code จากฐานข้อมูล
    db.session.delete(log)
    db.session.commit()
    
    return jsonify({'message': 'code deleted successfully'}), 200
    
    # return data
    
if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(port = 5001, debug = True)