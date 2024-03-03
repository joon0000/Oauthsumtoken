import datetime
import json
import time
import requests
#import ssl
from auth import decode_token, verify_id_token, get_exp

from flask import (Flask, jsonify, make_response, render_template, redirect, request,
                   url_for)

AUTH_PATH = 'http://127.0.0.1:5001/auth'
TOKEN_PATH = 'http://127.0.0.1:5001/token'
RES_PATH = 'http://127.0.0.1:5002/users'
REDIRECT_URL = 'http://127.0.0.1:5004/callback'
REFRESH_PATH = 'http://127.0.0.1:5001/auth/refresh'
CREATE_PATH = 'http://127.0.0.1:5002/content'

res_path = 'http://127.0.0.1:5001/admin'

scope2 = 'openid'

CLIENT_ID = 'test'
CLIENT_SECRET = 'test'
refresh_tokens = {}
user_info = {}
expire_in = None

app = Flask(__name__)

@app.before_request
def before_request():
  # Redirects user to the login page if access token is not present
  if request.endpoint not in ['login', 'callback']:
    access_token = request.cookies.get('access_token')
    refresh_token = refresh_tokens.get('refresh_token')
    if access_token:
      pass
    # if refresh_token:
    #   pass
    else:
      return redirect(url_for('login'))

@app.route('/')
def main():
  global expire_in
  # Retrieves a list of users
  access_token = request.cookies.get('access_token')
  # id_token = request.cookies.get('id_token')
  refresh_token = refresh_tokens.get('refresh_token')
  
  r = requests.get(res_path, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })
    
  if r.status_code != 200:
    if r.status_code == 401:
      r = requests.post(REFRESH_PATH, data = {
        "grant_type": "refresh_token",
        "client_id" : CLIENT_ID,
        "refresh_token": refresh_token
      })
      print(refresh_token)
      if r.status_code == 200:
          # หากขอ Access Token ใหม่สำเร็จ
          new_access_token = r.json().get('access_token')
          expire_in = r.json().get('exp')
          # สร้างการตอบสนองที่เปลี่ยนที่ตำแหน่งกลับไปยังหน้าหลักพร้อมกับตั้งค่าคุกกี้ Access Token ใหม่
          response = make_response(redirect(url_for('main')))
          response.set_cookie('access_token', new_access_token)
          return response
      else:
        print(r.text)
        return redirect(url_for('login'))
      
    return json.dumps({
      'error': 'The resource server returns an error: \n{}'.format(
        r.text)
    }), 500

  codes = json.loads(r.text).get('codes')

  return render_template('code.html', 
                         codes = codes,
                         sub = user_info.get('sub')
                         )
  
@app.route('/contents')
def get_content():
  access_token = request.cookies.get('access_token')
  content_url = 'http://127.0.0.1:5002/contents'
  r = requests.get(content_url, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })
  if r.status_code != 200:
    return json.dumps({
      'error': 'The resource server returns an error: \n{}'.format(
        r.text)
    }), 500
  contents = json.loads(r.text).get('contents')
  return render_template(
                         'contents.html',
                         contents=contents
                         )
  
@app.route('/contents/create')
def create_content():
  user = user_info.get('sub')
  return render_template('content_create.html',
                         user=user
                         )
  
@app.route('/content/create/submit',  methods = ['POST'])
def submit():
  title = request.form.get('title')
  detail = request.form.get('detail')
  sub = request.form.get('sub')
  access_token = request.cookies.get('access_token')
  data = {
        "title":title,
        "detail" : detail,
        "sub": sub
      }
  # json_data = json.dumps(data)
  r = requests.post(CREATE_PATH, headers={
                    'Authorization': 'Bearer {}'.format(access_token)},
                    data=data)
  if r.status_code == 201:
      # response = make_response(redirect(url_for('get_content')))
      return r.text
  # else:
  return json.dumps({
    'error': 'The resource server returns an error: \n{}'.format(
      r.text)
  }), 500
  
@app.route('/userinfo')
def get_userinfo():
    return jsonify(user_info)

@app.route('/login')
def login():
  # Presents the login page
  # print(SCOPE)
  return render_template('AC_login.html',
                         dest = AUTH_PATH,
                         client_id = CLIENT_ID,
                         redirect_url = REDIRECT_URL,
                         scope = scope2
                         )

@app.route('/callback')
def callback():
  global expire_in
  # Accepts the authorization code and exchanges it for access token
  authorization_code = request.args.get('authorization_code')
  
  if not authorization_code:
    return json.dumps({
      'error': 'No authorization code is received.'
    }), 500

  r = requests.post(TOKEN_PATH, data = {
    "grant_type": "authorization_code",
    "authorization_code": authorization_code,
    "client_id" : CLIENT_ID,
    "client_secret" : CLIENT_SECRET,
    "redirect_url": REDIRECT_URL
  })
  
  if r.status_code != 200:
    return json.dumps({
      'error': 'The authorization server returns an error: \n{}'.format(
        r.text)
    }), 500
    
  refresh_token = json.loads(r.text).get('refresh_token')
  access_token = json.loads(r.text).get('access_token')
  id_token = json.loads(r.text).get('id_token')
  expire_in = json.loads(r.text).get('exp')
  
  state, id_token = decode_token(id_token)
  if id_token and state:
      # print(type(id_token))
      user_info.update(id_token)
      # print(f'userinfo: \n{user_info}')
  else:
    return json.dumps({
      'error': 'ID token is invalid.'
    }), 400
  
  response = make_response(redirect(url_for('main')))
  response.set_cookie('access_token', access_token)
  # response.set_cookie('id_token',id_token)
  # response.set_cookie('refresh_token',refresh_token)
  
  refresh_tokens['refresh_token'] = refresh_token
  return response

@app.route('/role')
def get_role():
  access_token = request.cookies.get('access_token')
  role_url = 'http://127.0.0.1:5001/admin/role'
  r = requests.get(role_url, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })
  if r.status_code != 200:
    return json.dumps({
      'error': 'The authorization server returns an error: \n{}'.format(
        r.text)
    }), 500
  roles = json.loads(r.text).get('roles')
  return render_template(
                         'roles.html',
                         roles=roles
                         )
  
@app.route('/role/create')
def create_role():
  user = user_info.get('sub')
  return render_template('role_create.html',
                         user=user
                         )
  
@app.route('/role/create/submit',  methods = ['POST'])
def submit_role():
  name = request.form.get('name')
  ttl = request.form.get('ttl')
  permission = request.form.get('permissions')
  sub = request.form.get('sub')
  access_token = request.cookies.get('access_token')
  data = {
        "name":name,
        "ttl" : ttl,
        "permissions": permission
      }
  path = 'http://127.0.0.1:5001/admin/role'

  r = requests.post(path, headers={
                    'Authorization': 'Bearer {}'.format(access_token)},
                    data=data)
  if r.status_code == 201:
      # response = make_response(redirect(url_for('get_content')))
      return r.text
  return json.dumps({
    'error': 'The authorization server returns an error: \n{}'.format(
      r.text)
  }), 500
  # return data
  

  
@app.route('/code/create')
def create_role_token():
  user = user_info.get('sub')
  access_token = request.cookies.get('access_token')
  role_url = 'http://127.0.0.1:5001/admin/role'
  r = requests.get(role_url, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })
  if r.status_code != 200:
    return json.dumps({
      'error': 'The authorization server returns an error: \n{}'.format(
        r.text)
    }), 500
  roles = json.loads(r.text).get('roles')  
  return render_template('code_create.html',
                         roles=roles
                         )
  
@app.route('/code/create/submit',  methods = ['POST'])
def submit_token():
  role = request.form.get('role')
  quantity = request.form.get('quantity')
  access_token = request.cookies.get('access_token')
  data = {
        "role":role,
        "quantity" : quantity,
      }
  path = 'http://127.0.0.1:5001/admin/code'

  r = requests.post(path, headers={
                    'Authorization': 'Bearer {}'.format(access_token)},
                    data=data)
  if r.status_code == 201:
      # response = make_response(redirect(url_for('get_content')))
      return r.text
  return json.dumps({
    'error': 'The authorization server returns an error: \n{}'.format(
      r.text)
  }), 500
  # return data
                          
@app.route('/test')
def test():

  access_token = request.cookies.get('access_token')
  test_url = 'http://127.0.0.1:5001/admin'
  r = requests.get(test_url, headers = {
    'Authorization': 'Bearer {}'.format(access_token)
  })

  tokens = json.loads(r.text).get('tokens')

  return tokens
  
@app.route('/code/revoke', methods=['POST'])
def revoke_code():
    id = request.form.get('id')
    access_token = request.cookies.get('access_token')

    # สร้าง URL สำหรับลบบันทึกเข้าถึงโดยใช้ ID ที่ได้รับจากฟอร์ม
    path = 'http://127.0.0.1:5001/admin/revoke/{}'.format(id)

    # ส่ง HTTP DELETE request ไปยังเซิร์ฟเวอร์
    r = requests.delete(path, headers={
                        'Authorization': 'Bearer {}'.format(access_token)})

    # ตรวจสอบสถานะการตอบกลับ
    if r.status_code == 201:
        # ในกรณีที่สำเร็จ
        return r.text
    else:
        # ในกรณีที่เกิดข้อผิดพลาด
        return json.dumps({
            'error': 'The authorization server returns an error: \n{}'.format(
                r.text)
        }), 500

if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(port = 5004, debug = True)