import json
#import ssl

from auth import verify_token, check_scope
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    detail = db.Column(db.String(100))
    sub = db.Column(db.String(100))
    
    def __init__(self, title, detail, sub):
        self.title = title
        self.detail = detail
        self.sub = sub

with app.app_context():
    db.create_all()

@app.before_request
def before_request():
  # Checks if the access token is present and valid.
  auth_header = request.headers.get('Authorization')
  if 'Bearer' not in auth_header:
    return json.dumps({
      'error': 'Access token does not exist.'
    }), 400
  
  access_token = auth_header[7:]

  state, token = verify_token(access_token)
  if access_token and state:
    # Check if the HTTP method is allowed
    if request.method not in ['GET', 'POST']:  
        return json.dumps({
            'error': 'Method not allowed.'
        }), 405
    
    # Check scope against the requested method
    if not check_scope(token, request.method):
        return json.dumps({
            'error': 'Insufficient scope.'
        }), 403

  else:
      return json.dumps({
          'error': 'Access token is invalid.'
      }), 401

@app.route('/users', methods = ['GET'])
def get_user():
  # Returns a list of users.
  users = [
    { 'username': 'Jane Doe', 'email': 'janedoe@example.com'},
    { 'username': 'John Doe', 'email': 'johndoe@example.com'}
  ]
  return json.dumps({
    'results': users
  })
  
@app.route('/contents', methods=['GET'])
def get_all_contents():
    contents = Content.query.all()
    contents_data = []  # สร้างลิสต์เปล่าเพื่อเก็บข้อมูลทั้งหมด
    for content in contents:
        content_data = {  # สร้าง dictionary สำหรับข้อมูลแต่ละรายการ
            'id': content.id,
            'title': content.title,
            'detail': content.detail,
            'owner': content.sub
        }
        contents_data.append(content_data)  # เพิ่มข้อมูลแต่ละรายการลงในลิสต์
    return jsonify({'contents': contents_data}) 
  
@app.route('/content', methods=['POST'])
def create_content():
  
    title = request.form.get('title')
    detail = request.form.get('detail')
    sub = request.form.get('sub')
    
    if None in [ title, detail, sub ]:
      return json.dumps({
        "error": "invalid_request"
      }), 400
    
    content = Content(
                        title=title,
                        detail=detail,
                        sub=sub
                      )
    db.session.add(content)
    db.session.commit()
    # title = post_data['title']
    # content = post_data['content']
    
    content =  Content.query.filter_by(title=title,sub=sub).first()
    if not content:
      return json.dumps({
          'error': 'content not found'
      }), 500
    
    return json.dumps({
        'message': 'Post created successfully',
        'title': content.title,
        'detail': content.detail,
        'sub': content.sub
    }), 201  # 201 status code indicates successful creation of a resource

if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(port = 5002, debug = True)
