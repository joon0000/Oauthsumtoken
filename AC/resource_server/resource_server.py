import json
#import ssl

from auth import verify_access_token
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'  # กำหนด URL ของฐานข้อมูล
db = SQLAlchemy(app)

# สร้างตาราง Owners
class Owner(db.Model):
    owner_id = db.Column(db.Integer, primary_key=True)
    owner_name = db.Column(db.String(100), nullable=False)

# สร้างตาราง Contacts
class Note(db.Model):
    note_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, db.ForeignKey('owner.owner_id'), nullable=False)
    owner = db.relationship('Owner', backref=db.backref('notes', lazy=True))

@app.before_request
def before_request():
  # Checks if the access token is present and valid.
  auth_header = request.headers.get('Authorization')
  if 'Bearer' not in auth_header:
    return json.dumps({
      'error': 'Access token does not exist.'
    }), 400
  
  access_token = auth_header[7:]
  

  if access_token and verify_access_token(access_token):
      pass
  else:
    return json.dumps({
      'error': 'Access token is invalid.'
    }), 400  

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
    
# เรียกดูข้อมูลทั้งหมดของติดต่อ
@app.route('/notes', methods=['GET'])
def get_note_all():
    notes = Note.query.all()
    notes_data = []
    for note in notes:
        note_data = {  # เปลี่ยนชื่อตัวแปร notes_data เป็น note_data
            'id': note.note_id,
            'name': note.name,
            'detail': note.detail,
            'owner': note.owner.owner_name  # แก้ไขการเข้าถึงข้อมูลเจ้าของ
        }
        notes_data.append(note_data)  # เปลี่ยนเป็นการเพิ่มข้อมูล note_data ลงใน notes_data
    return json.dumps({
      'results': notes_data
    }) # แก้ไขให้คืนค่า notes_data ที่ถูกสร้างขึ้นให้กับเบื้องหลัง jsonify
    

if __name__ == '__main__':
  #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
  #context.load_cert_chain('domain.crt', 'domain.key')
  #app.run(port = 5000, debug = True, ssl_context = context)
  app.run(port = 5004, debug = True)
