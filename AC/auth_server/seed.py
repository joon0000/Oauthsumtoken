# seed.py

import datetime
import secrets
import time
from AC_auth_server import app, db, User, Client, Role, Code

def generate_role_token(length=32):
    # สร้าง Random String ที่มีความยาวตามที่กำหนด (ค่าเริ่มต้นคือ 32 ตัวอักษร)
    token = secrets.token_urlsafe(length)
    return token

with app.app_context():

    # Create an empty list
    users = []

    # Add some Pet instances to the list
    users.append(User(
                        username = "kawn", email = "kawn@gmail.com", password = 'kawn',
                        name = "kawinitda", birthday = datetime.date(2001, 1, 1), phone_number = "0887654321",admin=True
                    ))
    
    users.append(User(
                        username = "test", email = "test@gmail.com", password = 'test',
                        name = "test", birthday = datetime.date(1991, 4, 1), phone_number = "0812345678"))
    
    clients = []
    
    clients.append(Client(client_id     = 'sample-client-id',
                          client_secret = 'sample-client-secret',
                          redirect_url  = 'http://127.0.0.1:5000/callback'
                          ))
    
    clients.append(Client(client_id     = 'test',
                          client_secret = 'test',
                          redirect_url  = 'http://127.0.0.1:5004/callback'
                          ))
    
    role = Role( name = 'admin', ttl=1200, permissions='admin')
    
    code = Code(        
                  code = generate_role_token(),
                  exp= time.time() + 1200,
                  role_id = 1
                  )

    # Insert each Pet in the list into the database table
    db.session.add(role)
    db.session.add(code)
    db.session.add_all(users)
    db.session.add_all(clients)

    # Commit the transaction
    db.session.commit()
