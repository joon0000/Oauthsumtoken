import base64
import cryptography
import json
import jwt
import secrets
import time
#test
from cryptography.fernet import Fernet

# KEY = Fernet.generate_key()
KEY = b'YHD1m3rq3K-x6RxT1MtuGzvyLz4EWIJAEkRtBRycDHA='

ISSUER = 'sample-auth-server'
CODE_LIFE_SPAN = 600
JWT_LIFE_SPAN_ACCESS_TOKEN = 120
JWT_LIFE_SPAN_REFRESH_TOKEN = 2000

RESOURCE_PATH = "http://127.0.0.1:5002"

authorization_codes = {}

f = Fernet(KEY)

with open('private.pem', 'rb') as file:
  private_key = file.read()

def generate_access_token(username,client_id,scope):
  payload = {
    "iss": ISSUER,
    'sub': username,
    'aud': RESOURCE_PATH,
    'iat': time.time(),    
    "exp": time.time() + JWT_LIFE_SPAN_ACCESS_TOKEN,
    'client_id': client_id,
    "scope": scope
  }
  access_token = jwt.encode(payload, private_key, algorithm = 'RS256')
  return access_token

def generate_refresh_token(exp):
  payload = {
    "iss": ISSUER,
    "exp": exp
  }
  
  refresh_token = jwt.encode(payload, private_key, algorithm = 'RS256')
  return refresh_token

def generate_authorization_code(client_id, redirect_url):
  f = Fernet(KEY)
  authorization_code = f.encrypt(json.dumps({
    "client_id": client_id,
    "redirect_url": redirect_url,
  }).encode())

  authorization_code = base64.b64encode(authorization_code, b'-_').decode().replace('=', '')

  expiration_date = time.time() + CODE_LIFE_SPAN

  authorization_codes[authorization_code] = {
    "client_id": client_id,
    "redirect_url": redirect_url,
    "exp": expiration_date
  }

  return authorization_code

def verify_authorization_code(authorization_code, client_id, redirect_url):
  f = Fernet(KEY)
  record = authorization_codes.get(authorization_code)
  if not record:
    return False

  client_id_in_record = record.get('client_id')
  redirect_url_in_record = record.get('redirect_url')
  exp = record.get('exp')

  if client_id != client_id_in_record or \
     redirect_url != redirect_url_in_record:
    return False

  if exp < time.time():
    return False

  del authorization_codes[authorization_code]

  return True

with open('public.pem', 'rb') as filepub:
  public_key = filepub.read()

def verify_token(token):
    try:
        decoded_token = jwt.decode(
            token,
            public_key,
            issuer=ISSUER,
            algorithms=['RS256'],  # Specify the algorithm(s) used for encoding
        )
    except jwt.ExpiredSignatureError:
        msg = "Token has expired."
        print("Token has expired.")
        return False, msg
    except jwt.InvalidTokenError as e:
        msg = f"Invalid token: {e}"
        print(f"Invalid token: {e}")
        return False, msg
    except Exception as e:
        msg = f"Error decoding token: {e}"
        print(f"Error decoding token: {e}")
        return False, msg

    print("Token is valid.")
    msg = "Token is valid."
    print(decoded_token)
    return True, msg
  
def decode_token(access_token):
    try:
        decoded_token = jwt.decode(
            access_token,
            public_key,
            audience=RESOURCE_PATH,
            issuer=ISSUER,
            algorithms=['RS256'],  # Specify the algorithm(s) used for encoding
        )
    except jwt.ExpiredSignatureError:
        return False, "Token has expired."
    except jwt.InvalidTokenError as e:
        return False, f"Invalid token: {e}"
    except Exception as e:
        return False, f"Error decoding token: {e}"
    return True, decoded_token
