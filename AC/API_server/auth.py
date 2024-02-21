import cryptography
import jwt

ISSUER = 'sample-auth-server'
RESOURCE_PATH = "http://127.0.0.1:5002"

with open('public.pem', 'rb') as f:
  public_key = f.read()

def verify_token(access_token):
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

def check_scope(token, method):
  print(f'token: \n{token}')
  print(f'method: {method}')
#   print(f'scope: \n{token.get('scope')}')
  
  scopes = token.get('scope')
  scopes = scopes.split()
  
  print(f'scopes split: \n{scopes}')
  
  if method == 'GET':
    for s in scopes:
      print(s)
      if s == 'READ' or s == 'READWRITE':
        return True
    return False
  elif method == 'POST':
    for s in scopes:
      if s == 'WRITE' or s == 'READWRITE':
        print(s)
        return True
    return False
  else:
    return False


