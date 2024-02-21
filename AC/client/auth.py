import cryptography
import jwt

ISSUER = 'sample-auth-server'
CLIENT_ID = 'sample-client-id'

with open('public.pem', 'rb') as f:
  public_key = f.read()
  
def get_exp(access_token):
    try:
        decoded_token = jwt.decode(
            access_token,
            public_key,
            issuer=ISSUER,
            algorithms=['RS256'],  # Specify the algorithm(s) used for encoding
        )
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return False
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return False
    except Exception as e:
        print(f"Error decoding token: {e}")
        return False
    return decoded_token.get('exp')

def decode_token(access_token):
    try:
        decoded_token = jwt.decode(
            access_token,
            public_key,
            audience=CLIENT_ID,
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

def verify_id_token(id_token):
    try:
        decoded_token = jwt.decode(
            id_token,
            public_key,
            audience=CLIENT_ID,
            issuer=ISSUER,
            algorithms=['RS256'],  # Specify the algorithm(s) used for encoding
        )
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return False
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return False
    except Exception as e:
        print(f"Error decoding token: {e}")
        return False

    print("Token is valid.")
    print(decoded_token)
    return True
