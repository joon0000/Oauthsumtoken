import cryptography
import jwt

ISSUER = 'sample-auth-server'

with open('public.pem', 'rb') as f:
  public_key = f.read()

def verify_access_token(access_token):
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

    print("Token is valid.")
    print(decoded_token)
    return True


