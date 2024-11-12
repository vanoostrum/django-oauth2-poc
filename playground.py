import random
import string
from base64 import b64encode, urlsafe_b64encode, b64decode
import hashlib
from datetime import datetime
from unittest import TestCase
from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from dateutil.relativedelta import relativedelta
import jwt

import requests

class PlaygroundTest(TestCase):
    redirect_uri = "http://localhost"
    code_verifier = '05BX5FKF48WYI0Q1X504TFOBA7GOMVWIUTXQIIH66STNUF8M9Q7JT3IL8KLLLKAT5P5154BBMD'

    clients = {
        'person': {
            'private_key': "KkCDTwdtvFsLK/Y7pJQEzpeRyTM5u54SvkIGfhVsMjI=",
            'public_key': "LpTl4Gf3Bhq9Dy8hikl2JTPmVGDkH5O4vGc0FdNzGH8="
        },
        'computer': {
            'private_key': "BJGvH8XabRwdeDXxy8kXS+Y7ruzTBzjrn3CP6Kb5EjU=",
            'public_key': "I5AeZO+doRFq/b3ucEQHWvYp72B1r0Kly7vnummE5gE="
        },
        'auth.service.com': {
            'private_key': "GmtQ7R7i+F7nMvxS0fQO2DlvD0jEBfbJXhS8NXg9E5k=",
            'public_key': "7dn23Kj3eYCEPO5sVL1TACXLxPf8ImuJntSlkkTYTa0="
        }
    }

    def test_gen_code_verifier(self):
        generated_code_verifier = ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(43, 128)))
        print(generated_code_verifier)

    def test_authorize(self):
        code_challenge = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        code_challenge = urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')

        params = {
            'response_type': 'code',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'client_id': 'person',
            'redirect_uri': self.redirect_uri,
        }

        request = requests.Request("GET", "http://localhost:8082/oauth/authorize", params=params)
        print(request.prepare().url)

    def test_token_authorization_code(self):
        client_id = 'person'
        code = "hD8556RCxCgrowPiFPymvSNIcDSXVe"
        headers = {
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'client_id': client_id,
            'code': code,
            'client_assertion_type': "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            'client_assertion': self.test_client_token(client_id),
            'code_verifier': self.code_verifier,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code'
        }

        response = requests.post('http://localhost:8082/oauth/token/', data, headers=headers)
        self.validate_access_token(response)

    def test_token_jwt_bearer(self):
        headers = {
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'assertion': self.test_client_token('computer'),
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        }

        response = requests.post('http://localhost:8082/oauth/token/', data, headers=headers)
        self.validate_access_token(response)

    def validate_access_token(self, response):
        access_token = response.json()['access_token']
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(f"{self.clients['auth.service.com']['public_key']}=="))
        decoded_token = jwt.decode(access_token, public_key, algorithms=["EdDSA"])
        print(decoded_token)

    def test_client_token(self, client_id: str):
        token = {
            "iss": client_id,
            # System URL that issued this login token, and trying to obtain access token.
            # MUST be different per environment (dev, accept, prod), and must be pre-registered with authorization server.
            # Issuer will define default customer/department that is utilizing the access token.
            "sub": "user@email.com",
            # Email-address of user to authorize token under.
            # "aud": "djangotest.com",
            # Must match the authorization server. Same as the issuer of the token to be issued.
            "jti": "random jhvqjvbekhbqkvhbdg",
            # Random string ID. Used to prevent re-use. When the same JTI is used, token will not be issued.
            "exp": datetime.now() + relativedelta(minutes=1),
            # Expiry of this client authentication token.
            # Client authentication will be rejected if this timestamp is in the past, or more than 2 minutes in the future.
            # "iat": datetime.now() + relativedelta(seconds=1),
            # Time at which this client authentication token was issued.
            # Client authentication will be rejected of this timestamp is in the future, or more than 2 minutes in the past.
        }

        private_key = Ed25519PrivateKey.from_private_bytes(b64decode(f"{self.clients[client_id]['private_key']}=="))
        return jwt.encode(token, private_key, algorithm="EdDSA")

    @staticmethod
    def test_gen_private_key():
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_key_bytes = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
        encoded_private_key = b64encode(private_key_bytes)
        encoded_public_key = b64encode(public_key.public_bytes_raw())
        print(f"{encoded_private_key=}")
        print(f"{encoded_public_key=}")