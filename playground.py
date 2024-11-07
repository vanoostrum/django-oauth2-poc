import random
import string
import base64
import hashlib
import requests

client_id = "3TAkfotfYERdvb3WUlCTLTczv94luPHYX6hbgYiG"

client_secret = "E7FlVFJvoU0jLJnS5no5tFnf4e2KF7vNNs0qOONbKRozbXKnhesau4afSpY26RQDYzY6QIi2RrAnQzIFkQD1uhC4Ei2PgfSQNiES96oA7SZSfo0YUgDBrxZ5GmONX4Hm"
redirect_uri = "https://localhost:8083/auth"
code_verifier = '8CMO7FO0DA2JLIDGMMK3HUZ6VFQLJ650336CFP98J9YY6YEFODI8MBDG8609YERJJACSFFUEGSG61XXERMA2L5ASJIGTLXYRQTWGWJ8XDUAO14SNDYQ3U75BL2NF'


def gen_code_verifier():
    generated_code_verifier = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(43, 128)))
    print(generated_code_verifier)


def authorize():
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')

    params = {
        'response_type': 'code',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
    }
    response = requests.get("http://localhost:8082/oauth/authorize", params)
    print(response.url)


def token():
    code = "WJ32TpxznUOs7D4UFKJGZmstapXVm1"
    headers = {
        'Cache-Control': 'no-cache',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'code_verifier': code_verifier,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    response = requests.post('http://localhost:8082/oauth/token/', data, headers=headers)
    print(response.url)
    print(response.text)
    print(response.headers)


if __name__ == '__main__':
    token()
