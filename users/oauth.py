import logging
from base64 import b64decode
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749.endpoints.pre_configured import Server
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.errors import InvalidRequestFatalError, InvalidTokenError, UnsupportedGrantTypeError, \
    InvalidRequestError, InvalidClientError
import jwt
from oauthlib.oauth2.rfc6749.grant_types.client_credentials import ClientCredentialsGrant
import oauth2_provider.oauth2_validators
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

from users.models import Application

logger = logging.getLogger(__name__)

client_assertion_type_jwt_bearer = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
grant_type_jwt_bearer = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


class InvalidClientAssertionTypeError(InvalidRequestFatalError):
    description = "Invalid client_assertion_type parameter"


class MissingClientAssertionError(InvalidRequestFatalError):
    description = "Missing client_assertion parameter"


class MissingAssertionError(InvalidRequestFatalError):
    description = "Missing assertion parameter"


class CustomOAuth2Validator(OAuth2Validator):
    def authenticate_client(self, request, *args, **kwargs):
        try:
            client_assertion_type = getattr(request, 'client_assertion_type', None)
            grant_type = getattr(request, 'grant_type', None)
            if grant_type == grant_type_jwt_bearer:
                assertion = getattr(request, 'assertion', None)
                if assertion is None:
                    raise MissingClientAssertionError()
                token_no_verify = jwt.decode(assertion, options={"verify_signature": False})
                client_id = token_no_verify['iss']
            else:
                if client_assertion_type != client_assertion_type_jwt_bearer:
                    raise InvalidClientAssertionTypeError(f"Only {client_assertion_type_jwt_bearer} is supported")
                assertion = getattr(request, 'client_assertion', None)
                if assertion is None:
                    raise MissingAssertionError()
                token_no_verify = jwt.decode(assertion, options={"verify_signature": False})
                client_id = token_no_verify['sub']

            application: Application = self._load_application(client_id, request)
            public_key_bytes = b64decode(f"{application.public_key}==")
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            jwt.decode(assertion, public_key, algorithms="EdDSA")
        except AttributeError as e:
            print(e)
            return False
        except InvalidTokenError as e:
            print(e)
            return False
        return True


class JwtBearerGrant(ClientCredentialsGrant):
    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        oauth2_provider.oauth2_validators.GRANT_TYPE_MAPPING |= {
            grant_type_jwt_bearer: (Application.GRANT_JWT_BEARER,)
        }

        for validator in self.custom_validators.pre_token:
            validator(request)

        if not getattr(request, 'grant_type', None):
            raise InvalidRequestError('Request is missing grant type.',
                                      request=request)

        if not request.grant_type == grant_type_jwt_bearer:
            raise UnsupportedGrantTypeError(request=request)

        for param in ('grant_type', 'scope'):
            if param in request.duplicate_params:
                raise InvalidRequestError(description='Duplicate %s parameter.' % param,
                                          request=request)

        logger.debug('Authenticating client, %r.', request)
        if not self.request_validator.authenticate_client(request):
            logger.debug('Client authentication failed, %r.', request)
            raise InvalidClientError(request=request)
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError('Authenticate client must set the '
                                          'request.client.client_id attribute '
                                          'in authenticate_client.')
        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        request.client_id = request.client_id or request.client.client_id
        logger.debug('Authorizing access to client %r.', request.client_id)
        self.validate_scopes(request)

        for validator in self.custom_validators.post_token:
            validator(request)

    def create_token_response(self, request, token_handler):
        if request.scopes is None:
            request.scopes = []
        return super().create_token_response(request, token_handler)


class CustomOAuthServer(Server):
    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):

        def generate_token(request) -> str:
            private_key_path = '/var/run/secrets/eddsa-private-key'
            with open(private_key_path) as file:
                private_key_str = file.read()
            private_key = Ed25519PrivateKey.from_private_bytes(b64decode(f"{private_key_str}=="))
            token = {
                'exp': (datetime.now() + timedelta(seconds=token_expires_in)).timestamp(),
                'iss': 'djangotest.com',
                'idc': 'logged_in_customer_id',
                'sub': 'logged_in_user_id',
                'idd': 'logged_in_department_id',
                'perm': ['permission1', 'permission2']
            }
            return jwt.encode(token, private_key, algorithm='EdDSA')

        self.jwt_bearer_grant = JwtBearerGrant(request_validator)

        if refresh_token_generator is None:
            refresh_token_generator = random_token_generator

        super().__init__(request_validator, token_expires_in,
                         generate_token, refresh_token_generator,
                         *args, **kwargs)

        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                               grant_types={
                                   'authorization_code': self.auth_grant,
                                   'password': self.password_grant,
                                   'client_credentials': self.credentials_grant,
                                   'refresh_token': self.refresh_grant,
                                   grant_type_jwt_bearer: self.jwt_bearer_grant
                               },
                               default_token_type=self.bearer)
