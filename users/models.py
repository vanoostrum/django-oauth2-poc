from django.contrib.auth.models import AbstractUser
from oauth2_provider.models import AbstractApplication, AbstractAccessToken, AbstractIDToken, AbstractRefreshToken, \
    AbstractGrant
from django.db import models


class User(AbstractUser):
    pass


# TODO:
#  Remove Client_type from form and set default to 'Confidential'
#  Allow only Authorization Code and JWT Bearer Authorization grant types
#  Remove Algorithm from form and set default to ''
class Application(AbstractApplication):
    client_secret = None
    hash_client_secret = None
    public_key = models.CharField(max_length=255, blank=True, default='')


# TODO: Check if the token field (text) is long enough to store a JWT Token
class AccessToken(AbstractAccessToken):
    pass


class IdToken(AbstractIDToken):
    pass


class RefreshToken(AbstractRefreshToken):
    pass


class Grant(AbstractGrant):
    pass
