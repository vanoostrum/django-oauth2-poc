from authlib.oauth2.client import OAuth2Client
from authlib.oauth2.rfc6749.wrappers import OAuth2Token
from authlib.integrations.django_oauth2 import AuthorizationServer

from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'


server = AuthorizationServer(OAuth2Client, OAuth2Token)

server.