
from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'

    def ready(self):
        from users import oauth
        from oauth2_provider.views.mixins import OAuthLibMixin
        OAuthLibMixin.server_class = oauth.CustomOAuthServer
        OAuthLibMixin.validator_class = oauth.CustomOAuth2Validator
