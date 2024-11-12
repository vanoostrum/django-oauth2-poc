from django.contrib.auth.models import AbstractUser
from oauth2_provider.models import AbstractApplication, AbstractAccessToken, AbstractIDToken, AbstractRefreshToken, \
    AbstractGrant
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    pass


class Application(AbstractApplication):
    GRANT_JWT_BEARER = 'jwt-bearer'
    GRANT_TYPES = (
        (AbstractApplication.GRANT_AUTHORIZATION_CODE, _("Authorization code")),
        (GRANT_JWT_BEARER, _('JWT Bearer'))
    )
    CLIENT_TYPES = (
        (AbstractApplication.CLIENT_CONFIDENTIAL, _("Confidential")),
    )
    client_id = models.CharField(max_length=100, unique=True, db_index=True)
    client_secret = None
    hash_client_secret = None
    public_key = models.CharField(max_length=255, blank=True, default='')
    authorization_grant_type = models.CharField(max_length=32, choices=GRANT_TYPES)
    client_type = models.CharField(max_length=32, default=AbstractApplication.CLIENT_CONFIDENTIAL,
                                   choices=CLIENT_TYPES, editable=False)
    algorithm = models.CharField(max_length=5, choices=AbstractApplication.ALGORITHM_TYPES,
                                 default=AbstractApplication.NO_ALGORITHM, blank=True, editable=False)


class AccessToken(AbstractAccessToken):
    pass


class IdToken(AbstractIDToken):
    pass


class RefreshToken(AbstractRefreshToken):
    pass


class Grant(AbstractGrant):
    pass
