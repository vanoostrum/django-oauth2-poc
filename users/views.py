from oauth2_provider.views.application import ApplicationRegistration, ApplicationUpdate
from django.forms.models import modelform_factory
from oauth2_provider.models import get_application_model


class CustomApplicationRegistration(ApplicationRegistration):
    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "name",
                "client_id",
                "client_type",
                "authorization_grant_type",
                "public_key",
                "redirect_uris",
                "post_logout_redirect_uris",
                "allowed_origins",
                "algorithm",
            ),
        )


class CustomApplicationUpdate(ApplicationUpdate):
    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "name",
                "client_id",
                "client_type",
                "authorization_grant_type",
                "public_key",
                "redirect_uris",
                "post_logout_redirect_uris",
                "allowed_origins",
                "algorithm",
            ),
        )
