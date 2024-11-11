from django.urls import path

from users import views
from oauth2_provider import urls as oauth2_urls

app_name = "oauth2_provider"

custom_oauth2_urls = [
    path("applications/register/", views.CustomApplicationRegistration.as_view(), name="register"),
    path("applications/<slug:pk>/update/", views.CustomApplicationUpdate.as_view(), name="update"),
]

urlpatterns = custom_oauth2_urls + oauth2_urls.urlpatterns
