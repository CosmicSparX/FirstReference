from dj_rest_auth.registration.views import RegisterView
from dj_rest_auth.views import LoginView, LogoutView, UserDetailsView
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import ApplicantViewSet

# Create a router and register our viewsets with it
router = DefaultRouter()
router.register(r'applicants', ApplicantViewSet)

urlpatterns = [
    path('/', include(router.urls)),
    path("register/", RegisterView.as_view(), name="rest_register"),
    path("login/", LoginView.as_view(), name="rest_login"),
    path("logout/", LogoutView.as_view(), name="rest_logout"),
    path("user/", UserDetailsView.as_view(), name="rest_user_details"),
]