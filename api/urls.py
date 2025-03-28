from dj_rest_auth.registration.views import RegisterView
from dj_rest_auth.views import LoginView, LogoutView, UserDetailsView
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import ApplicantViewSet, CandidateUserViewSet, OrganizationUserViewSet

# Create routers
candidate_router = DefaultRouter()
candidate_router.register(r'candidates', CandidateUserViewSet, basename='candidate')

organization_router = DefaultRouter()
organization_router.register(r'organizations', OrganizationUserViewSet, basename='organization')

applicant_router = DefaultRouter()
applicant_router.register(r'applicants', ApplicantViewSet)

urlpatterns = [
    # Candidate Routes
    path('api/candidate/', include(candidate_router.urls)),
    path('api/candidate/check-email/', CandidateUserViewSet.as_view({'post': 'check_email'})),
    path('api/candidate/check-mobile/', CandidateUserViewSet.as_view({'post': 'check_mobile'})),
    path('api/candidate/login/', CandidateUserViewSet.as_view({'post': 'login'})),
    path('api/candidate/register/', CandidateUserViewSet.as_view({'post': 'register'})),

    # Org Routes
    path('api/organization/', include(organization_router.urls)),
    path('api/organization/check-email/', OrganizationUserViewSet.as_view({'post': 'check_email'})),
    path('api/organization/check-mobile/', OrganizationUserViewSet.as_view({'post': 'check_mobile'})),
    path('api/organization/login/', OrganizationUserViewSet.as_view({'post': 'login'})),
    path('api/organization/register/', OrganizationUserViewSet.as_view({'post': 'register'})),

    # Applicant Routes

    path('router/', include(applicant_router.urls)),
    # path("register/", RegisterView.as_view(), name="rest_register"),
    # path("login/", LoginView.as_view(), name="rest_login"),
    # path("logout/", LogoutView.as_view(), name="rest_logout"),
    # path("user/", UserDetailsView.as_view(), name="rest_user_details"),
]
