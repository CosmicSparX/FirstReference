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
    path('candidate/', include(candidate_router.urls)),
    path('candidate/check-email/', CandidateUserViewSet.as_view({'post': 'check_email'})),
    path('candidate/check-phone/', CandidateUserViewSet.as_view({'post': 'check_phone'})),
    path('candidate/login/', CandidateUserViewSet.as_view({'post': 'login'})),
    path('candidate/register/', CandidateUserViewSet.as_view({'post': 'register'})),

    # Org Routes
    path('organization/', include(organization_router.urls)),
    path('organization/check-email/', OrganizationUserViewSet.as_view({'post': 'check_email'})),
    path('organization/check-mobile/', OrganizationUserViewSet.as_view({'post': 'check_phone'})),
    path('organization/login/', OrganizationUserViewSet.as_view({'post': 'login'})),
    path('organization/register/', OrganizationUserViewSet.as_view({'post': 'register'})),

    # Applicant Routes
    path('router/', include(applicant_router.urls)),
]
