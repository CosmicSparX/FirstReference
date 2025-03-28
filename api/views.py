from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import transaction
from django.utils import timezone
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from .models import (
    Applicant, IdentityVerification, AddressVerification,
    AcademicVerification, EmploymentVerification, CreditReport,
    ProfessionalLicense, ReferenceVerification, VerificationStatus,
    CandidateUser, OrganizationUser
)
from .serializers import (
    ApplicantSerializer, ApplicantListSerializer, ApplicantDetailSerializer,
    IdentityVerificationSerializer, AddressVerificationSerializer,
    AcademicVerificationSerializer, EmploymentVerificationSerializer,
    CreditReportSerializer, ProfessionalLicenseSerializer,
    ReferenceVerificationSerializer, VerificationStatusSerializer,
    AdminVerificationSerializer, CandidateUserSerializer,
    OrganizationUserSerializer,
    CandidateLoginSerializer,
    OrganizationLoginSerializer
)


class CandidateUserViewSet(viewsets.GenericViewSet):
    """
    ViewSet for Candidate User operations
    Handles registration, login, and unique identifier checks
    """
    queryset = CandidateUser.objects.all()
    serializer_class = CandidateUserSerializer
    permission_classes = [permissions.AllowAny]

    @action(detail=False, methods=['POST'])
    def check_email(self, request):
        """
        Check if email already exists in the database

        Request Body:
        {
            "email": "example@email.com"
        }
        """
        email = request.data.get('email', '').strip()

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({
                'exists': False,
                'message': 'Invalid email format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if email exists
        email_exists = CandidateUser.objects.filter(email=email).exists()

        return Response({
            'exists': email_exists,
            'message': 'Email already registered' if email_exists else 'Email is available'
        })

    @action(detail=False, methods=['POST'])
    def check_mobile(self, request):
        """
        Check if mobile number already exists in the database

        Request Body:
        {
            "mobile": "1234567890"
        }
        """
        mobile = request.data.get('mobile', '').strip()

        # Basic mobile number validation
        if not mobile.isdigit() or len(mobile) < 10:
            return Response({
                'exists': False,
                'message': 'Invalid mobile number format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if mobile exists
        mobile_exists = CandidateUser.objects.filter(mobile=mobile).exists()

        return Response({
            'exists': mobile_exists,
            'message': 'Mobile number already registered' if mobile_exists else 'Mobile number is available'
        })

    @action(detail=False, methods=['POST'])
    def login(self, request):
        """
        Login endpoint for candidate users

        Request Body:
        {
            "mobile": "1234567890",
            "password": "userpassword"
        }
        """
        serializer = CandidateLoginSerializer(data=request.data)

        if serializer.is_valid():
            mobile = serializer.validated_data.get('mobile')
            password = serializer.validated_data.get('password')

            # Authenticate user
            user = authenticate(username=mobile, password=password)

            if user:
                # Generate or get existing token
                token, _ = Token.objects.get_or_create(user=user)

                return Response({
                    'token': token.key,
                    'user_id': user.id,
                    'name': user.name,
                    'mobile': user.mobile,
                    'email': user.email
                })

            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['POST'])
    def register(self, request):
        """
        Register a new candidate user

        Request Body:
        {
            "name": "Full Name",
            "mobile": "1234567890",
            "email": "example@email.com",
            "date_of_birth": "YYYY-MM-DD",
            "password1": "password",
            "password2": "password"
        }
        """
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Create user
            user = serializer.save()

            # Generate token
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                'token': token.key,
                'user_id': user.id,
                'name': user.name,
                'mobile': user.mobile,
                'email': user.email
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrganizationUserViewSet(viewsets.GenericViewSet):
    """
    ViewSet for Organization User operations
    Handles registration, login, and unique identifier checks
    """
    queryset = OrganizationUser.objects.all()
    serializer_class = OrganizationUserSerializer
    permission_classes = [permissions.AllowAny]

    @action(detail=False, methods=['POST'])
    def check_email(self, request):
        """
        Check if email already exists in the database

        Request Body:
        {
            "email": "example@email.com"
        }
        """
        email = request.data.get('email', '').strip()

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({
                'exists': False,
                'message': 'Invalid email format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if email exists
        email_exists = OrganizationUser.objects.filter(email=email).exists()

        return Response({
            'exists': email_exists,
            'message': 'Email already registered' if email_exists else 'Email is available'
        })

    @action(detail=False, methods=['POST'])
    def check_mobile(self, request):
        """
        Check if mobile number already exists in the database

        Request Body:
        {
            "mobile": "1234567890"
        }
        """
        mobile = request.data.get('mobile', '').strip()

        # Basic mobile number validation
        if not mobile.isdigit() or len(mobile) < 10:
            return Response({
                'exists': False,
                'message': 'Invalid mobile number format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if mobile exists
        mobile_exists = OrganizationUser.objects.filter(mobile=mobile).exists()

        return Response({
            'exists': mobile_exists,
            'message': 'Mobile number already registered' if mobile_exists else 'Mobile number is available'
        })

    @action(detail=False, methods=['POST'])
    def login(self, request):
        """
        Login endpoint for organization users

        Request Body:
        {
            "mobile": "1234567890",
            "password": "userpassword"
        }
        """
        serializer = OrganizationLoginSerializer(data=request.data)

        if serializer.is_valid():
            mobile = serializer.validated_data.get('mobile')
            password = serializer.validated_data.get('password')

            # Authenticate user
            user = authenticate(username=mobile, password=password)

            if user:
                # Generate or get existing token
                token, _ = Token.objects.get_or_create(user=user)

                return Response({
                    'token': token.key,
                    'user_id': user.id,
                    'name': user.name,
                    'mobile': user.mobile,
                    'email': user.email
                })

            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['POST'])
    def register(self, request):
        """
        Register a new organization user

        Request Body:
        {
            "name": "Organization Name",
            "mobile": "1234567890",
            "email": "example@email.com",
            "date_of_birth": "YYYY-MM-DD",
            "password1": "password",
            "password2": "password"
        }
        """
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Create user
            user = serializer.save()

            # Generate token
            token, _ = Token.objects.get_or_create(user=user)

            return Response({
                'token': token.key,
                'user_id': user.id,
                'name': user.name,
                'mobile': user.mobile,
                'email': user.email
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ApplicantViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing applicant records and all related verification data.

    Provides CRUD operations for applicants and custom actions for managing
    related verification data like identity, address, academics, etc.
    """
    queryset = Applicant.objects.all().order_by('-created_at')
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'email', 'position']
    ordering_fields = ['created_at', 'name', 'position']

    def get_serializer_class(self):
        if self.action == 'list':
            return ApplicantListSerializer
        elif self.action == 'retrieve':
            return ApplicantDetailSerializer
        return ApplicantSerializer

    def get_permissions(self):
        """
        Apply different permissions based on action:
        - Admin-only for destroy and verification actions
        - Authenticated users for other actions
        """
        if self.action in ['destroy', 'verify_record']:
            return [permissions.IsAdminUser()]
        return [permissions.IsAuthenticated()]

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='identity')
    def add_identity(self, request, pk=None):
        """Add or update identity verification information"""
        applicant = self.get_object()
        serializer = IdentityVerificationSerializer(data=request.data)

        if serializer.is_valid():
            # Update if exists, create if doesn't
            identity, created = IdentityVerification.objects.update_or_create(
                applicant=applicant,
                defaults=serializer.validated_data
            )

            # Update verification status if not yet started
            self._update_verification_status(applicant)

            return Response(
                IdentityVerificationSerializer(identity).data,
                status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='address')
    def add_address(self, request, pk=None):
        """Add or update address verification information"""
        applicant = self.get_object()
        serializer = AddressVerificationSerializer(data=request.data)

        if serializer.is_valid():
            address, created = AddressVerification.objects.update_or_create(
                applicant=applicant,
                defaults=serializer.validated_data
            )

            self._update_verification_status(applicant)

            return Response(
                AddressVerificationSerializer(address).data,
                status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='academic')
    def add_academic(self, request, pk=None):
        """Add academic verification record"""
        applicant = self.get_object()
        serializer = AcademicVerificationSerializer(data=request.data)

        if serializer.is_valid():
            academic = AcademicVerification.objects.create(
                applicant=applicant,
                **serializer.validated_data
            )

            self._update_verification_status(applicant)

            return Response(
                AcademicVerificationSerializer(academic).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['put', 'patch'], url_path='academic/(?P<academic_id>[^/.]+)')
    def update_academic(self, request, pk=None, academic_id=None):
        """Update specific academic record"""
        applicant = self.get_object()
        academic = get_object_or_404(AcademicVerification, id=academic_id, applicant=applicant)

        serializer = AcademicVerificationSerializer(
            academic,
            data=request.data,
            partial=request.method == 'PATCH'
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'], url_path='academic/(?P<academic_id>[^/.]+)')
    def delete_academic(self, request, pk=None, academic_id=None):
        """Delete specific academic record"""
        applicant = self.get_object()
        academic = get_object_or_404(AcademicVerification, id=academic_id, applicant=applicant)
        academic.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='employment')
    def add_employment(self, request, pk=None):
        """Add employment verification record"""
        applicant = self.get_object()
        serializer = EmploymentVerificationSerializer(data=request.data)

        if serializer.is_valid():
            employment = EmploymentVerification.objects.create(
                applicant=applicant,
                **serializer.validated_data
            )

            self._update_verification_status(applicant)

            return Response(
                EmploymentVerificationSerializer(employment).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['put', 'patch'], url_path='employment/(?P<employment_id>[^/.]+)')
    def update_employment(self, request, pk=None, employment_id=None):
        """Update specific employment record"""
        applicant = self.get_object()
        employment = get_object_or_404(EmploymentVerification, id=employment_id, applicant=applicant)

        serializer = EmploymentVerificationSerializer(
            employment,
            data=request.data,
            partial=request.method == 'PATCH'
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'], url_path='employment/(?P<employment_id>[^/.]+)')
    def delete_employment(self, request, pk=None, employment_id=None):
        """Delete specific employment record"""
        applicant = self.get_object()
        employment = get_object_or_404(EmploymentVerification, id=employment_id, applicant=applicant)
        employment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='credit')
    def add_credit(self, request, pk=None):
        """Add or update credit report information"""
        applicant = self.get_object()
        serializer = CreditReportSerializer(data=request.data)

        if serializer.is_valid():
            credit, created = CreditReport.objects.update_or_create(
                applicant=applicant,
                defaults=serializer.validated_data
            )

            self._update_verification_status(applicant)

            return Response(
                CreditReportSerializer(credit).data,
                status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='license')
    def add_license(self, request, pk=None):
        """Add professional license verification record"""
        applicant = self.get_object()
        serializer = ProfessionalLicenseSerializer(data=request.data)

        if serializer.is_valid():
            license = ProfessionalLicense.objects.create(
                applicant=applicant,
                **serializer.validated_data
            )

            self._update_verification_status(applicant)

            return Response(
                ProfessionalLicenseSerializer(license).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['put', 'patch'], url_path='license/(?P<license_id>[^/.]+)')
    def update_license(self, request, pk=None, license_id=None):
        """Update specific license record"""
        applicant = self.get_object()
        license = get_object_or_404(ProfessionalLicense, id=license_id, applicant=applicant)

        serializer = ProfessionalLicenseSerializer(
            license,
            data=request.data,
            partial=request.method == 'PATCH'
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'], url_path='license/(?P<license_id>[^/.]+)')
    def delete_license(self, request, pk=None, license_id=None):
        """Delete specific license record"""
        applicant = self.get_object()
        license = get_object_or_404(ProfessionalLicense, id=license_id, applicant=applicant)
        license.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='reference')
    def add_reference(self, request, pk=None):
        """Add reference verification record"""
        applicant = self.get_object()
        serializer = ReferenceVerificationSerializer(data=request.data)

        if serializer.is_valid():
            reference = ReferenceVerification.objects.create(
                applicant=applicant,
                **serializer.validated_data
            )

            self._update_verification_status(applicant)

            return Response(
                ReferenceVerificationSerializer(reference).data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['put', 'patch'], url_path='reference/(?P<reference_id>[^/.]+)')
    def update_reference(self, request, pk=None, reference_id=None):
        """Update specific reference record"""
        applicant = self.get_object()
        reference = get_object_or_404(ReferenceVerification, id=reference_id, applicant=applicant)

        serializer = ReferenceVerificationSerializer(
            reference,
            data=request.data,
            partial=request.method == 'PATCH'
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'], url_path='reference/(?P<reference_id>[^/.]+)')
    def delete_reference(self, request, pk=None, reference_id=None):
        """Delete specific reference record"""
        applicant = self.get_object()
        reference = get_object_or_404(ReferenceVerification, id=reference_id, applicant=applicant)
        reference.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='status')
    def update_status(self, request, pk=None):
        """Update verification status"""
        applicant = self.get_object()
        serializer = VerificationStatusSerializer(data=request.data)

        if serializer.is_valid():
            status_obj, created = VerificationStatus.objects.update_or_create(
                applicant=applicant,
                defaults={
                    **serializer.validated_data,
                    'assigned_to': request.user if 'assigned_to' not in serializer.validated_data else
                    serializer.validated_data['assigned_to']
                }
            )

            # If status is 'verified' or 'rejected', set completed_at timestamp
            if status_obj.status in ['verified', 'rejected'] and not status_obj.completed_at:
                status_obj.completed_at = timezone.now()
                status_obj.save()

            return Response(
                VerificationStatusSerializer(status_obj).data,
                status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    @action(detail=True, methods=['post'], url_path='verify')
    def verify_record(self, request, pk=None):
        """Admin action to verify a specific record"""
        applicant = self.get_object()
        serializer = AdminVerificationSerializer(data=request.data)

        if serializer.is_valid():
            verification_type = serializer.validated_data['verification_type']
            verification_id = serializer.validated_data['verification_id']
            verified = serializer.validated_data['verified']
            notes = serializer.validated_data.get('notes', '')

            # Process verification based on type
            if verification_type == 'identity':
                obj = get_object_or_404(IdentityVerification, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.save()
            elif verification_type == 'address':
                obj = get_object_or_404(AddressVerification, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.save()
            elif verification_type == 'academic':
                obj = get_object_or_404(AcademicVerification, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.save()
            elif verification_type == 'employment':
                obj = get_object_or_404(EmploymentVerification, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.save()
            elif verification_type == 'credit':
                obj = get_object_or_404(CreditReport, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.save()
            elif verification_type == 'license':
                obj = get_object_or_404(ProfessionalLicense, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.save()
            elif verification_type == 'reference':
                obj = get_object_or_404(ReferenceVerification, id=verification_id, applicant=applicant)
                obj.verified = verified
                obj.verification_date = timezone.now() if verified else None
                obj.verification_notes = notes
                obj.save()
            elif verification_type == 'status':
                obj, created = VerificationStatus.objects.get_or_create(applicant=applicant)
                obj.status = 'verified' if verified else 'rejected'
                obj.notes = notes
                obj.completed_at = timezone.now()
                obj.save()

            self._check_overall_verification(applicant)

            return Response({'status': 'verification updated'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'], url_path='summary')
    def get_summary(self, request, pk=None):
        """Get verification summary for applicant"""
        applicant = self.get_object()

        # Get counts for each verification type
        academics_count = AcademicVerification.objects.filter(applicant=applicant).count()
        academics_verified = AcademicVerification.objects.filter(applicant=applicant, verified=True).count()

        employments_count = EmploymentVerification.objects.filter(applicant=applicant).count()
        employments_verified = EmploymentVerification.objects.filter(applicant=applicant, verified=True).count()

        licenses_count = ProfessionalLicense.objects.filter(applicant=applicant).count()
        licenses_verified = ProfessionalLicense.objects.filter(applicant=applicant, verified=True).count()

        references_count = ReferenceVerification.objects.filter(applicant=applicant).count()
        references_verified = ReferenceVerification.objects.filter(applicant=applicant, verified=True).count()

        # Check required one-to-one fields
        try:
            identity_verified = applicant.identity.verified
        except:
            identity_verified = False

        try:
            address_verified = applicant.address.verified
        except:
            address_verified = False

        try:
            credit_verified = applicant.credit.verified
        except:
            credit_verified = False

        # Get overall status
        try:
            overall_status = applicant.status.get_status_display()
        except:
            overall_status = "Not Started"

        summary = {
            'applicant_id': applicant.id,
            'applicant_name': applicant.name,
            'overall_status': overall_status,
            'verification_details': {
                'identity': identity_verified,
                'address': address_verified,
                'academics': {
                    'total': academics_count,
                    'verified': academics_verified,
                    'percentage': round((academics_verified / academics_count * 100) if academics_count > 0 else 0, 1)
                },
                'employments': {
                    'total': employments_count,
                    'verified': employments_verified,
                    'percentage': round(
                        (employments_verified / employments_count * 100) if employments_count > 0 else 0, 1)
                },
                'credit': credit_verified,
                'licenses': {
                    'total': licenses_count,
                    'verified': licenses_verified,
                    'percentage': round((licenses_verified / licenses_count * 100) if licenses_count > 0 else 0, 1)
                },
                'references': {
                    'total': references_count,
                    'verified': references_verified,
                    'percentage': round((references_verified / references_count * 100) if references_count > 0 else 0,
                                        1)
                }
            },
            'created_at': applicant.created_at,
            'last_updated': applicant.updated_at
        }

        return Response(summary)

    def _update_verification_status(self, applicant):
        """Update verification status to in_progress if not already set"""
        status_obj, created = VerificationStatus.objects.get_or_create(
            applicant=applicant,
            defaults={'status': 'pending'}
        )

        if created or status_obj.status == 'pending':
            status_obj.status = 'in_progress'
            status_obj.save()

    def _check_overall_verification(self, applicant):
        """Check if all verifications are complete and update overall status"""
        # Get verification status object
        try:
            status_obj = applicant.status
        except VerificationStatus.DoesNotExist:
            return

        # Skip if already verified or rejected
        if status_obj.status in ['verified', 'rejected']:
            return

        # Check all required verifications
        try:
            if not applicant.identity.verified:
                return
        except:
            return

        try:
            if not applicant.address.verified:
                return
        except:
            return

        # Check all academics
        academics = AcademicVerification.objects.filter(applicant=applicant)
        if academics.exists() and academics.filter(verified=False).exists():
            return

        # Check all employments
        employments = EmploymentVerification.objects.filter(applicant=applicant)
        if employments.exists() and employments.filter(verified=False).exists():
            return

        # Check credit report if exists
        try:
            if applicant.credit and not applicant.credit.verified:
                return
        except:
            pass  # Credit report might be optional

        # Check all licenses
        licenses = ProfessionalLicense.objects.filter(applicant=applicant)
        if licenses.exists() and licenses.filter(verified=False).exists():
            return

        # Check all references
        references = ReferenceVerification.objects.filter(applicant=applicant)
        if references.exists() and references.filter(verified=False).exists():
            return

        # If we got here, all verifications are complete
        status_obj.status = 'verified'
        status_obj.completed_at = timezone.now()
        status_obj.save()