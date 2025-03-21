from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Applicant,
    IdentityVerification,
    AddressVerification,
    AcademicVerification,
    EmploymentVerification,
    CreditReport,
    ProfessionalLicense,
    ReferenceVerification,
    VerificationStatus
)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']


class IdentityVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = IdentityVerification
        fields = [
            'id', 'id_type', 'id_number', 'issue_date', 'expiry_date',
            'issuing_authority', 'id_document', 'verified', 'verification_date'
        ]
        read_only_fields = ['id', 'verified', 'verification_date']


class AddressVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AddressVerification
        fields = [
            'id', 'street_address', 'city', 'state', 'zip_postal_code',
            'country', 'resident_since', 'address_proof', 'verified', 'verification_date'
        ]
        read_only_fields = ['id', 'verified', 'verification_date']


class AcademicVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AcademicVerification
        fields = [
            'id', 'degree', 'field_of_study', 'institution', 'graduation_date',
            'degree_certificate', 'verified', 'verification_date'
        ]
        read_only_fields = ['id', 'verified', 'verification_date']


class EmploymentVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmploymentVerification
        fields = [
            'id', 'company', 'position', 'start_date', 'end_date',
            'supervisor_manager', 'employment_proof', 'verified', 'verification_date'
        ]
        read_only_fields = ['id', 'verified', 'verification_date']


class CreditReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditReport
        fields = [
            'id', 'ssn_id_number', 'credit_documents', 'verified', 'verification_date'
        ]
        read_only_fields = ['id', 'verified', 'verification_date']


class ProfessionalLicenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfessionalLicense
        fields = [
            'id', 'license_type', 'license_number', 'issuing_authority',
            'issue_date', 'expiry_date', 'license_document', 'verified', 'verification_date'
        ]
        read_only_fields = ['id', 'verified', 'verification_date']


class ReferenceVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferenceVerification
        fields = [
            'id', 'full_name', 'relationship', 'company', 'position',
            'email', 'phone', 'reference_document', 'verified',
            'verification_date', 'verification_notes'
        ]
        read_only_fields = ['id', 'verified', 'verification_date', 'verification_notes']


class VerificationStatusSerializer(serializers.ModelSerializer):
    assigned_to = UserSerializer(read_only=True)

    class Meta:
        model = VerificationStatus
        fields = [
            'id', 'status', 'assigned_to', 'notes',
            'created_at', 'updated_at', 'completed_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'completed_at']


# Nested serializers for complete applicant view
class ApplicantDetailSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    identity = IdentityVerificationSerializer(read_only=True)
    address = AddressVerificationSerializer(read_only=True)
    academics = AcademicVerificationSerializer(many=True, read_only=True)
    employments = EmploymentVerificationSerializer(many=True, read_only=True)
    credit = CreditReportSerializer(read_only=True)
    licenses = ProfessionalLicenseSerializer(many=True, read_only=True)
    references = ReferenceVerificationSerializer(many=True, read_only=True)
    status = VerificationStatusSerializer(read_only=True)

    class Meta:
        model = Applicant
        fields = [
            'id', 'user', 'name', 'email', 'phone', 'date_of_birth',
            'position', 'experience', 'created_at', 'updated_at',
            'identity', 'address', 'academics', 'employments',
            'credit', 'licenses', 'references', 'status'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# Basic serializer for list views
class ApplicantListSerializer(serializers.ModelSerializer):
    status_display = serializers.SerializerMethodField()

    class Meta:
        model = Applicant
        fields = [
            'id', 'name', 'email', 'position', 'experience',
            'created_at', 'status_display'
        ]
        read_only_fields = ['id', 'created_at', 'status_display']

    def get_status_display(self, obj):
        try:
            return obj.status.get_status_display()
        except:
            return "Not Started"


# Creation and update serializer
class ApplicantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Applicant
        fields = [
            'id', 'name', 'email', 'phone', 'date_of_birth',
            'position', 'experience', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


# Admin serializer for verification teams
class AdminVerificationSerializer(serializers.ModelSerializer):
    """Serializer for admin verification actions"""
    verification_id = serializers.IntegerField(write_only=True)
    verification_type = serializers.CharField(write_only=True)
    verified = serializers.BooleanField(write_only=True)
    notes = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = Applicant
        fields = ['verification_id', 'verification_type', 'verified', 'notes']

    def validate_verification_type(self, value):
        valid_types = ['identity', 'address', 'academic', 'employment',
                       'credit', 'license', 'reference', 'status']
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid verification type. Must be one of {valid_types}")
        return value