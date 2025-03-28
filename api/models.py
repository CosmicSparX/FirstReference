from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where mobile is the unique identifier
    """

    def create_user(self, mobile, password=None, **extra_fields):
        """
        Create and save a User with the given mobile and password.
        """
        if not mobile:
            raise ValueError('Mobile number must be set')

        user = self.model(mobile=mobile, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile, password=None, **extra_fields):
        """
        Create and save a SuperUser with the given mobile and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        return self.create_user(mobile, password, **extra_fields)


class CandidateUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model for candidates
    """
    # Mobile number validation
    mobile_validator = RegexValidator(
        regex=r'^\d{10}$',
        message="Mobile number must be 10 digits"
    )

    # Basic fields
    name = models.CharField(max_length=255)
    mobile = models.CharField(
        max_length=10,
        unique=True,
        validators=[mobile_validator]
    )
    email = models.EmailField(unique=True)
    date_of_birth = models.DateField()

    # System fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Use mobile as the unique identifier
    USERNAME_FIELD = 'mobile'
    REQUIRED_FIELDS = ['name', 'email', 'date_of_birth']

    objects = CustomUserManager()

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='candidate_users',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='candidate_users',
        blank=True
    )

    def __str__(self):
        return f"{self.name} - {self.mobile}"

    def clean(self):
        """
        Additional validation
        """
        # Ensure unique email and mobile
        if CandidateUser.objects.exclude(pk=self.pk).filter(email=self.email).exists():
            raise ValidationError({'email': 'A user with this email already exists.'})

        if CandidateUser.objects.exclude(pk=self.pk).filter(mobile=self.mobile).exists():
            raise ValidationError({'mobile': 'A user with this mobile number already exists.'})


class OrganizationUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model for organizations
    """
    # Mobile number validation
    mobile_validator = RegexValidator(
        regex=r'^\d{10}$',
        message="Mobile number must be 10 digits"
    )

    # Basic fields
    name = models.CharField(max_length=255)
    mobile = models.CharField(
        max_length=10,
        unique=True,
        validators=[mobile_validator]
    )
    email = models.EmailField(unique=True)
    date_of_birth = models.DateField()

    # Additional organization fields
    organization_type = models.CharField(max_length=100, blank=True, null=True)
    registration_number = models.CharField(max_length=100, blank=True, null=True)

    # System fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Use mobile as the unique identifier
    USERNAME_FIELD = 'mobile'
    REQUIRED_FIELDS = ['name', 'email', 'date_of_birth']

    objects = CustomUserManager()

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='organization_users',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='organization_users',
        blank=True
    )

    def __str__(self):
        return f"{self.name} - {self.mobile}"

    def clean(self):
        """
        Additional validation
        """
        # Ensure unique email and mobile
        if OrganizationUser.objects.exclude(pk=self.pk).filter(email=self.email).exists():
            raise ValidationError({'email': 'A user with this email already exists.'})

        if OrganizationUser.objects.exclude(pk=self.pk).filter(mobile=self.mobile).exists():
            raise ValidationError({'mobile': 'A user with this mobile number already exists.'})


class Applicant(models.Model):
    """Main applicant model containing basic information"""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone = models.CharField(validators=[phone_regex], max_length=17)
    date_of_birth = models.DateField()
    position = models.CharField(max_length=100)
    experience = models.PositiveIntegerField(help_text="Experience in years")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class IdentityVerification(models.Model):
    """Identity verification information"""
    ID_TYPE_CHOICES = [
        ('passport', 'Passport'),
        ('driver_license', 'Driver License'),
        ('national_id', 'National ID'),
        ('other', 'Other'),
    ]

    applicant = models.OneToOneField(Applicant, on_delete=models.CASCADE, related_name='identity')
    id_type = models.CharField(max_length=20, choices=ID_TYPE_CHOICES)
    id_number = models.CharField(max_length=50)
    issue_date = models.DateField()
    expiry_date = models.DateField()
    issuing_authority = models.CharField(max_length=100)
    id_document = models.FileField(upload_to='identity_documents/')
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s {self.get_id_type_display()}"


class AddressVerification(models.Model):
    """Address verification information"""
    applicant = models.OneToOneField(Applicant, on_delete=models.CASCADE, related_name='address')
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    zip_postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    resident_since = models.DateField()
    address_proof = models.FileField(upload_to='address_proofs/')
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s Address"


class AcademicVerification(models.Model):
    """Academic verification information"""
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='academics')
    degree = models.CharField(max_length=100)
    field_of_study = models.CharField(max_length=100)
    institution = models.CharField(max_length=255)
    graduation_date = models.DateField()
    degree_certificate = models.FileField(upload_to='degree_certificates/')
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s {self.degree} from {self.institution}"


class EmploymentVerification(models.Model):
    """Employment verification information"""
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='employments')
    company = models.CharField(max_length=255)
    position = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    supervisor_manager = models.CharField(max_length=100, blank=True, null=True)
    employment_proof = models.FileField(upload_to='employment_proofs/')
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name} at {self.company}"


class CreditReport(models.Model):
    """Credit report information"""
    applicant = models.OneToOneField(Applicant, on_delete=models.CASCADE, related_name='credit')
    ssn_id_number = models.CharField(max_length=20)
    credit_documents = models.FileField(upload_to='credit_documents/', blank=True, null=True)
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s Credit Report"


class ProfessionalLicense(models.Model):
    """Professional license verification information"""
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='licenses')
    license_type = models.CharField(max_length=100)
    license_number = models.CharField(max_length=50)
    issuing_authority = models.CharField(max_length=100)
    issue_date = models.DateField()
    expiry_date = models.DateField()
    license_document = models.FileField(upload_to='license_documents/')
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s {self.license_type} License"


class ReferenceVerification(models.Model):
    """Reference verification information"""
    RELATIONSHIP_CHOICES = [
        ('professional', 'Professional'),
        ('academic', 'Academic'),
        ('personal', 'Personal'),
    ]

    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE, related_name='references')
    full_name = models.CharField(max_length=100)
    relationship = models.CharField(max_length=20, choices=RELATIONSHIP_CHOICES)
    company = models.CharField(max_length=255, blank=True)
    position = models.CharField(max_length=100, blank=True)
    email = models.EmailField()
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone = models.CharField(validators=[phone_regex], max_length=17)
    reference_document = models.FileField(upload_to='reference_documents/', blank=True, null=True)
    verified = models.BooleanField(default=False)
    verification_date = models.DateTimeField(null=True, blank=True)
    verification_notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s Reference: {self.full_name}"


class VerificationStatus(models.Model):
    """Overall verification status for the applicant"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]

    applicant = models.OneToOneField(Applicant, on_delete=models.CASCADE, related_name='status')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='assigned_verifications')
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.applicant.name}'s Verification: {self.get_status_display()}"