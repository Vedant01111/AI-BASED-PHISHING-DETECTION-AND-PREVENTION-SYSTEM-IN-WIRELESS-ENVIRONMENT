from django.db import models
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
import uuid

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)


class UserModel(AbstractUser):
    id              = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False, unique=True)
    username        = None
    email           = models.EmailField(verbose_name="Email", unique=True, max_length=255)
    first_name      = models.CharField(verbose_name="First Name", max_length=255, null=True, blank=True)
    last_name       = models.CharField(verbose_name="Last Name", max_length=255, null=True, blank=True)
    objects         = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'
    full_name.fget.short_description = 'Full name'

    @property
    def short_name(self):
        self.first_name = self.first_name[0] if self.first_name else ''
        self.last_name = self.last_name if self.last_name else ''
        return f'{self.last_name} {self.first_name}.'
    short_name.fget.short_description = 'Short name'

    @property
    def initial_profile(self):
        self.first_name = self.first_name[0] if self.first_name else ''
        self.last_name = self.last_name[0] if self.last_name else ''
        return f'{self.first_name}{self.last_name}'
    initial_profile.fget.short_description = 'Initial Profile'

    def get_full_name(self):
        return self.full_name

    def get_short_name(self):
        return self.short_name
    
    def get_initial_profile(self):
        return self.initial_profile

    def __str__(self):
        return self.full_name