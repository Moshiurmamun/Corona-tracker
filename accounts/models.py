from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager


import os


# user profile manager
class UserProfileManager(BaseUserManager):
    """Helps django work with our custom user model"""

    def create_user(self,username, email, phone=None, password=None, **kwargs):
        """creates a new user profile objecs"""

        if not email:
            raise ValueError('User must have an email address!')

        if not phone:
            raise ValueError('User must have an phone number!')

        email = self.normalize_email(email)
        user = self.model(username=username,email=email, phone=phone)

        user.set_password(password)
        user.save(using=self._db)

        return user


    def create_superuser(self,username, email, phone, password):
        """creates and saves a new super user with given details"""

        user = self.create_user(username=username, email=email, phone=phone, password=password)

        user.is_superuser = True
        user.is_staff = True

        user.save(using=self._db)

        return user




Gender = (
    ('Male', 'Male'),
    ('Female', 'Female'),
)
# user profile model
class UserProfile(AbstractBaseUser, PermissionsMixin):
    """Represents a user profile inside our system"""

    #basic info

    username = models.CharField(max_length=100, unique=True, null=True, blank=True)
    fullname = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField(max_length=100, unique=True)
    phone = models.CharField(max_length=20, unique=True)
    address = models.TextField(max_length=500, null=True, blank=True)
    nid = models.CharField(max_length=30, null=True, blank=True, unique=True)
    age = models.CharField(max_length=3, null=True,blank=True)
    gender = models.CharField(max_length=100,choices=Gender , null=True, blank=True)



    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserProfileManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'phone',]


    def get_full_name(self):
        return self.fullname


    def __str__(self):
        """Django uses this when it needs to convert the object to a string"""

        return str(self.username)



class EmailOrUsernameModelBackend(object):
    def authenticate(self, username=None, password=None):
        if '@' in username:
            kwargs = {'email': username}
        else:
            kwargs = {'username': username}
        try:
            user = UserProfile.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except UserProfile.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return UserProfile.objects.get(pk=user_id)
        except UserProfile.DoesNotExist:
            return None




Status = (
    ('Well', 'Well'),
    ('Sick_Feel', 'Sick (feeling)'),
    ('Tested_wait', 'Tested, Waiting Results'),
    ('Tested_Neg', 'Tested Negative'),
    ('Tested_Pos', 'Tested Positive'),
    ('Recovered', 'Recovered'),
)

class Health(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, null=True, blank=True)
    date= models.DateTimeField(auto_now_add=True,auto_now=False, null=True, blank=True)
    health_status = models.CharField(max_length=100, choices=Status, null=True, blank=True)

    def __str__(self):
        return str(self.user.username)




class Location(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)

    latitude = models.DecimalField(max_digits=12 ,decimal_places=8, null=True, blank=True)
    longitude = models.DecimalField(max_digits=12, decimal_places=8, null=True, blank=True)

    date_time = models.DateTimeField(auto_now_add=True, null=True, blank=True)


    def __str__(self):
        return str(self.id)








