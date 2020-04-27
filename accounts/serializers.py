from rest_framework import serializers
from rest_framework.serializers import ModelSerializer

from accounts import models
from accounts.models import Health
from rest_framework.authtoken.models import Token
import re
from django.contrib.auth.password_validation import validate_password
import os


Gender = (
    ('Male', 'Male'),
    ('Female', 'Female'),
)
#create sign up api
class UserProfileSerializerForm(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=False, allow_null=True)
    fullname = serializers.CharField(max_length=100, required=False, allow_null=True)
    email = serializers.EmailField(max_length=100, required=False, allow_null=True)
    phone = serializers.CharField(max_length=20, required=False, allow_null=True)
    address = serializers.CharField(max_length=500, required=False, allow_null=True)
    nid = serializers.CharField(max_length=30, required=False, allow_null=True)
    age = serializers.CharField(max_length=3, required=False, allow_null=True)
    gender = serializers.ChoiceField(choices=Gender, required=False, allow_null=True)
    password = serializers.CharField(write_only=True, required=False, allow_null=True, style={"input_type": "password", "placeholder": "password"})

    def check_space(self, username):
        for x in username:
            if x == ' ':
                return True

        return False

    def validate(self, data):
        username = data.get('username')
        email = data.get('email')
        fullname = data.get('fullname')
        phone = data.get('phone')
        nid = data.get('nid')
        age = data.get('age')
        gender = data.get('gender')
        address = data.get('address')
        password = data.get('password')


        if not username:
            raise serializers.ValidationError({'username': ['Enter username!']})
        else:
            check_space = self.check_space(username)
            if check_space:
                raise serializers.ValidationError({'username': ['Space not allowed in username!']})
            else:
                username_exist = models.UserProfile.objects.filter(username__iexact=username).exists()
                if username_exist:
                    raise serializers.ValidationError({'username': ['Already sign up with this username!']})


        if not email:
            raise serializers.ValidationError({'email': ['Enter email!']})
        else:
            email_correction = re.match('^[_a-zA-Z0-9-]+(\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,4})$', email)
            if not email_correction:
                raise serializers.ValidationError({'email': ['Enter valid email!']})
            else:
                email_exist = models.UserProfile.objects.filter(email__iexact=email).exists()
                if email_exist:
                    raise serializers.ValidationError({'email': ['Already sign up with this email!']})

        if not phone:
            raise serializers.ValidationError({'phone': ['Enter phone number!']})
        if phone:
            phone_exist = models.UserProfile.objects.filter(phone__iexact=phone).exists()
            if phone_exist:
                raise serializers.ValidationError({'phone': ['Already sign up with this phone number!']})


        if nid:
            nid_exist = models.UserProfile.objects.filter(nid__iexact=nid).exists()
            if nid_exist:
                raise serializers.ValidationError({'nid': ['Already sign up with this nid!']})



        if not password:
            raise serializers.ValidationError({'password': ['Enter password!']})
        else:
            if len(password) < 8:
                raise serializers.ValidationError({'password': ['Password is too short!']})


        return data


    def deploy(self):
        username = self.validated_data.get('username')
        fullname = self.validated_data.get('fullname')
        email = self.validated_data.get('email')
        phone = self.validated_data.get('phone')
        nid = self.validated_data.get('nid')
        age = self.validated_data.get('age')
        gender = self.validated_data.get('gender')
        address = self.validated_data.get('address')
        password = self.validated_data.get('password')


        user = models.UserProfile(username=username, fullname=fullname,email=email,
                                  phone=phone, address=address, nid=nid, age=age,
                                  gender=gender)
        user.set_password(password)
        user.save()
        user = models.EmailOrUsernameModelBackend.authenticate(self, username=username, password=password)
        token, is_created = Token.objects.get_or_create(user=user)
        return user, token.key



#sign in
class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label="Username", allow_blank=True)
    password = serializers.CharField(
        label="Password",
        allow_blank=True,
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if not username:
            raise serializers.ValidationError({'username': ['Enter username!']})
        else:
            if not password:
                raise serializers.ValidationError({'password': ['Enter password!']})


        if username and password:
            user = models.EmailOrUsernameModelBackend.authenticate(self, username=username, password=password)

            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg, code='authorization')
            else:
                if not user.is_active:
                    raise serializers.ValidationError('User account disabled! Contact customer support!')
        else:
            msg = 'Must include "username / email" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs





#update password
class UpdatePasswordSerializer(serializers.Serializer):

    current_password = serializers.CharField(required=False)
    new_password = serializers.CharField(required=False)
    retype_password = serializers.CharField(required=False)

    def validate(self, data):
        user = self.context['request'].user
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        retype_password = data.get('retype_password')

        if not current_password:
            raise serializers.ValidationError({'current_password': ['Enter current password!']})
        else:
            if not user.check_password(current_password):
                raise serializers.ValidationError({'current_password': ['Password not correct!']})
        if not new_password:
            raise serializers.ValidationError({'new_password': ['Enter new password!']})
        else:
            if len(new_password) < 8:
                raise serializers.ValidationError({'new_password': ['Password too short!']})
            else:
                if new_password != retype_password:
                    raise serializers.ValidationError('Password not matched!')
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        password = self.validated_data.get('new_password')
        user.set_password(password)
        user.save()

        return user




"""========================= Password Reset Serializer ==========================="""
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(label="Email", required=False)

    def validate(self, data):
        email = data.get('email')

        if not email:
            raise serializers.ValidationError({'email' : ['Enter Email!']})
        else:
            email_correction = re.match('^[_a-zA-Z0-9-]+(\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,4})$', email)
            if not email_correction:
                raise serializers.ValidationError({'email' : ['Enter a valid email!']})
            else:
                email_exists = models.UserProfile.objects.filter(email__iexact=email).exists()
                if not email_exists:
                    raise serializers.ValidationError({'email' : ['Email is not registered!']})
        return data



class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(label="New password", style={'input_type': 'password'}, write_only=True, required=False)
    retype_password = serializers.CharField(label="Re-type password", style={'input_type': 'password'}, write_only=True, required=False)

    def validate(self, data):
        new_password = data.get('new_password')
        retype_password = data.get('retype_password')

        if not new_password:
            raise serializers.ValidationError({'new_password': ['Enter new password!']})
        else:
            if len(new_password) < 8:
                raise serializers.ValidationError({'new_password': ['Password too short!']})
            else:
                if new_password != retype_password:
                    raise serializers.ValidationError('Password not matched!')
        return data

    def save(self, **kwargs):
        user = self.context['user']
        password = self.validated_data.get('new_password')
        user.set_password(password)
        user.save()

        return user



#member detail
class MemberDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.UserProfile
        fields = ('username', 'email', 'fullname', 'phone', 'address','age','nid','gender', 'is_active', 'is_superuser')



#Edit user account
class MemberDetailEditSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.UserProfile
        fields = ('username', 'email', 'fullname', 'phone', 'address', 'nid', 'age', 'gender')


#Health Create
class HealthSerializer(ModelSerializer):
    class Meta:
        model = Health
        fields = [

            'health_status',
            'date',
        ]


#Health List All user
class HealthListSerializer(ModelSerializer):
    class Meta:
        model = Health
        fields = [
            'user',
            'health_status',
            'date',
        ]
