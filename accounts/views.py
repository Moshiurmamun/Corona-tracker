from rest_framework.views import APIView, Response
from rest_framework import status
from django.shortcuts import render, redirect
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import CreateAPIView, ListAPIView, RetrieveUpdateAPIView
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework import filters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from django.contrib.auth import update_session_auth_hash
import json

from  django.http import JsonResponse
from django.db.models import Q

from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404, HttpResponseRedirect
from django.utils import http
from django.utils.encoding import force_bytes, force_text
from django.urls import reverse
from accounts import serializers
from accounts import permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view

from accounts import models
from accounts.models import Health, Location



#sign up api
class SignUpApi(APIView):
    serializer_class = serializers.UserProfileSerializerForm

    def get(self, request):
        return Response(status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user, auth_token = serializer.deploy()
            user_obj = {

                "email": user.email
            }
            return Response({
                'user': user_obj,
                'token': auth_token,
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status.HTTP_400_BAD_REQUEST)


#sign in
class AuthTokenCustomised(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'email': user.email})

class SignInApi(ObtainAuthToken):
    serializer_class = serializers.AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES



""" ------------------------- sign out ------------------------------ """
class SignOutApi(APIView):
    def get(self, request):
        if request.user.is_authenticated:
            request.user.auth_token.delete()
            return Response({
                "sign-out": True
            }, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_200_OK)



#git bash
#curl http://localhost:8000/accounts/api/testapi/ -d value=10


""" ------------------------- Test API ------------------------------ """
class TestApi(APIView):
    def post(self,request):
        print(request.POST.get('value'))

        return Response({
            "success":"ok"
        })

""" ------------------------- Update Password ------------------------- """
class UpdatePassword(APIView):
    serializer_class = serializers.UpdatePasswordSerializer
    permission_classes = (permissions.UserProfilePermission, IsAuthenticated)

    def put(self, request, username):
        user = get_object_or_404(models.UserProfile, username=username)
        if user:
            serializer = self.serializer_class(context={'request': request}, data=request.data)

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'success':'Password changed successfully'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






"""----------------------- Password Reset View -------------------"""
class PasswordResetView(APIView):
    serializer_class = serializers.PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            to_mail = serializer.validated_data['email']
            user = get_object_or_404(models.UserProfile, email=to_mail)
            uid = http.urlsafe_base64_encode(force_bytes(user.id))
            token, created = Token.objects.get_or_create(user=user)
            url = '/'.join(['http:/', get_current_site(request).domain, 'accounts/api/password-reset-confirm', uid, str(token)])

            subject = 'Password reset on Corona Tracker'
            message = 'Please go to the following page and choose a new password:' + url
            from_mail = 'no_reply@asatel.co.uk'

            send_mail(subject, message, from_mail, [to_mail])
            return HttpResponseRedirect(reverse('accounts:password_reset_done'))
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetDoneView(APIView):
    def get(self, request):
        message = 'we have emailed you instructions for setting your password.'
        return Response({'message': message}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    serializer_class = serializers.SetNewPasswordSerializer

    def post(self, request, uidb64, token):
        uid = force_text(http.urlsafe_base64_decode(uidb64))
        user = models.UserProfile.objects.get(pk=uid)
        user_token = Token.objects.get(user=user)
        if user is not None and user_token.key == token:
            serializer = self.serializer_class(context={'user': user}, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'message': 'Your Password has been set. You may go ahead and login now.'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.erros, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'warning': 'Something went wrong while matching credentials. Please try again'}, status=status.HTTP_400_BAD_REQUEST)







""" ======================================= Map View ==============================="""

# class ViewMap(APIView):
#     renderer_classes = [TemplateHTMLRenderer,]
#
#
#     def get(self, request):
#
#         return Response( template_name='create_maps.html')
#
#
#     def post(self, request):
#         print(12312)
#         print(request.POST)
#         lat = request.POST.get('latitude')
#         lon = request.POST.get('longitude')
#
#         obj = Location(user=request.user, latitude=lat, longitude=lon)
#         obj.save()
#
#         instance = Location.objects.all()
#
#         return Response({'instance': instance}, template_name='maps.html')

#{% url 'accounts:view_map' %}

def view_map(request, username):

    if request.method =="POST":
        data = json.loads(request.body)
        lat = (data['x'])
        lon = (data['y'])

        user = get_object_or_404(models.UserProfile, username=username)
        obj = Location(user=user, latitude = lat, longitude=lon)
        obj.save()

        data_instance = list(Location.objects.filter(~Q(user=user)).values())
        print(data_instance)
        dd = list(Location.objects.filter(user=user).values().order_by('-id'))
        data_current_user = dd[0]
        print("-------------------")
        print(data_current_user)

        return JsonResponse({"di":data_instance, "cu":data_current_user},safe=False)

    user = get_object_or_404(models.UserProfile, username=username)
    instance = Location.objects.filter(~Q(user=user))
    print(instance)
    current_user = Location.objects.filter(user=user).order_by('-id')[0]
    print(current_user.id)
    context = {
        "instance":instance,
        "current_user":current_user,
    }
    return render(request, 'create_maps.html', context)






#member detail api
class MemberDetailApi(APIView):
    permission_classes = (permissions.MemberDetailPermission, )

    def get(self, request, username):
        member = get_object_or_404(models.UserProfile, username=username)
        serializer = serializers.MemberDetailSerializer(member).data

        return Response({
            'results': serializer
        }, status=status.HTTP_200_OK)




# Member Edit Api
class MemberDetailEditApi(RetrieveUpdateAPIView):
    queryset = models.UserProfile.objects.all()
    serializer_class = serializers.MemberDetailEditSerializer
    permission_classes = (permissions.MemberDetailPermission, )
    lookup_field = 'username'

    def perform_update(self, serializer):
        serializer.save(user=self.request.user)



#Health api
class Health_Api(CreateAPIView):
    queryset = Health.objects.all()
    serializer_class = serializers.HealthSerializer
    permission_classes = (IsAuthenticated,)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)



#Health Detail Api
class HealthList_Api(ListAPIView):
    queryset = Health.objects.all()
    serializer_class = serializers.HealthListSerializer


"""

class UserProfileViewSet(viewsets.ModelViewSet):
    
    serializer_class = serializers.UserProfileSerializer
    queryset = models.UserProfile.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.UpdateOwnProfile,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('name', 'email',)

"""

