from django.urls import path, include
from accounts import views


app_name = 'accounts'


urlpatterns = [
    path('api/sign-up/', views.SignUpApi.as_view(), name='sign_up'),
    path('api/sign-in/', views.SignInApi.as_view(), name='sign_in'),
    path('api/sign-out/', views.SignOutApi.as_view(), name='sign_out'),
    path('api/update/password/<str:username>/', views.UpdatePassword.as_view(), name='update_password'),
    path('api/testapi/', views.TestApi.as_view(), name='testapi'),

    # PASSWORD RESET URL
    path('api/password-reset/', views.PasswordResetView.as_view(), name="password_reset"),
    path('api/password-reset-done/', views.PasswordResetDoneView.as_view(), name="password_reset_done"),
    path('api/password-reset-confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),


    # Map View
    #path('api/view-map/', views.ViewMap.as_view(), name='view_map'),
    path('api/view-map/<str:username>/', views.view_map, name='view_map'),

    #Member Account
    path('api/member/<str:username>/', views.MemberDetailApi.as_view(), name='member_detail_api'),
    path('api/member/edit/<str:username>/', views.MemberDetailEditApi.as_view(), name="member_detail_edit_api"),


    path('api/health-create/', views.Health_Api.as_view(), name="health"),
    path('api/health-list/', views.HealthList_Api.as_view(), name="health_list"),

]
