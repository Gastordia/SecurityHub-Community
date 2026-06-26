from django.urls import path
from django.conf import settings

from . import views
from .views import MyTokenObtainPairView, LogoutGetView, MyTokenRefreshView

urlpatterns = [
    # AUTHENTICATION
    path('login/', MyTokenObtainPairView.as_view(), name='login'),
    path('token/refresh/', MyTokenRefreshView.as_view(), name='token-refresh'),
    path('logout/', LogoutGetView.as_view(), name='logout'),

    # PROFILE & CURRENT USER
    path('profile/', views.myprofile, name='profile-operations'),
    path('me/', views.myprofile, name='current-user'),

]
