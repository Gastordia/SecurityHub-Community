import logging
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from utils.throttles import TenantAwareThrottle
from utils.audit_logging import AuditLogger
from utils.logging_helpers import log_view_start, log_view_success, log_view_error
from .throttles import LoginThrottle as AccountLoginThrottle
from .models import CustomUser
from .serializers import ProfileUserSerializer, CustomUserSerializer

logger = logging.getLogger(__name__)


class MyTokenRefreshView(TokenRefreshView):
    throttle_classes = [TenantAwareThrottle]

    def post(self, request, *args, **kwargs):
        start_ctx = log_view_start('MyTokenRefreshView.post', request)
        try:
            # Accept refresh token from httpOnly cookie when not supplied in body.
            # This lets the frontend avoid ever storing the refresh token in localStorage.
            data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
            if 'refresh' not in data or not data['refresh']:
                cookie_refresh = request.COOKIES.get('refresh_token')
                if cookie_refresh:
                    data['refresh'] = cookie_refresh

            serializer = self.get_serializer(data=data)
            try:
                serializer.is_valid(raise_exception=True)
            except Exception as e:
                error_str = str(e).lower()
                is_expired = 'expired' in error_str or 'token is invalid or expired' in error_str
                if is_expired:
                    error_message = 'Refresh token has expired. Please log in again.'
                    logger.warning(f"Token refresh: Token expired - {e}")
                else:
                    error_message = 'Invalid refresh token.'
                    AuditLogger.log_security_event(
                        event_type='LOGIN_FAILURE', user=None, request=request,
                        details={'error': 'Invalid refresh token'}, severity='warning',
                    )
                return Response({'detail': error_message}, status=status.HTTP_400_BAD_REQUEST)

            validated = serializer.validated_data
            access_token = validated.get("access")
            new_refresh = validated.get("refresh")
            response = Response({'access': access_token}, status=status.HTTP_200_OK)
            _set_auth_cookies(response, access_token, new_refresh)
            log_view_success('MyTokenRefreshView.post', request, {}, start_ctx['start_time'])
            return response
        except Exception as e:
            log_view_error('MyTokenRefreshView.post', request, e)
            return Response({'detail': 'An error occurred during token refresh.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _set_auth_cookies(response, access_token: str, refresh_token=None):
    """Set JWT tokens as httpOnly cookies so JS cannot read them."""
    from django.conf import settings as dj_settings
    secure = getattr(dj_settings, 'AUTH_COOKIE_SECURE', False)
    response.set_cookie(
        key='access_token', value=access_token,
        httponly=True, secure=secure, samesite='Lax', path='/',
    )
    if refresh_token:
        refresh_lifetime = dj_settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
        response.set_cookie(
            key='refresh_token', value=refresh_token,
            httponly=True, secure=secure, samesite='Lax',
            # Scoped to the refresh endpoint so the cookie isn't sent with every request.
            path='/api/auth/token/refresh/',
            max_age=int(refresh_lifetime.total_seconds()),  # matches REFRESH_TOKEN_LIFETIME
        )


class LogoutGetView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [TenantAwareThrottle]

    def post(self, request):
        start_ctx = log_view_start('LogoutGetView.post', request)
        try:
            AuditLogger.log_security_event(
                event_type='LOGOUT', user=request.user, request=request,
                details={'user_id': request.user.id}, severity='info',
            )
            response = Response("OK", status=status.HTTP_200_OK)
            response.delete_cookie('access_token', path='/')
            response.delete_cookie('refresh_token', path='/api/auth/token/refresh/')
            log_view_success('LogoutGetView.post', request, {}, start_ctx['start_time'])
            return response
        except Exception as e:
            log_view_error('LogoutGetView.post', request, e)
            return Response({'detail': 'Logout failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    # USERNAME_FIELD='email' → SimpleJWT declares 'email' as required.
    # We loosen that and accept username or email from callers.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from rest_framework import serializers as rf_serializers
        if 'email' in self.fields:
            self.fields['email'].required = False
        self.fields['username'] = rf_serializers.CharField(
            required=False, write_only=True, allow_blank=True
        )

    def validate(self, attrs):
        from accounts.models import CustomUser
        login = attrs.get('username') or attrs.get('email', '')
        if login and '@' not in login:
            try:
                user_obj = CustomUser.objects.get(username=login)
                attrs['email'] = user_obj.email
            except CustomUser.DoesNotExist:
                pass
        elif login:
            attrs.setdefault('email', login)
        attrs.pop('username', None)

        data = super().validate(attrs)
        data['Status'] = "True"
        data['username'] = self.user.username or self.user.email
        data['Pic'] = self.user.profilepic.url if self.user.profilepic else '/media/profile/avatar-1.svg'
        data['isAdmin'] = self.user.is_superuser
        data['isStaff'] = self.user.is_staff
        return data


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    throttle_classes = [AccountLoginThrottle, AnonRateThrottle]

    def post(self, request, *args, **kwargs):
        start_ctx = log_view_start('MyTokenObtainPairView.post', request)
        try:
            serializer = self.get_serializer(data=request.data)
            try:
                serializer.is_valid(raise_exception=True)
            except Exception as e:
                email = request.data.get('email', 'unknown')
                AuditLogger.log_security_event(
                    event_type='LOGIN_FAILURE', user=None, request=request,
                    details={'email': email, 'error': 'Invalid credentials'}, severity='warning',
                )
                log_view_error('MyTokenObtainPairView.post', request, e)
                return Response({'detail': 'Authentication failed. Please check your credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

            token_data = serializer.validated_data
            user = serializer.user
            AuditLogger.log_security_event(
                event_type='LOGIN_SUCCESS', user=user, request=request,
                details={'user_id': user.id, 'email': user.email, 'is_staff': user.is_staff},
                severity='info',
            )
            response = Response({
                'access': token_data['access'],
                'Status': token_data.get('Status'),
                'username': token_data.get('username'),
                'Pic': token_data.get('Pic'),
                'isAdmin': token_data.get('isAdmin'),
                'isStaff': token_data.get('isStaff'),
            }, status=status.HTTP_200_OK)
            _set_auth_cookies(response, token_data['access'], token_data.get('refresh'))
            log_view_success('MyTokenObtainPairView.post', request, {'user_id': user.id}, start_ctx['start_time'])
            return response
        except Exception as e:
            log_view_error('MyTokenObtainPairView.post', request, e)
            return Response({'detail': 'An error occurred during authentication.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
@throttle_classes([TenantAwareThrottle])
def myprofile(request):
    start_ctx = log_view_start('myprofile', request)
    try:
        user = request.user
        if request.method == 'GET':
            serializer = CustomUserSerializer(user)
            response_data = serializer.data
            response_data['user_type'] = 'staff'
            log_view_success('myprofile', request, {}, start_ctx['start_time'])
            return Response(response_data)

        elif request.method == 'PATCH':
            user_serializer = ProfileUserSerializer(user, data=request.data, partial=True, context={'request': request})
            if user_serializer.is_valid(raise_exception=True):
                user_serializer.save()
                log_view_success('myprofile', request, {'user_id': user.id, 'action': 'UPDATE'}, start_ctx['start_time'])
                return Response(user_serializer.data)
            else:
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    except Exception as e:
        log_view_error('myprofile', request, e)
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



