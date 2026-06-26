from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password, ValidationError
from drf_spectacular.utils import extend_schema_serializer
from .models import CustomUser


@extend_schema_serializer()
class ChangePasswordSerializer(serializers.ModelSerializer):
    oldpassword = serializers.CharField(write_only=True, required=True)
    newpassword = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ['oldpassword', 'newpassword']

    def validate(self, data):
        user = self.context['request'].user
        if not user.check_password(data.get('oldpassword')):
            raise serializers.ValidationError("Current password does not match")
        try:
            validate_password(data.get('newpassword'))
        except ValidationError as e:
            raise serializers.ValidationError({"password": e.messages})
        return data


@extend_schema_serializer()
class ProfileUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'full_name', 'profilepic']
        read_only_fields = ['date_joined', 'is_staff', 'email', 'position', 'is_active', 'username']


@extend_schema_serializer()
class CustomUserSerializer(serializers.ModelSerializer):
    profilepic = serializers.ImageField(required=False)
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'full_name', 'email', 'is_staff', 'is_active',
            'is_superuser', 'profilepic', 'position', 'password',
        ]
        read_only_fields = ['date_joined']

    def validate(self, attrs):
        attrs = super().validate(attrs)
        request = self.context.get('request')
        if attrs.get('is_superuser') and not (request and request.user.is_superuser):
            raise serializers.ValidationError({
                'is_superuser': 'Only superusers can assign superuser privileges.'
            })
        return attrs

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['is_staff'] = True
        if not (request and request.user.is_superuser):
            validated_data.pop('is_superuser', None)
        if 'password' not in validated_data:
            raise serializers.ValidationError("Password is required for creating a new user.")
        password = validated_data.pop('password')
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({"password": e.messages})
        user = CustomUser.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        request = self.context.get('request')
        if 'is_staff' in validated_data and not (request and request.user.is_superuser):
            validated_data.pop('is_staff')
        if 'is_superuser' in validated_data and not (request and request.user.is_superuser):
            validated_data.pop('is_superuser')
        if 'password' in validated_data:
            if not validated_data['password']:
                validated_data.pop('password')
            else:
                password = validated_data['password']
                try:
                    validate_password(password)
                except ValidationError as e:
                    raise serializers.ValidationError({"password": e.messages})
                validated_data['password'] = make_password(password)
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.pop('password', None)
        return data
