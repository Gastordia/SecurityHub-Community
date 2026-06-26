from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['email', 'full_name', 'is_staff', 'is_active', 'is_superuser', 'username', 'position']
    fieldsets = (
        (None, {'fields': ('email', 'password', 'username')}),
        ('Personal Info', {'fields': ('full_name', 'position')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_superuser')}),
    )


admin.site.register(CustomUser, CustomUserAdmin)
