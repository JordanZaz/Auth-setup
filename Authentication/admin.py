from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'username', 'is_staff', 'date_joined')
    search_fields = ('email', 'username')
    ordering = ('-date_joined',)

    # exclude the date_joined field from the form
    fieldsets = (
        (None, {'fields': ('email', 'password', 'username',
                           'is_active', 'is_staff', 'is_superuser')}),
        ('Permissions', {'fields': ('groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )


admin.site.register(CustomUser, CustomUserAdmin)
