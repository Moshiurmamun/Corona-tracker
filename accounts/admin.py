from django.contrib import admin

from . import models


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['email','phone']

admin.site.register(models.UserProfile, UserProfileAdmin)
admin.site.site_header = "Corona Tracker"

admin.site.register(models.Health)
admin.site.register(models.Location)
