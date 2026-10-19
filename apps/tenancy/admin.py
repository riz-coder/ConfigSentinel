from django.contrib import admin

from .models import Membership, Tenant

admin.site.register(Tenant)
admin.site.register(Membership)

