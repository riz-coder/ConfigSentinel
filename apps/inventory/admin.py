from django.contrib import admin

from .models import Asset, AssetDependency, CriticalService, Site

admin.site.register((Site, CriticalService, Asset, AssetDependency))
