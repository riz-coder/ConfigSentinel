from django.contrib import admin

from .models import Regulation, RegulatorySource, RegulatoryVersion

admin.site.register(RegulatorySource)
admin.site.register(RegulatoryVersion)
admin.site.register(Regulation)

