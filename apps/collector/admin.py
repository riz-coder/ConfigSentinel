from django.contrib import admin

from .models import CollectionJob, CollectorAgent, CommandDefinition, CommandProfile, CredentialReference, Device, ScopeGrant


class CollectorReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(CredentialReference)
class CredentialReferenceAdmin(CollectorReadOnlyAdmin):
    exclude = ("secret_reference",)
    list_display = ("name", "provider", "tenant", "is_active", "created_at")


for model in (Device, CollectorAgent, CommandProfile, CommandDefinition, ScopeGrant, CollectionJob):
    admin.site.register(model, CollectorReadOnlyAdmin)
