from django.db import connection, transaction

from .access import tenant_for_request
from .rls import set_rls_context


class TenantContextMiddleware:
    """Validate membership and scope PostgreSQL RLS for the complete view call."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)
        if connection.vendor != "postgresql":
            self._activate_if_available(request)
            return self.get_response(request)

        with transaction.atomic():
            set_rls_context(user_id=request.user.pk)
            tenant = self._activate_if_available(request)
            if tenant is not None:
                set_rls_context(tenant_id=tenant.pk)
            return self.get_response(request)

    @staticmethod
    def _activate_if_available(request):
        if request.path.startswith(("/accounts/", "/health/", "/static/")):
            return None
        if not request.user.tenant_memberships.filter(is_active=True, tenant__is_active=True).exists():
            return None
        return tenant_for_request(request)

