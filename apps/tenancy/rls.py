from django.db import connection


def set_rls_context(*, user_id=None, tenant_id=None):
    if connection.vendor != "postgresql":
        return
    with connection.cursor() as cursor:
        if user_id is not None:
            cursor.execute("SELECT set_config('configsentinel.user_id', %s, true)", [str(user_id)])
        if tenant_id is not None:
            cursor.execute("SELECT set_config('configsentinel.tenant_id', %s, true)", [str(tenant_id)])
