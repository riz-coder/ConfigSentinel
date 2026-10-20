from django.conf import settings


def product_branding(request):
    return {"product_name": settings.PRODUCT_NAME}
