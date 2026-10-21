from rest_framework import serializers

from .models import Asset, AssetDependency, CriticalService, Site


class SiteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Site
        exclude = ["tenant", "created_by"]
        read_only_fields = ["id", "created_at", "updated_at"]


class CriticalServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = CriticalService
        exclude = ["tenant", "created_by"]
        read_only_fields = ["id", "created_at", "updated_at"]


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        exclude = ["tenant", "created_by"]
        read_only_fields = ["id", "created_at", "updated_at"]


class AssetDependencySerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetDependency
        exclude = ["tenant", "created_by"]
        read_only_fields = ["id", "created_at"]
