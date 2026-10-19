from rest_framework import serializers

from .models import Regulation, RegulatorySource


class RegulatorySourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegulatorySource
        fields = ["id", "title", "authority_url", "gazette_identifier", "sha256", "legal_status", "reviewed_by", "reviewed_at", "created_at"]
        read_only_fields = ["id", "legal_status", "reviewed_by", "reviewed_at", "created_at"]


class RegulationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Regulation
        fields = ["id", "version", "number", "title", "legal_status", "source_page", "created_at"]
        read_only_fields = fields

