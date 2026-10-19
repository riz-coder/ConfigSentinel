from rest_framework import serializers

from .models import Regulation, RegulatoryReview, RegulatorySource, RegulatoryVersion, TrustedSigningKey


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


class TrustedSigningKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = TrustedSigningKey
        fields = ["id", "name", "public_key_base64", "fingerprint", "is_active", "created_at"]
        read_only_fields = ["id", "fingerprint", "created_at"]
        extra_kwargs = {"public_key_base64": {"write_only": True}}


class RegulatoryReviewSerializer(serializers.ModelSerializer):
    reviewer = serializers.CharField(source="reviewer.username", read_only=True)

    class Meta:
        model = RegulatoryReview
        fields = ["id", "kind", "decision", "note", "reviewer", "created_at"]
        read_only_fields = fields


class RegulatoryVersionSerializer(serializers.ModelSerializer):
    source_title = serializers.CharField(source="source.title", read_only=True)
    legal_status = serializers.CharField(source="source.legal_status", read_only=True)
    reviews = RegulatoryReviewSerializer(many=True, read_only=True)

    class Meta:
        model = RegulatoryVersion
        fields = ["id", "source", "source_title", "version_label", "effective_date", "approval_status", "legal_status", "reviews", "created_at"]
        read_only_fields = fields

