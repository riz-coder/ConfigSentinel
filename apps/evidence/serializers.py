from rest_framework import serializers

from apps.regulatory.models import ObligationControlMapping

from .models import CustodyEvent, EvidenceArtifact, EvidenceReview, RetentionHold


class EvidenceUploadSerializer(serializers.Serializer):
    mapping = serializers.PrimaryKeyRelatedField(queryset=ObligationControlMapping.objects.none())
    title = serializers.CharField(max_length=255)
    file = serializers.FileField(write_only=True)
    period_start = serializers.DateField(required=False, allow_null=True)
    period_end = serializers.DateField(required=False, allow_null=True)
    collected_at = serializers.DateTimeField(required=False, allow_null=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        tenant = getattr(request, "active_tenant", None)
        if tenant:
            self.fields["mapping"].queryset = ObligationControlMapping.objects.filter(tenant=tenant)


class EvidenceReviewSerializer(serializers.ModelSerializer):
    reviewer = serializers.CharField(source="reviewer.username", read_only=True)

    class Meta:
        model = EvidenceReview
        fields = ["decision", "note", "reviewer", "integrity_verified_at", "created_at"]
        read_only_fields = fields


class RetentionHoldSerializer(serializers.ModelSerializer):
    applied_by = serializers.CharField(source="applied_by.username", read_only=True)
    released_by = serializers.CharField(source="released_by.username", read_only=True)

    class Meta:
        model = RetentionHold
        fields = ["id", "reason", "applied_by", "applied_at", "released_by", "released_at", "release_reason"]
        read_only_fields = fields


class CustodyEventSerializer(serializers.ModelSerializer):
    actor = serializers.CharField(source="actor.username", read_only=True)

    class Meta:
        model = CustodyEvent
        fields = ["id", "kind", "actor", "metadata", "created_at"]
        read_only_fields = fields


class EvidenceArtifactSerializer(serializers.ModelSerializer):
    effective_status = serializers.CharField(read_only=True)
    uploaded_by = serializers.CharField(source="uploaded_by.username", read_only=True)
    review = EvidenceReviewSerializer(read_only=True)
    retention_holds = RetentionHoldSerializer(many=True, read_only=True)
    custody_events = CustodyEventSerializer(many=True, read_only=True)

    class Meta:
        model = EvidenceArtifact
        fields = [
            "id", "mapping", "requirement", "title", "original_filename", "media_type", "size_bytes",
            "plaintext_sha256", "status", "effective_status", "period_start", "period_end", "collected_at",
            "expires_at", "retain_until", "uploaded_by", "created_at", "finalized_at", "purged_at",
            "review", "retention_holds", "custody_events",
        ]
        read_only_fields = fields
