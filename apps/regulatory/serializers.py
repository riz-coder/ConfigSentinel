from rest_framework import serializers

from .models import (
    ControlDefinition, EvidenceRequirement, MappingReview, Obligation,
    ObligationControlMapping, Regulation, RegulatoryReview, RegulatorySource,
    RegulatoryVersion, TestProcedure, TrustedSigningKey,
)


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


class ControlDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ControlDefinition
        fields = ["id", "control_key", "version", "title", "description", "created_by", "created_at"]
        read_only_fields = ["id", "created_by", "created_at"]


class TenantRelationSerializer(serializers.ModelSerializer):
    tenant_relations = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        tenant = getattr(request, "active_tenant", None)
        if tenant:
            for field_name, queryset_factory in self.tenant_relations.items():
                self.fields[field_name].queryset = queryset_factory(tenant)


class TestProcedureSerializer(TenantRelationSerializer):
    tenant_relations = {"control": lambda tenant: ControlDefinition.objects.filter(tenant=tenant)}

    class Meta:
        model = TestProcedure
        fields = ["id", "control", "procedure_key", "version", "title", "procedure", "expected_result", "created_by", "created_at"]
        read_only_fields = ["id", "created_by", "created_at"]


class EvidenceRequirementSerializer(TenantRelationSerializer):
    tenant_relations = {"test_procedure": lambda tenant: TestProcedure.objects.filter(tenant=tenant)}

    class Meta:
        model = EvidenceRequirement
        fields = ["id", "test_procedure", "requirement_key", "version", "title", "description", "recurrence", "retention_days", "freshness_days", "created_by", "created_at"]
        read_only_fields = ["id", "created_by", "created_at"]


class MappingReviewSerializer(serializers.ModelSerializer):
    reviewer = serializers.CharField(source="reviewer.username", read_only=True)

    class Meta:
        model = MappingReview
        fields = ["id", "kind", "decision", "note", "reviewer", "created_at"]
        read_only_fields = fields


class ObligationControlMappingSerializer(TenantRelationSerializer):
    tenant_relations = {
        "obligation": lambda tenant: Obligation.objects.filter(subclause__regulation__version__source__tenant=tenant),
        "control": lambda tenant: ControlDefinition.objects.filter(tenant=tenant),
        "test_procedure": lambda tenant: TestProcedure.objects.filter(tenant=tenant),
        "evidence_requirement": lambda tenant: EvidenceRequirement.objects.filter(tenant=tenant),
    }
    reviews = MappingReviewSerializer(many=True, read_only=True)

    class Meta:
        model = ObligationControlMapping
        fields = [
            "id", "obligation", "control", "test_procedure", "evidence_requirement", "rationale",
            "status", "created_by", "created_at", "finalized_at", "reviews",
        ]
        read_only_fields = ["id", "status", "created_by", "created_at", "finalized_at", "reviews"]

