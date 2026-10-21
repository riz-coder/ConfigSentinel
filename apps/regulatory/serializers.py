from rest_framework import serializers

from .models import (
    ControlDefinition, EvidenceRequirement, MappingReview, Obligation,
    ObligationControlMapping, Regulation, RegulatoryReview, RegulatorySource,
    RegulatoryVersion, TestProcedure, TrustedSigningKey,
    ClauseAuditAssessment, ClauseEvidenceReview,
    AuditorReport,
    AuditorReportImport, AuditorReportImportRow,
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
    review_blockers = serializers.SerializerMethodField()

    def get_review_blockers(self, obj):
        from .services import version_review_blockers
        return version_review_blockers(obj)

    class Meta:
        model = RegulatoryVersion
        fields = ["id", "source", "source_title", "version_label", "effective_date", "approval_status", "legal_status", "review_blockers", "reviews", "created_at"]
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


class ClauseEvidenceReviewSerializer(serializers.ModelSerializer):
    reviewer = serializers.CharField(source="reviewer.username", read_only=True)
    artifact_filename = serializers.CharField(source="artifact.original_filename", read_only=True)

    class Meta:
        model = ClauseEvidenceReview
        fields = ["id", "artifact", "artifact_filename", "decision", "note", "integrity_sha256", "reviewer", "created_at"]
        read_only_fields = fields


class ClauseAuditAssessmentSerializer(serializers.ModelSerializer):
    reviewer = serializers.CharField(source="reviewer.username", read_only=True)
    clause_path = serializers.CharField(source="subclause.clause_path", read_only=True)

    class Meta:
        model = ClauseAuditAssessment
        fields = ["id", "subclause", "clause_path", "sequence", "decision", "compliance_status", "note", "gaps", "evidence_snapshot", "preliminary_analysis", "reviewer", "created_at"]
        read_only_fields = fields


class ClauseEvidenceReviewCreateSerializer(serializers.Serializer):
    artifact = serializers.UUIDField()
    decision = serializers.ChoiceField(choices=["ACCEPTED", "REJECTED"])
    note = serializers.CharField(allow_blank=False)


class ClauseAuditAssessmentCreateSerializer(serializers.Serializer):
    subclause = serializers.UUIDField()
    decision = serializers.ChoiceField(choices=ClauseAuditAssessment.Decision.choices)
    note = serializers.CharField(allow_blank=False)
    gaps = serializers.CharField(required=False, allow_blank=True)


class AuditorAccountSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)


class AuditorReportSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.CharField(source="uploaded_by.username", read_only=True)

    class Meta:
        model = AuditorReport
        fields = ["id", "title", "original_filename", "size_bytes", "plaintext_sha256", "uploaded_by", "uploaded_at"]
        read_only_fields = fields


class AuditorReportUploadSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=255)
    report = serializers.FileField()


class AuditorReportImportRowSerializer(serializers.ModelSerializer):
    clause_path = serializers.CharField(source="subclause.clause_path", read_only=True)
    confirmed_assessment_status = serializers.CharField(source="confirmed_assessment.compliance_status", read_only=True)

    class Meta:
        model = AuditorReportImportRow
        fields = ["id", "batch", "row_number", "raw_clause_reference", "reported_status", "remarks", "subclause", "clause_path", "validation_error", "confirmed_assessment", "confirmed_assessment_status"]
        read_only_fields = fields


class AuditorReportImportRowUpdateSerializer(serializers.Serializer):
    subclause = serializers.UUIDField()
    reported_status = serializers.ChoiceField(choices=AuditorReportImportRow.ReportedStatus.choices)
    remarks = serializers.CharField(allow_blank=False)


class AuditorReportImportSerializer(serializers.ModelSerializer):
    rows = AuditorReportImportRowSerializer(many=True, read_only=True)
    report_title = serializers.CharField(source="report.title", read_only=True)

    class Meta:
        model = AuditorReportImport
        fields = ["id", "report", "report_title", "status", "extraction_note", "created_by", "created_at", "confirmed_by", "confirmed_at", "rows"]
        read_only_fields = fields

