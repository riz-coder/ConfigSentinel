from django.contrib import admin

from .models import (
    ControlDefinition, EvidenceRequirement, MappingReview, Obligation, ObligationControlMapping,
    Regulation, RegulatoryImportBatch, RegulatoryReview, RegulatorySource, RegulatoryVersion,
    SubClause, TestProcedure, TrustedSigningKey,
    ClauseAuditAssessment, ClauseEvidenceReview,
    AuditorReport,
    AuditorReportImport, AuditorReportImportRow,
    CorrectiveAction, CorrectiveActionEvent, CorrectiveActionEvidence,
)


@admin.register(RegulatorySource)
class RegulatorySourceAdmin(admin.ModelAdmin):
    readonly_fields = ("legal_status", "reviewed_by", "reviewed_at", "verification_completed_at", "created_at")


@admin.register(RegulatoryVersion)
class RegulatoryVersionAdmin(admin.ModelAdmin):
    readonly_fields = ("approval_status", "created_at")


@admin.register(Regulation, SubClause, Obligation)
class RegulatoryContentAdmin(admin.ModelAdmin):
    readonly_fields = ("legal_status",)


@admin.register(RegulatoryImportBatch, RegulatoryReview)
class RegulatoryProvenanceAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(TrustedSigningKey)
admin.site.register(ControlDefinition)
admin.site.register(TestProcedure)
admin.site.register(EvidenceRequirement)


@admin.register(ObligationControlMapping, MappingReview)
class MappingProvenanceAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ClauseAuditAssessment, ClauseEvidenceReview, AuditorReport, AuditorReportImport, AuditorReportImportRow, CorrectiveAction, CorrectiveActionEvent, CorrectiveActionEvidence)
class ClauseAuditProvenanceAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

