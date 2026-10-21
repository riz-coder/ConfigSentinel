import base64
import tempfile
from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.tenancy.models import Membership, Tenant

from .models import ClauseAuditAssessment, ClauseEvidence, CorrectiveAction, CorrectiveActionEvent, Regulation, RegulatorySource, RegulatoryVersion, SubClause
from .services import (
    add_corrective_action_progress, assess_clause, attach_corrective_action_evidence,
    configure_corrective_action, create_missing_corrective_action_drafts,
    review_clause_evidence, review_corrective_action_retest, submit_for_retest,
    upload_clause_evidence,
)


class CorrectiveActionWorkflowTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.override = self.settings(EVIDENCE_STORAGE_ROOT=Path(self.temp.name), EVIDENCE_MASTER_KEY=base64.b64encode(b"c" * 32).decode())
        self.override.enable()
        users = get_user_model().objects
        self.owner = users.create_user(username="capa-owner", password="test-password")
        self.compliance = users.create_user(username="capa-compliance", password="test-password")
        self.auditor = users.create_user(username="capa-auditor", password="test-password")
        self.tenant = Tenant.objects.create(name="CAPA tenant", slug="capa-tenant")
        Membership.objects.create(user=self.owner, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.compliance, tenant=self.tenant, role=Membership.Role.COMPLIANCE_LEAD)
        Membership.objects.create(user=self.auditor, tenant=self.tenant, role=Membership.Role.AUDITOR)
        source = RegulatorySource.objects.create(tenant=self.tenant, title="Pending source", sha256="b" * 64)
        version = RegulatoryVersion.objects.create(source=source, version_label="v1", approval_status=RegulatoryVersion.ApprovalStatus.UNDER_REVIEW)
        regulation = Regulation.objects.create(version=version, number=1, title="Clause", source_page="1", source_excerpt="Source")
        self.clause = SubClause.objects.create(regulation=regulation, clause_path="1", title="Clause", source_page="1")

    def tearDown(self):
        self.override.disable(); self.temp.cleanup()

    def _action_from_auditor_gap(self):
        evidence = upload_clause_evidence(tenant=self.tenant, actor=self.owner, subclause=self.clause, title="Initial", filename="initial.txt", content=b"Initial evidence")
        review_clause_evidence(artifact=evidence, reviewer=self.auditor, decision=ClauseEvidence.Status.ACCEPTED, note="Reviewed.")
        assessment = assess_clause(
            subclause=self.clause, reviewer=self.auditor,
            decision=ClauseAuditAssessment.Decision.REQUEST_UPDATE,
            note="Evidence requires remediation.", gaps="Provide approved current-period record.",
        )
        return assessment.corrective_action

    def test_auditor_gap_creates_draft_then_isp_evidence_retest_and_close(self):
        action = self._action_from_auditor_gap()
        self.assertEqual(action.status, CorrectiveAction.Status.OPEN)
        self.assertEqual(action.events.first().kind, CorrectiveActionEvent.Kind.CREATED)

        configure_corrective_action(
            action=action, actor=self.owner, assigned_to=self.compliance,
            due_date=timezone.localdate() + timedelta(days=5), remediation_plan="Update and obtain approval.",
        )
        add_corrective_action_progress(action=action, actor=self.compliance, note="Policy owner completed updates.")
        evidence = attach_corrective_action_evidence(
            action=action, actor=self.compliance, title="Updated policy", filename="updated.txt", content=b"Updated controlled evidence",
        )
        action.refresh_from_db()
        self.assertEqual(action.evidence_versions.get().evidence_id, evidence.id)
        submit_for_retest(action=action, actor=self.compliance, note="Updated evidence supplied for retest.")
        action.refresh_from_db()
        self.assertEqual(action.status, CorrectiveAction.Status.READY_FOR_RETEST)
        review_corrective_action_retest(action=action, actor=self.auditor, decision="CLOSE", note="Retest completed; workflow closed.")
        action.refresh_from_db()
        self.assertEqual(action.status, CorrectiveAction.Status.CLOSED)
        self.assertEqual(action.closed_by, self.auditor)

    def test_only_auditor_can_close_and_auditor_can_reopen(self):
        action = self._action_from_auditor_gap()
        configure_corrective_action(action=action, actor=self.owner, assigned_to=self.compliance, due_date=timezone.localdate(), remediation_plan="Fix it.")
        submit_for_retest(action=action, actor=self.compliance, note="Ready.")
        with self.assertRaises(PermissionDenied):
            review_corrective_action_retest(action=action, actor=self.owner, decision="CLOSE", note="No.")
        review_corrective_action_retest(action=action, actor=self.auditor, decision="REOPEN", note="Retest found approval missing.")
        action.refresh_from_db()
        self.assertEqual(action.status, CorrectiveAction.Status.REOPENED)

    def test_closed_action_and_events_are_immutable(self):
        action = self._action_from_auditor_gap()
        configure_corrective_action(action=action, actor=self.owner, assigned_to=self.compliance, due_date=timezone.localdate(), remediation_plan="Fix it.")
        submit_for_retest(action=action, actor=self.compliance, note="Ready.")
        review_corrective_action_retest(action=action, actor=self.auditor, decision="CLOSE", note="Closed.")
        with self.assertRaisesMessage(ValidationError, "Closed actions"):
            configure_corrective_action(action=action, actor=self.owner, assigned_to=self.compliance, due_date=timezone.localdate(), remediation_plan="Change")
        event = action.events.first()
        event.note = "Rewrite"
        with self.assertRaisesMessage(ValidationError, "append-only"):
            event.save()

    def test_authorized_user_can_backfill_old_auditor_gap_drafts_idempotently(self):
        assessment = ClauseAuditAssessment.objects.create(
            tenant=self.tenant,
            subclause=self.clause,
            reviewer=self.auditor,
            sequence=1,
            decision=ClauseAuditAssessment.Decision.REJECT,
            compliance_status=ClauseAuditAssessment.ComplianceStatus.LEGAL_UNVERIFIED,
            note="Older independent gap.",
            gaps="A controlled record is missing.",
            evidence_snapshot=[{"note": "Legacy assessment had no active evidence."}],
        )
        self.assertEqual(
            create_missing_corrective_action_drafts(tenant=self.tenant, actor=self.owner),
            1,
        )
        self.assertTrue(CorrectiveAction.objects.filter(source_assessment=assessment).exists())
        self.assertEqual(
            create_missing_corrective_action_drafts(tenant=self.tenant, actor=self.owner),
            0,
        )
