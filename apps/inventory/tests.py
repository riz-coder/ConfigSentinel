import csv
import io

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.test import APIClient

from apps.tenancy.models import Membership, Tenant
from .models import Asset, CriticalService, Site
from .services import TEMPLATE_COLUMNS, asset_template_csv, asset_template_xlsx, import_assets_file, save_inventory_object, standard_template_rows


class InventoryFoundationTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.owner = users.create_user(username="asset-owner", password="test-password")
        self.viewer = users.create_user(username="asset-viewer", password="test-password")
        self.foreign = users.create_user(username="foreign-owner", password="test-password")
        self.tenant = Tenant.objects.create(name="Asset tenant", slug="asset-tenant")
        self.other = Tenant.objects.create(name="Other tenant", slug="other-tenant")
        Membership.objects.create(user=self.owner, tenant=self.tenant, role=Membership.Role.OWNER)
        Membership.objects.create(user=self.viewer, tenant=self.tenant, role=Membership.Role.VIEWER)
        Membership.objects.create(user=self.foreign, tenant=self.other, role=Membership.Role.OWNER)
        self.site = save_inventory_object(obj=Site(tenant=self.tenant, code="KHI-01", name="Karachi", kind=Site.Kind.POP, created_by=self.owner), actor=self.owner)
        self.service = save_inventory_object(obj=CriticalService(tenant=self.tenant, code="DNS", name="DNS", criticality=CriticalService.Criticality.CRITICAL, owner=self.owner, created_by=self.owner), actor=self.owner)

    def _csv(self, rows, delimiter=",", encoding="utf-8-sig"):
        stream = io.StringIO(); writer = csv.DictWriter(stream, fieldnames=TEMPLATE_COLUMNS, delimiter=delimiter, lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
        return stream.getvalue().encode(encoding)

    def test_asset_requires_same_tenant_accountability_and_scope(self):
        asset = Asset(tenant=self.tenant, asset_tag="RTR-01", name="Core router", kind=Asset.Kind.NETWORK_DEVICE, site=self.site, service=self.service, owner=self.owner, custodian=self.foreign, criticality=CriticalService.Criticality.CRITICAL, created_by=self.owner)
        with self.assertRaises(ValidationError):
            save_inventory_object(obj=asset, actor=self.owner)

    def test_viewer_cannot_mutate_inventory(self):
        with self.assertRaises(PermissionDenied):
            save_inventory_object(obj=Site(tenant=self.tenant, code="X", name="X", kind=Site.Kind.OTHER, created_by=self.viewer), actor=self.viewer)

    def test_csv_import_is_atomic_when_any_row_is_invalid(self):
        rows = standard_template_rows(self.owner.username)[:2]; rows[1]["asset_type"] = "BAD"
        with self.assertRaises(ValidationError):
            import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.csv", content=self._csv(rows))
        self.assertFalse(Asset.objects.filter(tenant=self.tenant).exists())

    def test_csv_rejects_unresolved_scope_reference(self):
        rows = standard_template_rows(self.owner.username)[:1]; rows[0]["site_code"] = "UNKNOWN"
        with self.assertRaisesMessage(ValidationError, "Unknown site_code"):
            import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.csv", content=self._csv(rows))

    def test_standard_csv_supports_windows_encoding_and_semicolon_delimiter(self):
        rows = standard_template_rows(self.owner.username)[:1]; rows[0]["asset_name"] = "Café Router"
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="inventory.csv", content=self._csv(rows, ";", "cp1252")), 1)
        self.assertEqual(Asset.objects.get(asset_tag="NET-CORE-001").name, "Café Router")

    def test_policy_aligned_xlsx_template_imports_sample_rows(self):
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.xlsx", content=asset_template_xlsx(self.owner.username)), 3)
        asset = Asset.objects.get(asset_tag="NET-CORE-001")
        self.assertEqual(asset.business_function, "Internet connectivity")
        self.assertTrue(asset.is_cii)

    def test_excel_content_is_detected_when_file_has_csv_extension(self):
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="wrong.csv", content=asset_template_xlsx(self.owner.username)), 3)

    def test_unknown_acquisition_and_review_dates_do_not_block_import(self):
        rows = standard_template_rows(self.owner.username)[:1]
        rows[0]["date_of_acquisition"] = ""
        rows[0]["last_reviewed_on"] = ""
        rows[0]["next_review_due"] = ""
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.csv", content=self._csv(rows)), 1)
        asset = Asset.objects.get(asset_tag="NET-CORE-001")
        self.assertIsNone(asset.acquired_on)
        self.assertIsNone(asset.last_reviewed_on)
        self.assertIsNone(asset.review_due_at)

    def test_repeated_row_errors_are_compacted(self):
        rows = standard_template_rows(self.owner.username)[:2]
        for row in rows:
            row["asset_name"] = ""
        with self.assertRaisesMessage(ValidationError, "Rows 2-3: Required values are blank: name"):
            import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.csv", content=self._csv(rows))

    def test_business_owner_roles_are_preserved_without_workspace_accounts(self):
        rows = standard_template_rows(self.owner.username)[:1]
        rows[0]["asset_owner"] = "IP-NOC"
        rows[0]["custodian_responsible_person"] = "Network Operations"
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.csv", content=self._csv(rows)), 1)
        asset = Asset.objects.get(asset_tag="NET-CORE-001")
        self.assertEqual(asset.declared_owner, "IP-NOC")
        self.assertEqual(asset.declared_custodian, "Network Operations")
        self.assertEqual(asset.owner, self.owner)
        self.assertEqual(asset.custodian, self.owner)

    def test_template_csv_has_fixed_policy_columns_and_three_examples(self):
        rows = list(csv.DictReader(io.StringIO(asset_template_csv(self.owner.username).decode("utf-8-sig"))))
        self.assertEqual(list(rows[0]), TEMPLATE_COLUMNS)
        self.assertEqual(len(rows), 3)

    def test_api_is_tenant_scoped(self):
        Asset.objects.create(tenant=self.tenant, asset_tag="A-1", name="Visible", kind=Asset.Kind.SERVER, owner=self.owner, custodian=self.owner, criticality=CriticalService.Criticality.HIGH, created_by=self.owner)
        Asset.objects.create(tenant=self.other, asset_tag="B-1", name="Hidden", kind=Asset.Kind.SERVER, owner=self.foreign, custodian=self.foreign, criticality=CriticalService.Criticality.HIGH, created_by=self.foreign)
        client = APIClient(); client.force_login(self.owner)
        device = TOTPDevice.objects.create(user=self.owner, name="test", confirmed=True)
        session = client.session; session["otp_device_id"] = device.persistent_id; session.save()
        response = client.get("/api/v1/assets/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["name"] for row in response.data["results"]], ["Visible"])
        csv_response = client.get("/inventory/template.csv")
        xlsx_response = client.get("/inventory/template.xlsx")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn("asset-register-template.csv", csv_response["Content-Disposition"])
        self.assertEqual(xlsx_response.status_code, 200)
        self.assertTrue(xlsx_response.content.startswith(b"PK\x03\x04"))
