from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.test import APIClient
from io import BytesIO
from openpyxl import Workbook

from apps.tenancy.models import Membership, Tenant

from .models import Asset, CriticalService, Site
from .services import import_assets_csv, import_assets_file, save_inventory_object


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

    def test_asset_requires_same_tenant_accountability_and_scope(self):
        asset = Asset(tenant=self.tenant, asset_tag="RTR-01", name="Core router", kind=Asset.Kind.NETWORK_DEVICE, site=self.site, service=self.service, owner=self.owner, custodian=self.foreign, criticality=CriticalService.Criticality.CRITICAL, created_by=self.owner)
        with self.assertRaises(ValidationError):
            save_inventory_object(obj=asset, actor=self.owner)

    def test_viewer_cannot_mutate_inventory(self):
        with self.assertRaises(PermissionDenied):
            save_inventory_object(obj=Site(tenant=self.tenant, code="X", name="X", kind=Site.Kind.OTHER, created_by=self.viewer), actor=self.viewer)

    def test_csv_import_is_atomic_when_any_row_is_invalid(self):
        payload = b"asset_tag,name,kind,owner_username,custodian_username,criticality,site_code\nRTR-01,Router,NETWORK_DEVICE,asset-owner,asset-owner,CRITICAL,KHI-01\nRTR-02,Router 2,BAD,asset-owner,asset-owner,HIGH,KHI-01\n"
        with self.assertRaises(ValidationError):
            import_assets_csv(tenant=self.tenant, actor=self.owner, content=payload)
        self.assertFalse(Asset.objects.filter(tenant=self.tenant).exists())

    def test_csv_rejects_unresolved_scope_reference(self):
        payload = b"asset_tag,name,kind,owner_username,custodian_username,criticality,site_code\nRTR-01,Router,NETWORK_DEVICE,asset-owner,asset-owner,CRITICAL,UNKNOWN\n"
        with self.assertRaisesMessage(ValidationError, "Unknown site_code"):
            import_assets_csv(tenant=self.tenant, actor=self.owner, content=payload)

    def test_flexible_csv_headers_and_windows_encoding_are_mapped(self):
        payload = "Inventory Code,Device Name,Category,Business Owner,Technical Custodian,Priority,Location\nRTR-01,Core Router,Router,asset-owner,asset-owner,Critical,KHI-01\n".encode("cp1252")
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="inventory.csv", content=payload), 1)
        asset = Asset.objects.get(asset_tag="RTR-01")
        self.assertEqual(asset.kind, Asset.Kind.NETWORK_DEVICE)
        self.assertEqual(asset.criticality, CriticalService.Criticality.CRITICAL)

    def test_xlsx_headers_are_mapped_to_internal_fields(self):
        workbook = Workbook(); sheet = workbook.active
        sheet.append(["Asset ID", "Asset Name", "Asset Type", "Owner", "Custodian", "Impact", "Site Code", "CII"])
        sheet.append(["SRV-01", "Billing VM", "VM", "asset-owner", "asset-owner", "High", "KHI-01", "Yes"])
        stream = BytesIO(); workbook.save(stream)
        self.assertEqual(import_assets_file(tenant=self.tenant, actor=self.owner, filename="assets.xlsx", content=stream.getvalue()), 1)
        asset = Asset.objects.get(asset_tag="SRV-01")
        self.assertEqual(asset.kind, Asset.Kind.SERVER)
        self.assertTrue(asset.is_cii)

    def test_api_is_tenant_scoped(self):
        Asset.objects.create(tenant=self.tenant, asset_tag="A-1", name="Visible", kind=Asset.Kind.SERVER, owner=self.owner, custodian=self.owner, criticality=CriticalService.Criticality.HIGH, created_by=self.owner)
        Asset.objects.create(tenant=self.other, asset_tag="B-1", name="Hidden", kind=Asset.Kind.SERVER, owner=self.foreign, custodian=self.foreign, criticality=CriticalService.Criticality.HIGH, created_by=self.foreign)
        client = APIClient()
        client.force_login(self.owner)
        device = TOTPDevice.objects.create(user=self.owner, name="test", confirmed=True)
        session = client.session; session["otp_device_id"] = device.persistent_id; session.save()
        response = client.get("/api/v1/assets/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["name"] for row in response.data["results"]], ["Visible"])
