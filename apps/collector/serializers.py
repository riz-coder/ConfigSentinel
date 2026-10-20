from rest_framework import serializers

from .models import CollectionJob, CollectorAgent, CommandProfile, CredentialReference, Device, ScopeGrant


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        exclude = ["tenant", "created_by"]
        read_only_fields = ["id", "created_at"]


class CredentialReferenceSerializer(serializers.ModelSerializer):
    secret_reference = serializers.CharField(write_only=True)

    class Meta:
        model = CredentialReference
        fields = ["id", "name", "provider", "secret_reference", "is_active", "created_at"]
        read_only_fields = ["id", "created_at"]


class CollectorAgentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CollectorAgent
        exclude = ["tenant", "registered_by"]
        read_only_fields = ["id", "status", "created_at"]


class CommandProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommandProfile
        exclude = ["tenant", "created_by", "approved_by"]
        read_only_fields = ["id", "status", "approved_at", "created_at"]


class ScopeGrantSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScopeGrant
        exclude = ["tenant", "requested_by", "approved_by"]
        read_only_fields = ["id", "status", "approved_at", "revoked_at", "created_at"]


class CollectionJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = CollectionJob
        exclude = ["tenant", "requested_by"]
        read_only_fields = ["id", "max_commands", "max_runtime_seconds", "max_output_bytes", "state", "technical_result", "failure_reason", "created_at", "finished_at"]


class CollectionRequestSerializer(serializers.Serializer):
    device = serializers.UUIDField()
    agent = serializers.UUIDField()
    scope_grant = serializers.UUIDField()
    command_profile = serializers.UUIDField()
    observed_host_key_sha256 = serializers.CharField(max_length=95)
