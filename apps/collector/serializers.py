from rest_framework import serializers

from .models import CollectionJob, CollectorAgent, CommandDefinition, CommandProfile, CredentialReference, Device, ScopeGrant


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        exclude = ["tenant", "created_by"]
        read_only_fields = ["id", "is_active", "telnet_approved_by", "telnet_approved_at", "created_at"]


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


class CommandDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommandDefinition
        fields = ["id", "key", "command_text", "purpose", "sequence", "contains_sensitive_output"]
        read_only_fields = fields


class CommandProfileSerializer(serializers.ModelSerializer):
    commands = CommandDefinitionSerializer(many=True, read_only=True)

    class Meta:
        model = CommandProfile
        exclude = ["tenant", "created_by", "approved_by"]
        read_only_fields = ["id", "status", "approved_at", "approval_reference", "created_at", "manifest_sha256", "command_count", "commands"]


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
