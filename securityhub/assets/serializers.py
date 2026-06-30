from rest_framework import serializers

from .models import Asset


class AssetSerializer(serializers.ModelSerializer):
    risk_score = serializers.IntegerField(read_only=True)
    vulnerability_count = serializers.SerializerMethodField()

    def get_vulnerability_count(self, obj):
        return obj.vulnerabilities.count()

    class Meta:
        model = Asset
        fields = [
            'id', 'project', 'ip', 'hostname', 'os', 'tags', 'criticality',
            'risk_score', 'vulnerability_count', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class AssetDetailSerializer(AssetSerializer):
    """Includes vulnerability IDs for the detail view."""
    vulnerabilities = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta(AssetSerializer.Meta):
        fields = AssetSerializer.Meta.fields + ['vulnerabilities']
