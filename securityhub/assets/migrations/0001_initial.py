# Generated migration for the assets app

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('project', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ip', models.GenericIPAddressField(blank=True, null=True)),
                ('hostname', models.CharField(blank=True, max_length=255)),
                ('os', models.CharField(blank=True, max_length=100)),
                ('tags', models.JSONField(blank=True, default=list)),
                ('criticality', models.CharField(
                    choices=[
                        ('critical', 'Critical'),
                        ('high', 'High'),
                        ('medium', 'Medium'),
                        ('low', 'Low'),
                        ('unknown', 'Unknown'),
                    ],
                    default='unknown',
                    max_length=20,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='assets',
                    to='project.project',
                )),
            ],
            options={
                'ordering': ['hostname', 'ip'],
                'unique_together': {('project', 'ip', 'hostname')},
            },
        ),
        migrations.AddField(
            model_name='asset',
            name='vulnerabilities',
            field=models.ManyToManyField(
                blank=True,
                related_name='assets',
                to='project.vulnerability',
            ),
        ),
    ]
