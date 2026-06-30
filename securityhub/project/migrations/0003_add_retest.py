import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('project', '0002_vulnerability_cve_enrichment'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Retest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('date', models.DateField()),
                ('result', models.CharField(
                    choices=[
                        ('fixed', 'Fixed'),
                        ('still_vulnerable', 'Still Vulnerable'),
                        ('partial_fix', 'Partial Fix'),
                    ],
                    max_length=20,
                )),
                ('notes', models.TextField(blank=True)),
                ('evidence', models.TextField(blank=True, help_text='Screenshot URL or text evidence')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('vulnerability', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='retests',
                    to='project.vulnerability',
                )),
                ('tester', models.ForeignKey(
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-date', '-created_at'],
            },
        ),
    ]
