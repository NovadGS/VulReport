# Generated manually – adds CRITICAL severity and OWASP-aligned KB categories

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0007_user_profile_id_friendrequest"),
    ]

    operations = [
        migrations.AlterField(
            model_name="finding",
            name="severity_level",
            field=models.IntegerField(
                choices=[(1, "Low"), (2, "Medium"), (3, "High"), (4, "Critical")],
                db_index=True,
                default=1,
            ),
        ),
        migrations.AlterField(
            model_name="knowledgebase",
            name="default_severity",
            field=models.IntegerField(
                choices=[(1, "Low"), (2, "Medium"), (3, "High"), (4, "Critical")],
                default=1,
            ),
        ),
        migrations.AlterField(
            model_name="knowledgebase",
            name="category",
            field=models.CharField(
                choices=[
                    ("web", "Web"),
                    ("crypto", "Crypto"),
                    ("network", "Network"),
                    ("injection", "Injection"),
                    ("auth", "Broken Authentication"),
                    ("xss", "Cross-Site Scripting"),
                    ("access_control", "Broken Access Control"),
                    ("misconfig", "Security Misconfiguration"),
                    ("components", "Vulnerable Components"),
                    ("logging", "Logging & Monitoring"),
                ],
                db_index=True,
                max_length=50,
            ),
        ),
    ]
