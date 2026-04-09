from django.db import migrations, models


def migrate_statuses(apps, schema_editor):
    Report = apps.get_model("core", "Report")
    Report.objects.filter(status="in_review").update(status="in_progress")
    Report.objects.filter(status="archived").update(status="published")


def reverse_statuses(apps, schema_editor):
    Report = apps.get_model("core", "Report")
    Report.objects.filter(status="in_progress").update(status="in_review")
    Report.objects.filter(status="published").update(status="archived")


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0008_extend_severity_and_kb_categories"),
    ]

    operations = [
        migrations.AlterField(
            model_name="report",
            name="status",
            field=models.CharField(
                choices=[
                    ("draft", "Brouillon"),
                    ("in_progress", "En cours"),
                    ("final", "Finalisé"),
                    ("published", "Publié"),
                ],
                db_index=True,
                default="draft",
                max_length=20,
            ),
        ),
        migrations.RunPython(migrate_statuses, reverse_statuses),
    ]
