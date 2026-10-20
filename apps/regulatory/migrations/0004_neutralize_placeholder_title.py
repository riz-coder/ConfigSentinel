from django.db import migrations


OLD_TITLE = "PTA CTDISR 2025 — authenticated source required"
NEW_TITLE = "Framework source — authenticated copy required"


def neutralize_placeholder(apps, schema_editor):
    RegulatorySource = apps.get_model("regulatory", "RegulatorySource")
    _rename(RegulatorySource, schema_editor, OLD_TITLE, NEW_TITLE)


def restore_placeholder(apps, schema_editor):
    RegulatorySource = apps.get_model("regulatory", "RegulatorySource")
    _rename(RegulatorySource, schema_editor, NEW_TITLE, OLD_TITLE)


def _rename(model, schema_editor, old_title, new_title):
    is_postgres = schema_editor.connection.vendor == "postgresql"
    if is_postgres:
        schema_editor.execute('ALTER TABLE "regulatory_regulatorysource" NO FORCE ROW LEVEL SECURITY')
    try:
        model.objects.filter(title=old_title, gazette_identifier="", sha256="").update(title=new_title)
    finally:
        if is_postgres:
            schema_editor.execute('ALTER TABLE "regulatory_regulatorysource" FORCE ROW LEVEL SECURITY')


class Migration(migrations.Migration):
    dependencies = [("regulatory", "0003_controldefinition_evidencerequirement_and_more")]
    operations = [migrations.RunPython(neutralize_placeholder, restore_placeholder)]
