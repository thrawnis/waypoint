from django.db import migrations


def unverify_unconfirmed(apps, schema_editor):
    # Accounts registered while verification was off were stored as verified
    # without ever confirming anything; a real confirmation always records
    # verified_at. Reset those so they must verify once SMTP is enabled.
    EmailVerification = apps.get_model("tracker", "EmailVerification")
    EmailVerification.objects.filter(verified=True, verified_at__isnull=True).update(verified=False)


class Migration(migrations.Migration):

    dependencies = [
        ("tracker", "0028_webauthncredential"),
    ]

    operations = [
        migrations.RunPython(unverify_unconfirmed, migrations.RunPython.noop),
    ]
