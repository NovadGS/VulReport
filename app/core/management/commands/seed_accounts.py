"""Create default demo accounts (admin / pentester / viewer) if they don't exist."""

import os

from django.core.management.base import BaseCommand

from core.models import User, UserRole


SEED_ACCOUNTS = [
    {
        "username": "admin",
        "email": "admin@vulnreport.local",
        "role": UserRole.ADMIN,
        "is_staff": True,
        "is_superuser": True,
    },
    {
        "username": "pentester",
        "email": "pentester@vulnreport.local",
        "role": UserRole.PENTESTER,
        "is_staff": False,
        "is_superuser": False,
    },
    {
        "username": "viewer",
        "email": "viewer@vulnreport.local",
        "role": UserRole.VIEWER,
        "is_staff": False,
        "is_superuser": False,
    },
]

DEFAULT_PASSWORD = os.getenv("SEED_PASSWORD", "VulnReport2025!")


class Command(BaseCommand):
    help = "Create default demo accounts (admin, pentester, viewer)"

    def handle(self, *_args, **_options):
        for acct in SEED_ACCOUNTS:
            username = acct["username"]
            if User.objects.filter(username=username).exists():
                self.stdout.write(f"  {username} already exists, skipping.")
                continue
            user = User(
                username=username,
                email=acct["email"],
                role=acct["role"],
                is_staff=acct["is_staff"],
                is_superuser=acct["is_superuser"],
                is_active=True,
            )
            user.set_password(DEFAULT_PASSWORD)
            user.save()
            self.stdout.write(self.style.SUCCESS(f"  Created {username} ({acct['role']})"))
