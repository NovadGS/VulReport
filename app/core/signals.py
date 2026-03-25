from django.contrib.auth.models import Group
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver

from .models import AuditAction, AuditLog, User


@receiver(post_save, sender=User)
def log_user_role_change(sender, instance: User, created: bool, **kwargs):
    action = AuditAction.CREATE if created else AuditAction.PRIVILEGE_CHANGE
    AuditLog.objects.create(
        actor=instance,
        action=action,
        object_type="user",
        object_id=instance.pk,
        metadata={"role": instance.role, "created": created},
    )


@receiver(m2m_changed, sender=User.groups.through)
def log_group_membership_change(sender, instance: User, action: str, pk_set, **kwargs):
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    groups = list(Group.objects.filter(pk__in=pk_set).values_list("name", flat=True)) if pk_set else []
    AuditLog.objects.create(
        actor=instance,
        action=AuditAction.PRIVILEGE_CHANGE,
        object_type="user_group",
        object_id=instance.pk,
        metadata={"change_type": action, "groups": groups},
    )
