from django.urls import path

from . import views


urlpatterns = [
    path("", views.home, name="home"),
    path("share/<str:token>/", views.report_public_share, name="report_public_share"),
    path("account/settings/", views.account_settings, name="account_settings"),
    path("organizations/", views.organization_list, name="organization_list"),
    path("organizations/create/", views.organization_create, name="organization_create"),
    path("organizations/<int:org_id>/", views.organization_detail, name="organization_detail"),
    path("organizations/<int:org_id>/add-member/", views.organization_add_member, name="organization_add_member"),
    path(
        "organizations/<int:org_id>/members/<int:user_id>/role/",
        views.organization_update_member_role,
        name="organization_update_member_role",
    ),
    path(
        "organizations/<int:org_id>/members/<int:user_id>/remove/",
        views.organization_remove_member,
        name="organization_remove_member",
    ),
    path("resources/", views.resources, name="resources"),
    path("kb/", views.kb_list, name="kb_list"),
    path("kb/create/", views.kb_create, name="kb_create"),
    path("kb/<int:entry_id>/", views.kb_detail, name="kb_detail"),
    path("kb/<int:entry_id>/edit/", views.kb_edit, name="kb_edit"),
    path("kb/<int:entry_id>/delete/", views.kb_delete, name="kb_delete"),
    path("mfa/setup/", views.mfa_setup, name="mfa_setup"),
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("accounts/register/", views.register_viewer, name="register"),
    path(
        "accounts/activate/<uidb64>/<token>/",
        views.activate_account,
        name="activate_account",
    ),
    path("reports/create/", views.report_create, name="report_create"),
    path("reports/<int:report_id>/", views.report_detail, name="report_detail"),
    path("reports/<int:report_id>/edit/", views.report_edit, name="report_edit"),
    path("reports/<int:report_id>/delete/", views.report_delete, name="report_delete"),
    path("reports/<int:report_id>/pdf/", views.report_pdf, name="report_pdf"),
    path("reports/<int:report_id>/request-review/", views.report_request_review, name="report_request_review"),
    path("reports/<int:report_id>/approve/", views.report_approve, name="report_approve"),
    path("reports/<int:report_id>/share-link/", views.report_generate_share_link, name="report_generate_share_link"),
    path("reports/<int:report_id>/share-org/", views.report_share_with_org, name="report_share_with_org"),
    path("reports/<int:report_id>/findings/<int:finding_id>/comments/", views.finding_add_comment, name="finding_add_comment"),
    path("reports/<int:report_id>/findings/from-cve/", views.report_add_finding_from_cve, name="report_add_finding_from_cve"),
    path("reports/<int:report_id>/import/", views.report_import_tool_report, name="report_import_tool_report"),
    path("api/report-autofill/", views.report_autofill, name="report_autofill"),
    path("api/cve/", views.cve_lookup, name="cve_lookup"),
]
