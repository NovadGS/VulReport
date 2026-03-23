from django.urls import path

from . import views


urlpatterns = [
    path("", views.home, name="home"),
    path("accounts/register/", views.register_viewer, name="register"),
    path("reports/create/", views.report_create, name="report_create"),
    path("reports/<int:report_id>/", views.report_detail, name="report_detail"),
    path("reports/<int:report_id>/edit/", views.report_edit, name="report_edit"),
]
