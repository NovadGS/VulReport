from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render

from .forms import ReportForm, ViewerRegistrationForm
from .models import Report, UserRole


def register_viewer(request):
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = ViewerRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Compte Viewer cree avec succes.")
            return redirect("home")
    else:
        form = ViewerRegistrationForm()

    return render(request, "registration/register.html", {"form": form})


@login_required
def home(request):
    reports = Report.objects.select_related("author").all()[:30]
    can_create = request.user.role in {UserRole.ADMIN, UserRole.PENTESTER}
    return render(request, "core/home.html", {"reports": reports, "can_create": can_create})


@login_required
def report_detail(request, report_id: int):
    report = get_object_or_404(Report.objects.select_related("author"), pk=report_id)
    can_edit = request.user.role == UserRole.ADMIN or report.author_id == request.user.id
    return render(request, "core/report_detail.html", {"report": report, "can_edit": can_edit})


@login_required
def report_create(request):
    if request.user.role not in {UserRole.ADMIN, UserRole.PENTESTER}:
        raise PermissionDenied("Seuls les admins et pentesters peuvent creer des rapports.")

    if request.method == "POST":
        form = ReportForm(request.POST)
        if form.is_valid():
            report = form.save(commit=False)
            report.author = request.user
            report.save()
            form.save_m2m()
            messages.success(request, "Rapport cree avec succes.")
            return redirect("report_detail", report_id=report.id)
    else:
        form = ReportForm()

    return render(request, "core/report_form.html", {"form": form, "is_edit": False})


@login_required
def report_edit(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    if not (request.user.role == UserRole.ADMIN or report.author_id == request.user.id):
        raise PermissionDenied("Seul le createur ou un admin peut modifier ce rapport.")

    if request.method == "POST":
        form = ReportForm(request.POST, instance=report)
        if form.is_valid():
            form.save()
            messages.success(request, "Rapport mis a jour avec succes.")
            return redirect("report_detail", report_id=report.id)
    else:
        form = ReportForm(instance=report)

    return render(request, "core/report_form.html", {"form": form, "report": report, "is_edit": True})
