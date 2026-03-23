from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.shortcuts import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .forms import ReportForm, ViewerRegistrationForm
from .models import Report, User, UserRole


def register_viewer(request):
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        form = ViewerRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = request.build_absolute_uri(
                reverse("activate_account", kwargs={"uidb64": uid, "token": token})
            )
            message = (
                "Bonjour,\n\n"
                "Votre compte Viewer VulnReport a ete cree.\n"
                "Veuillez confirmer votre compte en cliquant sur ce lien :\n"
                f"{activation_link}\n\n"
                "Si vous n'etes pas a l'origine de cette demande, ignorez cet email."
            )
            try:
                send_mail(
                    subject="Confirmation de votre compte VulnReport",
                    message=message,
                    from_email=None,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            except Exception:
                user.delete()
                messages.error(
                    request,
                    "Impossible d'envoyer l'email de confirmation. Verifiez la configuration SMTP.",
                )
                return render(request, "registration/register.html", {"form": form})
            messages.success(
                request,
                "Compte cree. Un email de confirmation a ete envoye pour activer votre acces.",
            )
            return redirect("login")
        messages.error(request, "Le formulaire contient des erreurs. Verifiez les champs puis reessayez.")
    else:
        form = ViewerRegistrationForm()

    return render(request, "registration/register.html", {"form": form})


def activate_account(request, uidb64: str, token: str):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save(update_fields=["is_active"])
        messages.success(request, "Votre compte est active. Vous pouvez maintenant vous connecter.")
        return redirect("login")

    return HttpResponse("Lien d'activation invalide ou expire.", status=400)


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
