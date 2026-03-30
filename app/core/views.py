from django.contrib import messages
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.core.mail import send_mail
from django.shortcuts import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils import timezone
from django.views.decorators.http import require_POST
from datetime import timedelta

from .forms import (
    AccountSettingsForm,
    CurrentUserPasswordResetForm,
    FindingCommentForm,
    FriendSearchForm,
    KnowledgeBaseForm,
    OrganizationAddMemberForm,
    OrganizationCreateForm,
    ReportForm,
    ViewerRegistrationForm,
)
from .cve_sources import fetch_cve_data
from .mfa import build_totp_enrollment, get_or_create_totp_device, verify_totp_code
from .models import (
    Finding,
    FindingComment,
    FriendRequest,
    FriendRequestStatus,
    KnowledgeBase,
    Organization,
    OrganizationMembership,
    OrganizationRole,
    Report,
    ReportOrganizationShare,
    TopDevice,
    User,
    UserRole,
)
import hashlib
import hmac
import secrets


def _ensure_can_edit_report(user, report: Report) -> None:
    if user.role == UserRole.ADMIN:
        return
    if user.role == UserRole.PENTESTER and report.author_id == user.id:
        return
    raise PermissionDenied("Acces interdit.")


def _audit(request, action: str, object_type: str, object_id: int | None = None, metadata: dict | None = None):
    from .models import AuditLog

    AuditLog.objects.create(
        actor=request.user if getattr(request, "user", None) and request.user.is_authenticated else None,
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=request.META.get("REMOTE_ADDR"),
        metadata=metadata or {},
    )


def _is_org_admin_or_owner(org: Organization, user: User) -> bool:
    membership = OrganizationMembership.objects.filter(organization=org, user=user).first()
    if not membership:
        return False
    return membership.role in {OrganizationRole.OWNER, OrganizationRole.ADMIN}


def _clean_text(value: str, limit: int = 2000) -> str:
    return " ".join((value or "").replace("\r", " ").replace("\n", " ").split())[:limit].strip()


def _friends_for_user(user: User) -> list[User]:
    relations = FriendRequest.objects.filter(status=FriendRequestStatus.ACCEPTED).filter(
        Q(from_user=user) | Q(to_user=user)
    ).select_related("from_user", "to_user")
    friends = []
    for relation in relations:
        friends.append(relation.to_user if relation.from_user_id == user.id else relation.from_user)
    return sorted(friends, key=lambda item: item.username.lower())


def _friend_context(user: User) -> dict:
    return {
        "friends": _friends_for_user(user),
        "incoming_requests": FriendRequest.objects.filter(
            to_user=user,
            status=FriendRequestStatus.PENDING,
        ).select_related("from_user"),
        "outgoing_requests": FriendRequest.objects.filter(
            from_user=user,
            status=FriendRequestStatus.PENDING,
        ).select_related("to_user"),
    }


def _extract_report_suggestions_from_text(raw_text: str, source_name: str = "") -> dict[str, str]:
    import re

    text = (raw_text or "").strip()
    if not text:
        return {"title": "", "context": "", "executive_summary": ""}

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    low_noise_lines = [
        line for line in lines
        if not re.search(r"(font-family|padding:|margin:|color:|display:|<style|</style>)", line, re.I)
    ]

    joined = " ".join(low_noise_lines) if low_noise_lines else " ".join(lines)
    title_guess = ""
    for candidate in low_noise_lines[:20]:
        if 6 <= len(candidate) <= 120 and not re.search(r"(http|www\.|{|\}|;)", candidate):
            title_guess = candidate
            break
    if not title_guess:
        filename_base = (source_name or "rapport").rsplit(".", 1)[0]
        title_guess = f"Rapport importé - {filename_base}".strip(" -")

    # Heuristiques "pentest report": extraire quelques signaux utiles.
    risk_counts = {}
    for level in ("critical", "high", "medium", "low", "info"):
        m = re.search(rf"\b{level}\b[^0-9]{{0,20}}(\d{{1,4}})", joined, re.I)
        if m:
            risk_counts[level.upper()] = m.group(1)

    urls = re.findall(r"https?://[^\s\"'<>]+", text, flags=re.I)
    host = ""
    if urls:
        host = re.sub(r"^https?://", "", urls[0], flags=re.I).split("/")[0]

    vuln_keywords = []
    keyword_map = [
        ("xss", "XSS"),
        ("sql injection", "SQL Injection"),
        ("csrf", "CSRF"),
        ("command injection", "Command Injection"),
        ("path traversal", "Path Traversal"),
        ("insecure cookie", "Insecure Cookie"),
        ("missing security headers", "Security Headers manquants"),
        ("open redirect", "Open Redirect"),
    ]
    lowered = joined.lower()
    for needle, label in keyword_map:
        if needle in lowered and label not in vuln_keywords:
            vuln_keywords.append(label)
        if len(vuln_keywords) >= 6:
            break

    resume_parts = []
    if host:
        resume_parts.append(f"Cible analysée: {host}.")
    if risk_counts:
        counts = ", ".join(f"{k}: {v}" for k, v in risk_counts.items())
        resume_parts.append(f"Répartition de sévérité détectée: {counts}.")
    if vuln_keywords:
        resume_parts.append("Vulnérabilités probables: " + ", ".join(vuln_keywords) + ".")
    if not resume_parts:
        sample = _clean_text(joined, 320)
        resume_parts.append(f"Contenu importé analysé automatiquement. Extrait: {sample}")

    context_lines = []
    if host:
        context_lines.append(f"Application cible: {host}")
    if vuln_keywords:
        context_lines.append("Axes principaux: " + ", ".join(vuln_keywords))
    if risk_counts:
        context_lines.append("Priorisation initiale: " + ", ".join(f"{k}={v}" for k, v in risk_counts.items()))
    context_lines.append("Source: rapport importé (analyse automatique).")
    context_lines.append("Valider manuellement les points avant publication.")

    executive_summary = _clean_text(" ".join(resume_parts), 800)
    context = _clean_text(" | ".join(context_lines), 1200)
    title = _clean_text(title_guess, 120) or "Rapport importe"

    return {
        "title": title,
        "context": context,
        "executive_summary": executive_summary,
    }


def _read_upload_as_text(upload) -> str:
    raw = upload.read().decode("utf-8", errors="replace")
    lowered = (getattr(upload, "name", "") or "").lower()
    if lowered.endswith((".html", ".htm")):
        import re
        # Remove noisy sections first, then strip tags.
        raw = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", raw)
        raw = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", raw)
        raw = re.sub(r"<[^>]+>", " ", raw)
        raw = re.sub(r"&nbsp;|&#160;", " ", raw)
    return raw


def _create_finding_from_cve_id(report: Report, cve_id: str) -> Finding | None:
    normalized_cve = (cve_id or "").strip().upper()
    if not normalized_cve:
        return None
    data = fetch_cve_data(normalized_cve)
    if not data:
        return None

    severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 3}
    sev = severity_map.get((data.severity_label or "").strip().upper(), 1)
    return Finding.objects.create(
        report=report,
        cve_id=data.cve_id,
        source_urls=data.sources,
        title=data.title or data.cve_id,
        description=data.description or "",
        references="\n".join(data.references or []),
        severity_level=sev,
        cvss_score=(data.cvss_score or 0.0),
        display_order=report.findings.count(),
    )


def _import_findings_from_upload(report: Report, upload) -> int:
    if not upload:
        return 0
    if upload.size > settings.MAX_IMPORT_FILE_SIZE:
        raise ValueError("Fichier trop volumineux pour l'import.")
    allowed_types = {
        "application/json",
        "text/json",
        "text/plain",
        "text/html",
        "application/xhtml+xml",
    }
    filename = (getattr(upload, "name", "") or "").lower()
    allowed_ext = (".json", ".html", ".htm", ".txt")
    if upload.content_type not in allowed_types and not filename.endswith(allowed_ext):
        raise ValueError("Type de fichier non autorise (JSON/HTML/TXT attendus).")

    import json

    raw = upload.read().decode("utf-8", errors="replace")
    data = None
    try:
        data = json.loads(raw)
    except Exception:
        data = None

    created = 0

    if isinstance(data, dict) and isinstance(data.get("results"), list):
        for item in data["results"]:
            if created >= settings.MAX_IMPORT_FINDINGS:
                break
            issue = (item.get("issue_text") or "Bandit finding").strip()
            sev = (item.get("issue_severity") or "LOW").strip().upper()
            conf = (item.get("issue_confidence") or "").strip().upper()
            sev_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
            score = {"LOW": 3.0, "MEDIUM": 6.0, "HIGH": 8.5}.get(sev, 0.0)
            filename = item.get("filename") or ""
            line = item.get("line_number") or ""
            code = item.get("code") or ""
            desc = f"{issue}\n\nFichier: {filename}:{line}\nConfiance: {conf}\n\n{code}".strip()
            Finding.objects.create(
                report=report,
                title=f"[Bandit] {issue}"[:255],
                description=desc,
                severity_level=sev_map.get(sev, 1),
                cvss_score=score,
                references="Bandit",
                display_order=report.findings.count() + created,
            )
            created += 1

    if isinstance(data, dict) and isinstance(data.get("site"), list):
        for site in data["site"]:
            if created >= settings.MAX_IMPORT_FINDINGS:
                break
            alerts = site.get("alerts") or []
            if not isinstance(alerts, list):
                continue
            for a in alerts:
                if created >= settings.MAX_IMPORT_FINDINGS:
                    break
                name = (a.get("name") or "ZAP Alert").strip()
                risk = (a.get("riskcode") or a.get("riskdesc") or "").strip()
                sev_map = {"0": 1, "1": 1, "2": 2, "3": 3}
                sev = sev_map.get(str(risk).split()[0], 1)
                desc = (a.get("desc") or "").strip()
                sol = (a.get("solution") or "").strip()
                ref = (a.get("reference") or "").strip()
                Finding.objects.create(
                    report=report,
                    title=f"[ZAP] {name}"[:255],
                    description=desc,
                    recommendation=sol,
                    references=ref,
                    severity_level=sev,
                    cvss_score=0.0,
                    display_order=report.findings.count() + created,
                )
                created += 1

    if created == 0:
        # Fallback for HTML/TXT or unknown JSON schema.
        content_preview = raw[:20000].strip()
        if not content_preview:
            raise ValueError("Fichier vide ou non exploitable.")
        Finding.objects.create(
            report=report,
            title=f"[Import] {getattr(upload, 'name', 'report')}"[:255],
            description=content_preview,
            references="Import brut (non structure).",
            severity_level=1,
            cvss_score=0.0,
            display_order=report.findings.count(),
        )
        created = 1

    return created


@login_required
@require_POST
def report_autofill(request):
    if request.user.role not in {UserRole.ADMIN, UserRole.PENTESTER}:
        raise PermissionDenied("Acces interdit.")

    cve_id = (request.POST.get("cve_id") or "").strip()
    upload = request.FILES.get("file")
    payload = {
        "title": "",
        "context": "",
        "executive_summary": "",
        "cve": {},
    }

    if upload:
        if upload.size > settings.MAX_IMPORT_FILE_SIZE:
            return HttpResponse('{"error":"file_too_large"}', content_type="application/json", status=400)
        text = _read_upload_as_text(upload)
        payload.update(_extract_report_suggestions_from_text(text, getattr(upload, "name", "")))

    if cve_id:
        data = fetch_cve_data(cve_id)
        if data:
            payload["cve"] = {
                "cve_id": data.cve_id,
                "title": data.title or "",
                "description": data.description or "",
                "severity": data.severity_label or "",
                "cvss_score": data.cvss_score,
            }
            if not payload["title"]:
                payload["title"] = _clean_text(data.title or data.cve_id, 120)
            if not payload["executive_summary"]:
                payload["executive_summary"] = _clean_text(data.description or "", 800)
            if not payload["context"]:
                payload["context"] = _clean_text(
                    f"CVE ciblee: {data.cve_id}. Severite: {data.severity_label or 'N/A'}.",
                    1200,
                )

    import json
    return HttpResponse(json.dumps(payload), content_type="application/json")


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
                    "Impossible d'envoyer l'email de confirmation. Verifiez EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, EMAIL_PORT et EMAIL_USE_TLS/SSL dans le .env puis redemarrez le service.",
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


def _report_queryset_for_user(user):
    qs = Report.objects.select_related("author")
    if user.role == UserRole.ADMIN:
        return qs
    if user.role == UserRole.PENTESTER:
        return qs.filter(Q(author=user) | Q(is_public=True) | Q(organizations__members=user)).distinct()
    # Viewer
    return qs.filter(Q(is_public=True) | Q(viewers=user) | Q(organizations__members=user)).distinct()


def _ensure_can_view_report(user, report: Report) -> None:
    if user.role == UserRole.ADMIN:
        return
    if report.is_public:
        return
    if user.role == UserRole.PENTESTER and report.author_id == user.id:
        return
    if report.viewers.filter(pk=user.pk).exists():
        return
    if report.organizations.filter(members=user).exists():
        return
    raise PermissionDenied("Acces interdit a ce rapport.")


@login_required
def home(request):
    reports = _report_queryset_for_user(request.user)[:30]
    can_create = request.user.role in {UserRole.ADMIN, UserRole.PENTESTER}
    return render(request, "core/home.html", {"reports": reports, "can_create": can_create})


@login_required
def report_detail(request, report_id: int):
    report = get_object_or_404(Report.objects.select_related("author"), pk=report_id)
    _ensure_can_view_report(request.user, report)
    can_edit = request.user.role == UserRole.ADMIN or report.author_id == request.user.id
    findings = report.findings.prefetch_related("comments__author").all().order_by("display_order", "created_at")
    orgs = Organization.objects.filter(members=request.user).order_by("name")
    return render(
        request,
        "core/report_detail.html",
        {
            "report": report,
            "can_edit": can_edit,
            "findings": findings,
            "comment_form": FindingCommentForm(),
            "available_orgs": orgs,
        },
    )


@login_required
def report_create(request):
    if request.user.role not in {UserRole.ADMIN, UserRole.PENTESTER}:
        raise PermissionDenied("Seuls les admins et pentesters peuvent creer des rapports.")

    if request.method == "POST":
        form = ReportForm(request.POST)
        if form.is_valid():
            report = form.save(commit=False)
            report.author = request.user
            if not report.company_name:
                report.company_name = request.user.company_name or ""
            if not report.company_logo_url and request.user.company_logo:
                report.company_logo_url = request.build_absolute_uri(request.user.company_logo.url)
            report.save()
            form.save_m2m()
            cve_id = (request.POST.get("cve_id") or "").strip()
            upload = request.FILES.get("file")
            cve_created = False
            imported_count = 0

            if cve_id:
                finding = _create_finding_from_cve_id(report, cve_id)
                if finding:
                    cve_created = True
                else:
                    messages.warning(request, "CVE non reconnue: aucun finding ajoute.")

            if upload:
                try:
                    imported_count = _import_findings_from_upload(report, upload)
                except ValueError as exc:
                    messages.error(request, str(exc))

            messages.success(request, "Rapport cree avec succes.")
            if cve_created:
                messages.success(request, "Finding CVE ajoute.")
            if imported_count:
                messages.success(request, f"Import termine: {imported_count} findings ajoutes.")
            return redirect("report_detail", report_id=report.id)
    else:
        initial = {"company_name": request.user.company_name or ""}
        if request.user.company_logo:
            initial["company_logo_url"] = request.build_absolute_uri(request.user.company_logo.url)
        form = ReportForm(initial=initial)

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


@login_required
def report_delete(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    _ensure_can_edit_report(request.user, report)

    if request.method == "POST":
        report.delete()
        messages.success(request, "Rapport supprime avec succes.")
        return redirect("home")

    return render(request, "core/report_delete.html", {"report": report})


@login_required
def report_pdf(request, report_id: int):
    report = get_object_or_404(Report.objects.select_related("author"), pk=report_id)
    _ensure_can_view_report(request.user, report)
    findings = list(report.findings.all().order_by("display_order", "created_at"))
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cvss_bands = [
        {"range": "9.0 - 10.0", "level": "Critique", "class_name": "critical"},
        {"range": "7.0 - 8.9", "level": "Elevee", "class_name": "high"},
        {"range": "4.0 - 6.9", "level": "Moyenne", "class_name": "medium"},
        {"range": "0.1 - 3.9", "level": "Faible", "class_name": "low"},
        {"range": "0.0", "level": "Info / Nul", "class_name": "low"},
    ]
    matrix_rows = ["Critique", "Eleve", "Moyen", "Faible"]
    matrix_cols = ["Quasi certaine", "Elevee", "Moyenne", "Faible"]
    matrix_map = {
        "Critique": "Quasi certaine",
        "Eleve": "Elevee",
        "Moyen": "Moyenne",
        "Faible": "Faible",
    }
    matrix_counts = {row: {col: 0 for col in matrix_cols} for row in matrix_rows}

    def _cvss_level(score: float) -> str:
        if score >= 9.0:
            return "Critique"
        if score >= 7.0:
            return "Eleve"
        if score >= 4.0:
            return "Moyen"
        return "Faible"

    for finding in findings:
        score = float(finding.cvss_score or 0)
        if score >= 9.0:
            severity_counts["critical"] += 1
        elif score >= 7.0:
            severity_counts["high"] += 1
        elif score >= 4.0:
            severity_counts["medium"] += 1
        else:
            severity_counts["low"] += 1
        impact_level = _cvss_level(score)
        probability_level = matrix_map[impact_level]
        matrix_counts[impact_level][probability_level] += 1

    matrix_grid = [
        {
            "impact": row,
            "cells": [
                {"probability": col, "value": matrix_counts[row][col]}
                for col in matrix_cols
            ],
        }
        for row in matrix_rows
    ]
    company_logo_src = report.company_logo_url
    if not company_logo_src and report.author.company_logo:
        company_logo_src = request.build_absolute_uri(report.author.company_logo.url)

    integrity_payload = "|".join(
        [
            report.title,
            report.status,
            str(report.updated_at.timestamp()),
            "|".join(f"{f.title}:{f.cvss_score}" for f in findings),
        ]
    )
    integrity_hash = hashlib.sha256(integrity_payload.encode("utf-8")).hexdigest()
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        integrity_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    watermark_text = report.confidentiality_mark or "CONFIDENTIEL"

    context = {
        "report": report,
        "findings": findings,
        "severity_counts": severity_counts,
        "cvss_bands": cvss_bands,
        "matrix_cols": matrix_cols,
        "matrix_grid": matrix_grid,
        "company_logo_src": company_logo_src,
        "integrity_hash": integrity_hash,
        "pdf_signature": signature,
        "watermark_text": watermark_text,
        "generated_at": timezone.now(),
    }
    try:
        from weasyprint import HTML
    except OSError:
        messages.error(request, "Generation PDF indisponible sur ce systeme (dependances WeasyPrint manquantes).")
        return redirect("report_detail", report_id=report.id)

    html = render(request, "core/report_pdf.html", context).content.decode("utf-8")
    pdf_bytes = HTML(string=html, base_url=request.build_absolute_uri("/")).write_pdf()
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="rapport-pentest-{report.id}.pdf"'
    return response


@login_required
def report_add_finding_from_cve(request, report_id: int):
    report = get_object_or_404(Report.objects.select_related("author"), pk=report_id)
    _ensure_can_view_report(request.user, report)
    _ensure_can_edit_report(request.user, report)

    if request.method != "POST":
        return redirect("report_detail", report_id=report.id)

    cve_id = (request.POST.get("cve_id") or "").strip()
    finding = _create_finding_from_cve_id(report, cve_id)
    if not finding:
        messages.error(request, "CVE invalide.")
        return redirect("report_detail", report_id=report.id)
    messages.success(request, f"Finding créé depuis {finding.cve_id}.")
    return redirect("report_detail", report_id=report.id)


@login_required
def report_import_tool_report(request, report_id: int):
    report = get_object_or_404(Report.objects.select_related("author"), pk=report_id)
    _ensure_can_view_report(request.user, report)
    _ensure_can_edit_report(request.user, report)

    if request.method != "POST":
        return redirect("report_detail", report_id=report.id)

    upload = request.FILES.get("file")
    if not upload:
        messages.error(request, "Aucun fichier envoye.")
        return redirect("report_detail", report_id=report.id)

    try:
        created = _import_findings_from_upload(report, upload)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("report_detail", report_id=report.id)

    if created:
        messages.success(request, f"Import terminé: {created} findings ajoutés.")
    else:
        messages.warning(request, "Aucun finding reconnu dans ce JSON (formats supportés: Bandit JSON, ZAP JSON).")

    return redirect("report_detail", report_id=report.id)


@login_required
@require_POST
def finding_add_comment(request, report_id: int, finding_id: int):
    report = get_object_or_404(Report, pk=report_id)
    _ensure_can_view_report(request.user, report)
    finding = get_object_or_404(Finding, pk=finding_id, report=report)
    form = FindingCommentForm(request.POST)
    if form.is_valid():
        comment = form.save(commit=False)
        comment.finding = finding
        comment.author = request.user
        comment.save()
        _audit(
            request,
            action="create",
            object_type="finding_comment",
            object_id=comment.id,
            metadata={"report_id": report.id, "finding_id": finding.id},
        )
        messages.success(request, "Commentaire ajoute.")
    else:
        messages.error(request, "Commentaire invalide.")
    return redirect("report_detail", report_id=report.id)


@login_required
@require_POST
def report_request_review(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    _ensure_can_edit_report(request.user, report)
    if report.status == "draft":
        report.status = "in_review"
        report.save(update_fields=["status", "updated_at"])
        _audit(
            request,
            action="update",
            object_type="report_workflow",
            object_id=report.id,
            metadata={"from": "draft", "to": "in_review"},
        )
        messages.success(request, "Rapport passe en revue.")
    else:
        messages.warning(request, "Transition non autorisee depuis ce statut.")
    return redirect("report_detail", report_id=report.id)


@login_required
@require_POST
def report_approve(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    if request.user.role != UserRole.ADMIN:
        raise PermissionDenied("Seul un admin peut valider un rapport.")
    if report.status != "in_review":
        messages.warning(request, "Le rapport doit etre en revue.")
        return redirect("report_detail", report_id=report.id)
    report.status = "final"
    report.approved_by = request.user
    report.approved_at = timezone.now()
    report.save(update_fields=["status", "approved_by", "approved_at", "updated_at"])
    _audit(
        request,
        action="update",
        object_type="report_workflow",
        object_id=report.id,
        metadata={"from": "in_review", "to": "final"},
    )
    if report.author.email:
        send_mail(
            subject=f"Rapport valide: {report.title}",
            message=(
                f"Bonjour {report.author.username},\n\n"
                f"Votre rapport '{report.title}' vient d'etre valide par {request.user.username}.\n"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[report.author.email],
            fail_silently=True,
        )
    messages.success(request, "Rapport valide.")
    return redirect("report_detail", report_id=report.id)


@login_required
@require_POST
def report_generate_share_link(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    _ensure_can_edit_report(request.user, report)
    days = int((request.POST.get("days") or "7").strip() or "7")
    report.public_share_token = secrets.token_urlsafe(24)
    report.public_share_expires_at = timezone.now() + timedelta(days=max(1, min(days, 90)))
    report.is_public = True
    report.save(update_fields=["public_share_token", "public_share_expires_at", "is_public", "updated_at"])
    _audit(
        request,
        action="update",
        object_type="report_share_link",
        object_id=report.id,
        metadata={"expires_at": report.public_share_expires_at.isoformat()},
    )
    messages.success(request, "Lien public securise genere.")
    return redirect("report_detail", report_id=report.id)


def report_public_share(request, token: str):
    report = get_object_or_404(Report, public_share_token=token)
    if not report.is_public:
        return HttpResponse("Lien non actif.", status=403)
    if report.public_share_expires_at and timezone.now() > report.public_share_expires_at:
        return HttpResponse("Lien expire.", status=410)
    findings = report.findings.all().order_by("display_order", "created_at")
    return render(request, "core/report_public_share.html", {"report": report, "findings": findings})


@login_required
def organization_list(request):
    orgs = Organization.objects.filter(members=request.user).order_by("name")
    form = OrganizationCreateForm()
    return render(request, "core/organization_list.html", {"organizations": orgs, "form": form})


@login_required
@require_POST
def organization_create(request):
    form = OrganizationCreateForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Nom d'organisation invalide.")
        return redirect("organization_list")
    org = form.save(commit=False)
    org.owner = request.user
    org.save()
    OrganizationMembership.objects.create(organization=org, user=request.user, role=OrganizationRole.OWNER)
    _audit(
        request,
        action="create",
        object_type="organization",
        object_id=org.id,
        metadata={"name": org.name},
    )
    messages.success(request, "Organisation creee.")
    return redirect("organization_detail", org_id=org.id)


@login_required
def organization_detail(request, org_id: int):
    org = get_object_or_404(Organization, pk=org_id)
    if not org.members.filter(pk=request.user.pk).exists():
        raise PermissionDenied("Acces interdit.")
    members = org.memberships.select_related("user").all()
    shares = org.report_shares.select_related("report").all()
    return render(
        request,
        "core/organization_detail.html",
        {"organization": org, "memberships": members, "shares": shares, "member_form": OrganizationAddMemberForm()},
    )


@login_required
@require_POST
def organization_add_member(request, org_id: int):
    org = get_object_or_404(Organization, pk=org_id)
    if not _is_org_admin_or_owner(org, request.user):
        raise PermissionDenied("Seul un owner/admin peut ajouter des membres.")
    form = OrganizationAddMemberForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Username invalide.")
        return redirect("organization_detail", org_id=org.id)
    username = form.cleaned_data["username"]
    role = form.cleaned_data["role"]
    user = User.objects.filter(username=username).first()
    if not user:
        messages.error(request, "Utilisateur introuvable.")
        return redirect("organization_detail", org_id=org.id)
    created = False
    membership, created = OrganizationMembership.objects.get_or_create(
        organization=org,
        user=user,
        defaults={"role": role},
    )
    if not created:
        membership.role = role
        membership.save(update_fields=["role"])
    _audit(
        request,
        action="update" if not created else "create",
        object_type="organization_membership",
        object_id=membership.id,
        metadata={"organization_id": org.id, "username": username, "role": role},
    )
    messages.success(request, f"{username} ajoute a l'organisation.")
    return redirect("organization_detail", org_id=org.id)


@login_required
@require_POST
def organization_update_member_role(request, org_id: int, user_id: int):
    org = get_object_or_404(Organization, pk=org_id)
    if not _is_org_admin_or_owner(org, request.user):
        raise PermissionDenied("Seul un owner/admin peut modifier un role.")
    target = get_object_or_404(OrganizationMembership, organization=org, user_id=user_id)
    role = (request.POST.get("role") or "").strip()
    if role not in {OrganizationRole.OWNER, OrganizationRole.ADMIN, OrganizationRole.MEMBER}:
        messages.error(request, "Role invalide.")
        return redirect("organization_detail", org_id=org.id)
    if target.role == OrganizationRole.OWNER and role != OrganizationRole.OWNER:
        messages.error(request, "Le role owner ne peut pas etre retrograde ici.")
        return redirect("organization_detail", org_id=org.id)
    if request.user.id != org.owner_id and role == OrganizationRole.OWNER:
        messages.error(request, "Seul le owner actuel peut transferer ownership.")
        return redirect("organization_detail", org_id=org.id)
    if role == OrganizationRole.OWNER:
        org.owner = target.user
        org.save(update_fields=["owner"])
        OrganizationMembership.objects.filter(organization=org, user=request.user).update(role=OrganizationRole.ADMIN)
    target.role = role
    target.save(update_fields=["role"])
    _audit(
        request,
        action="privilege_change",
        object_type="organization_membership",
        object_id=target.id,
        metadata={"organization_id": org.id, "target_user_id": user_id, "new_role": role},
    )
    messages.success(request, "Role mis a jour.")
    return redirect("organization_detail", org_id=org.id)


@login_required
@require_POST
def organization_remove_member(request, org_id: int, user_id: int):
    org = get_object_or_404(Organization, pk=org_id)
    if not _is_org_admin_or_owner(org, request.user):
        raise PermissionDenied("Seul un owner/admin peut retirer un membre.")
    target = get_object_or_404(OrganizationMembership, organization=org, user_id=user_id)
    if target.role == OrganizationRole.OWNER:
        messages.error(request, "Impossible de retirer le owner.")
        return redirect("organization_detail", org_id=org.id)
    _audit(
        request,
        action="delete",
        object_type="organization_membership",
        object_id=target.id,
        metadata={"organization_id": org.id, "target_user_id": user_id},
    )
    target.delete()
    messages.success(request, "Membre retire.")
    return redirect("organization_detail", org_id=org.id)


@login_required
@require_POST
def report_share_with_org(request, report_id: int):
    report = get_object_or_404(Report, pk=report_id)
    _ensure_can_edit_report(request.user, report)
    org_id = int((request.POST.get("org_id") or "0"))
    org = get_object_or_404(Organization, pk=org_id)
    if not org.members.filter(pk=request.user.pk).exists():
        raise PermissionDenied("Vous n'etes pas membre de cette organisation.")
    share, _created = ReportOrganizationShare.objects.get_or_create(
        report=report,
        organization=org,
        defaults={"created_by": request.user},
    )
    _audit(
        request,
        action="update",
        object_type="report_org_share",
        object_id=share.id,
        metadata={"report_id": report.id, "organization_id": org.id},
    )
    recipient_emails = list(
        org.members.exclude(id=request.user.id).exclude(email="").values_list("email", flat=True)
    )
    if recipient_emails:
        send_mail(
            subject=f"Rapport partage: {report.title}",
            message=(
                f"Le rapport '{report.title}' a ete partage avec l'organisation '{org.name}' "
                f"par {request.user.username}."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_emails,
            fail_silently=True,
        )
    messages.success(request, "Rapport partage a l'organisation.")
    return redirect("report_detail", report_id=report.id)


@login_required
def cve_lookup(request):
    cve_id = (request.GET.get("cve") or "").strip()
    data = fetch_cve_data(cve_id)
    if not data:
        return HttpResponse('{"error":"invalid"}', content_type="application/json", status=400)
    payload = {
        "cve_id": data.cve_id,
        "title": data.title,
        "description": data.description,
        "cvss_score": data.cvss_score,
        "severity": data.severity_label,
        "references": data.references,
        "sources": data.sources,
    }
    import json

    return HttpResponse(json.dumps(payload), content_type="application/json")


@login_required
def kb_list(request):
    entries = KnowledgeBase.objects.all()
    return render(request, "core/kb_list.html", {"entries": entries})


@login_required
def kb_detail(request, entry_id: int):
    entry = get_object_or_404(KnowledgeBase, pk=entry_id)
    return render(request, "core/kb_detail.html", {"entry": entry})


@login_required
def kb_create(request):
    if request.user.role != UserRole.ADMIN:
        raise PermissionDenied("Seuls les admins peuvent gerer la base de connaissance.")

    if request.method == "POST":
        form = KnowledgeBaseForm(request.POST)
        if form.is_valid():
            entry = form.save()
            messages.success(request, "Entree KB creee.")
            return redirect("kb_detail", entry_id=entry.id)
    else:
        form = KnowledgeBaseForm()

    return render(request, "core/kb_form.html", {"form": form, "is_edit": False})


@login_required
def kb_edit(request, entry_id: int):
    if request.user.role != UserRole.ADMIN:
        raise PermissionDenied("Seuls les admins peuvent gerer la base de connaissance.")

    entry = get_object_or_404(KnowledgeBase, pk=entry_id)
    if request.method == "POST":
        form = KnowledgeBaseForm(request.POST, instance=entry)
        if form.is_valid():
            form.save()
            messages.success(request, "Entree KB mise a jour.")
            return redirect("kb_detail", entry_id=entry.id)
    else:
        form = KnowledgeBaseForm(instance=entry)

    return render(request, "core/kb_form.html", {"form": form, "entry": entry, "is_edit": True})


@login_required
def kb_delete(request, entry_id: int):
    if request.user.role != UserRole.ADMIN:
        raise PermissionDenied("Seuls les admins peuvent gerer la base de connaissance.")

    entry = get_object_or_404(KnowledgeBase, pk=entry_id)
    if request.method == "POST":
        entry.delete()
        messages.success(request, "Entree KB supprimee.")
        return redirect("kb_list")

    return render(request, "core/kb_delete.html", {"entry": entry})


@login_required
def resources(request):
    return render(request, "core/resources.html")


@login_required
def friends(request):
    if request.method == "POST":
        form = FriendSearchForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Veuillez saisir un ID ami valide.")
            return redirect("friends")

        profile_id = form.cleaned_data["profile_id"]
        target = User.objects.filter(profile_id__iexact=profile_id).exclude(pk=request.user.pk).first()
        if not target:
            messages.error(request, "Aucun utilisateur ne correspond a cet ID.")
            return redirect("friends")

        existing = FriendRequest.objects.filter(
            Q(from_user=request.user, to_user=target) | Q(from_user=target, to_user=request.user)
        ).order_by("-created_at").first()

        if existing and existing.status == FriendRequestStatus.ACCEPTED:
            messages.info(request, f"Vous etes deja ami avec {target.username}.")
            return redirect("friends")

        if existing and existing.status == FriendRequestStatus.PENDING:
            if existing.to_user_id == request.user.id:
                existing.status = FriendRequestStatus.ACCEPTED
                existing.responded_at = timezone.now()
                existing.save(update_fields=["status", "responded_at"])
                _audit(
                    request,
                    action="update",
                    object_type="friend_request",
                    object_id=existing.id,
                    metadata={"status": FriendRequestStatus.ACCEPTED, "friend_user_id": target.id},
                )
                messages.success(request, f"Vous etes maintenant ami avec {target.username}.")
            else:
                messages.info(request, "Une demande d'ami est deja en attente.")
            return redirect("friends")

        if existing and existing.status == FriendRequestStatus.DECLINED:
            existing.from_user = request.user
            existing.to_user = target
            existing.status = FriendRequestStatus.PENDING
            existing.responded_at = None
            existing.save(update_fields=["from_user", "to_user", "status", "responded_at"])
            request_obj = existing
        else:
            request_obj = FriendRequest.objects.create(from_user=request.user, to_user=target)

        _audit(
            request,
            action="create",
            object_type="friend_request",
            object_id=request_obj.id,
            metadata={"to_user_id": target.id, "profile_id": target.profile_id},
        )
        messages.success(request, f"Demande d'ami envoyee a {target.username}.")
        return redirect("friends")

    context = {"search_form": FriendSearchForm(), **_friend_context(request.user)}
    return render(request, "core/friends.html", context)


@login_required
@require_POST
def friend_request_accept(request, request_id: int):
    friend_request = get_object_or_404(
        FriendRequest.objects.select_related("from_user"),
        pk=request_id,
        to_user=request.user,
        status=FriendRequestStatus.PENDING,
    )
    friend_request.status = FriendRequestStatus.ACCEPTED
    friend_request.responded_at = timezone.now()
    friend_request.save(update_fields=["status", "responded_at"])
    _audit(
        request,
        action="update",
        object_type="friend_request",
        object_id=friend_request.id,
        metadata={"status": FriendRequestStatus.ACCEPTED, "from_user_id": friend_request.from_user_id},
    )
    messages.success(request, f"{friend_request.from_user.username} a ete ajoute a vos amis.")
    return redirect("friends")


@login_required
@require_POST
def friend_request_decline(request, request_id: int):
    friend_request = get_object_or_404(
        FriendRequest.objects.select_related("from_user"),
        pk=request_id,
        to_user=request.user,
        status=FriendRequestStatus.PENDING,
    )
    friend_request.status = FriendRequestStatus.DECLINED
    friend_request.responded_at = timezone.now()
    friend_request.save(update_fields=["status", "responded_at"])
    _audit(
        request,
        action="update",
        object_type="friend_request",
        object_id=friend_request.id,
        metadata={"status": FriendRequestStatus.DECLINED, "from_user_id": friend_request.from_user_id},
    )
    messages.info(request, "Demande d'ami refusee.")
    return redirect("friends")


@login_required
@require_POST
def friend_request_cancel(request, request_id: int):
    friend_request = get_object_or_404(
        FriendRequest,
        pk=request_id,
        from_user=request.user,
        status=FriendRequestStatus.PENDING,
    )
    _audit(
        request,
        action="delete",
        object_type="friend_request",
        object_id=friend_request.id,
        metadata={"to_user_id": friend_request.to_user_id},
    )
    friend_request.delete()
    messages.info(request, "Demande d'ami annulee.")
    return redirect("friends")


@login_required
def account_settings(request):
    if request.method == "POST":
        if request.POST.get("action") == "send_reset_link":
            reset_form = CurrentUserPasswordResetForm({"email": request.user.email})
            if reset_form.is_valid():
                try:
                    reset_form.save(
                        request=request,
                        use_https=request.is_secure(),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        email_template_name="registration/password_reset_email.html",
                        subject_template_name="registration/password_reset_subject.txt",
                    )
                except Exception:
                    messages.error(
                        request,
                        "Impossible d'envoyer l'email de reinitialisation. Verifiez EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, EMAIL_PORT et EMAIL_USE_TLS/SSL dans le .env puis redemarrez le service.",
                    )
                else:
                    messages.success(request, "Email de reinitialisation envoye.")
            else:
                messages.error(request, "Impossible d'envoyer l'email de reinitialisation.")
            return redirect("account_settings")

        form = AccountSettingsForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profil mis a jour.")
            return redirect("account_settings")
    else:
        form = AccountSettingsForm(instance=request.user)

    return render(request, "core/account_settings.html", {"form": form})


@login_required
def mfa_setup(request):
    if request.user.role not in {UserRole.PENTESTER, UserRole.ADMIN}:
        raise PermissionDenied("Acces interdit.")

    request.user.mfa_required = True
    request.user.save(update_fields=["mfa_required"])

    enrollment = build_totp_enrollment(request.user, issuer_name="VulnReport")
    device = get_or_create_totp_device(request.user)

    if request.method == "POST":
        code = (request.POST.get("code") or "").strip().replace(" ", "")
        from pyotp import TOTP
        from .mfa import _device_secret
        if code and TOTP(_device_secret(device), interval=30, digits=6).verify(code, valid_window=1):
            device.is_confirmed = True
            device.save(update_fields=["is_confirmed"])
            request.user.mfa_enrolled = True
            request.user.save(update_fields=["mfa_enrolled"])
            request.session["mfa_ok"] = True
            messages.success(request, "2FA activée. Connexion sécurisée.")
            return redirect(request.session.pop("post_mfa_redirect", "home"))
        messages.error(request, "Code invalide. Réessaie.")

    return render(
        request,
        "core/mfa_setup.html",
        {"enrollment": enrollment, "device": device},
    )


@login_required
def mfa_verify(request):
    if request.user.role not in {UserRole.PENTESTER, UserRole.ADMIN}:
        raise PermissionDenied("Acces interdit.")

    if not request.user.mfa_enrolled or not TopDevice.objects.filter(user=request.user, is_confirmed=True).exists():
        return redirect("mfa_setup")

    if request.method == "POST":
        code = (request.POST.get("code") or "").strip().replace(" ", "")
        if verify_totp_code(request.user, code):
            request.session["mfa_ok"] = True
            messages.success(request, "2FA validée.")
            return redirect(request.session.pop("post_mfa_redirect", "home"))
        messages.error(request, "Code invalide.")

    return render(request, "core/mfa_verify.html")


@login_required
def mfa_webauthn_sim(request):
    raise PermissionDenied("Mode simulation MFA désactivé.")
