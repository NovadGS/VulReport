from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import Report, ReportViewer, User, UserRole


class ViewerRegistrationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = UserRole.VIEWER
        user.is_staff = False
        user.is_active = False
        if commit:
            user.save()
        return user

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True
        for field in self.fields.values():
            field.widget.attrs["class"] = "form-control"

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Un compte existe deja avec cet email.")
        return email


class ReportForm(forms.ModelForm):
    viewers = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 8, "class": "form-select"}),
    )

    class Meta:
        model = Report
        fields = ("title", "context", "executive_summary", "status")
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control"}),
            "context": forms.Textarea(attrs={"rows": 4, "class": "form-control"}),
            "executive_summary": forms.Textarea(attrs={"rows": 3, "class": "form-control"}),
            "status": forms.Select(attrs={"class": "form-select"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # CSS bootstrap (pour garder l'UI cohérente)
        self.fields["title"].widget.attrs["class"] = "form-control"
        self.fields["context"].widget.attrs["class"] = "form-control"
        self.fields["executive_summary"].widget.attrs["class"] = "form-control"
        self.fields["status"].widget.attrs["class"] = "form-select"

        if "viewers" in self.fields:
            self.fields["viewers"].widget.attrs["class"] = "form-select"

    def save(self, commit=True):
        report = super().save(commit=commit)
        if commit:
            self.save_m2m()
        return report

    def save_m2m(self):
        """
        Persistance des viewers via la table through `report_viewers`
        (schéma cible: report_viewers(report_id, viewer_id, assigned_at)).
        """
        report = getattr(self, "instance", None)
        if not report or not report.pk:
            return

        selected_viewers = self.cleaned_data.get("viewers") or []

        ReportViewer.objects.filter(report=report).delete()
        if not selected_viewers:
            return

        ReportViewer.objects.bulk_create(
            [ReportViewer(report=report, viewer=user) for user in selected_viewers]
        )
