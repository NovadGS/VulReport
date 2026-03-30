from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import PasswordResetForm

from .models import (
    FindingComment,
    KnowledgeBase,
    Organization,
    OrganizationRole,
    Report,
    User,
    UserRole,
)


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
    class Meta:
        model = Report
        fields = (
            "title",
            "context",
            "executive_summary",
            "company_name",
            "company_logo_url",
            "custom_header",
            "status",
            "is_public",
        )
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control"}),
            "context": forms.Textarea(attrs={"rows": 4, "class": "form-control"}),
            "executive_summary": forms.Textarea(attrs={"rows": 3, "class": "form-control"}),
            "company_name": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "Ex: ACME Security"}
            ),
            "company_logo_url": forms.URLInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "https://votre-entreprise.tld/logo.png",
                }
            ),
            "custom_header": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "Ex: Rapport de pentest confidentiel"}
            ),
            "status": forms.Select(attrs={"class": "form-select"}),
            "is_public": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # CSS bootstrap (pour garder l'UI cohérente)
        self.fields["title"].widget.attrs["class"] = "form-control"
        self.fields["context"].widget.attrs["class"] = "form-control"
        self.fields["executive_summary"].widget.attrs["class"] = "form-control"
        self.fields["company_name"].widget.attrs["class"] = "form-control"
        self.fields["company_logo_url"].widget.attrs["class"] = "form-control"
        self.fields["custom_header"].widget.attrs["class"] = "form-control"
        self.fields["status"].widget.attrs["class"] = "form-select"

        if "is_public" in self.fields:
            self.fields["is_public"].help_text = "Si coché, le rapport est visible par tous les utilisateurs."
        self.fields["company_logo_url"].help_text = (
            "URL publique du logo de votre entreprise (affiché dans le PDF)."
        )

    def save(self, commit=True):
        report = super().save(commit=commit)
        if commit:
            self.save_m2m()
        return report

    def save_m2m(self):
        return


class KnowledgeBaseForm(forms.ModelForm):
    class Meta:
        model = KnowledgeBase
        fields = ("name", "category", "default_severity", "description", "recommendation", "references")
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control"}),
            "category": forms.Select(attrs={"class": "form-select"}),
            "default_severity": forms.Select(attrs={"class": "form-select"}),
            "description": forms.Textarea(attrs={"rows": 4, "class": "form-control"}),
            "recommendation": forms.Textarea(attrs={"rows": 4, "class": "form-control"}),
            "references": forms.Textarea(attrs={"rows": 3, "class": "form-control"}),
        }


class AccountSettingsForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "company_name", "profile_photo", "company_logo")
        widgets = {
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "company_name": forms.TextInput(attrs={"class": "form-control"}),
            "profile_photo": forms.ClearableFileInput(attrs={"class": "form-control"}),
            "company_logo": forms.ClearableFileInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].required = True

    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip().lower()
        exists = User.objects.filter(email=email).exclude(pk=self.instance.pk).exists()
        if exists:
            raise forms.ValidationError("Cet email est deja utilise par un autre compte.")
        return email


class CurrentUserPasswordResetForm(PasswordResetForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].widget.attrs["class"] = "form-control"


class FindingCommentForm(forms.ModelForm):
    class Meta:
        model = FindingComment
        fields = ("body",)
        widgets = {
            "body": forms.Textarea(attrs={"rows": 2, "class": "form-control", "placeholder": "Commentaire interne"}),
        }


class OrganizationCreateForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ("name",)
        widgets = {"name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom de l'organisation"})}


class OrganizationAddMemberForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "username du membre"}),
    )
    role = forms.ChoiceField(
        choices=OrganizationRole.choices,
        initial=OrganizationRole.MEMBER,
        widget=forms.Select(attrs={"class": "form-select"}),
    )
