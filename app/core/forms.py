from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import Report, User, UserRole


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
        fields = ("title", "client", "report_date", "status", "viewers")
        widgets = {
            "report_date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "viewers": forms.SelectMultiple(attrs={"size": 8, "class": "form-select"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ("title", "client"):
            self.fields[field_name].widget.attrs["class"] = "form-control"
        self.fields["status"].widget.attrs["class"] = "form-select"
