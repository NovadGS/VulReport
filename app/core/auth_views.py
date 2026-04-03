from django.contrib.auth import views as auth_views
from django.contrib import messages

from .models import UserRole


class LoginView(auth_views.LoginView):
    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.request.user
        # Require MFA per role (enforced again by middleware)
        if getattr(user, "role", None) == UserRole.PENTESTER:
            self.request.session["mfa_ok"] = False
        if getattr(user, "role", None) == UserRole.ADMIN:
            self.request.session["mfa_ok"] = False
        return response

    def form_invalid(self, form):
        """AUTH-04: Display generic error message on authentication failure."""
        messages.error(self.request, "Identifiant ou mot de passe invalide.")
        return super().form_invalid(form)

