from django.contrib.auth import views as auth_views

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

