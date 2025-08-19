from django import template
from Cripto1.models import UserProfile

register = template.Library()

@register.filter
def has_role(user_profile, role_name):
    """Verifica se un profilo utente ha un determinato ruolo"""
    if not hasattr(user_profile, 'get_roles'):
        return False
    return user_profile.has_role(role_name)