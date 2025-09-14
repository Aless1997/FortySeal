from django import template
from Cripto1.models import UserProfile

register = template.Library()

@register.filter
def has_role(user_profile, role_name):
    """Verifica se un profilo utente ha un determinato ruolo"""
    try:
        # Verifica che user_profile sia un'istanza di UserProfile
        if not isinstance(user_profile, UserProfile):
            return False
        
        # Verifica che il metodo has_role esista
        if not hasattr(user_profile, 'has_role'):
            return False
            
        # Rimosso il controllo is_active che causava il problema
        return user_profile.has_role(role_name)
    except Exception as e:
        # Log dell'errore per debug
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Errore nel template tag has_role: {e}")
        return False