from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from functools import wraps  # Aggiunta questa importazione mancante
from .models import UserProfile, AuditLog


def permission_required(permission_codename, redirect_url=None):
    """
    Decoratore per verificare se un utente ha un determinato permesso.
    
    Args:
        permission_codename (str): Il codice del permesso richiesto
        redirect_url (str): URL di redirect se l'utente non ha il permesso
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('Cripto1:login')
            
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                
                if not user_profile.is_active:
                    messages.error(request, 'Il tuo account è stato disattivato.')
                    return redirect('Cripto1:login')
                
                if user_profile.is_locked():
                    messages.error(request, 'Il tuo account è temporaneamente bloccato.')
                    return redirect('Cripto1:login')
                
                # Verifica il permesso
                if user_profile.has_permission(permission_codename):
                    return view_func(request, *args, **kwargs)
                else:
                    # Log dell'accesso negato
                    AuditLog.log_action(
                        user=request.user,
                        action_type='SECURITY_EVENT',
                        description=f'Tentativo di accesso negato alla vista {view_func.__name__} - Permesso richiesto: {permission_codename}',
                        severity='HIGH',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        error_message=f'Permesso mancante: {permission_codename}'
                    )
                    
                    if redirect_url:
                        messages.error(request, f'Non hai i permessi necessari per accedere a questa funzionalità.')
                        return redirect(redirect_url)
                    else:
                        return HttpResponseForbidden('Accesso negato: permessi insufficienti.')
                        
            except UserProfile.DoesNotExist:
                messages.error(request, 'Profilo utente non trovato.')
                return redirect('Cripto1:login')
                
        return _wrapped_view
    return decorator


def role_required(role_name, redirect_url=None):
    """
    Decoratore per verificare se un utente ha un determinato ruolo.
    
    Args:
        role_name (str): Il nome del ruolo richiesto
        redirect_url (str): URL di redirect se l'utente non ha il ruolo
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('Cripto1:login')
            
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                if not user_profile.is_active:
                    messages.error(request, 'Il tuo account è stato disattivato.')
                    return redirect('Cripto1:login')
                
                if user_profile.is_locked():
                    messages.error(request, 'Il tuo account è temporaneamente bloccato.')
                    return redirect('Cripto1:login')
                
                if user_profile.has_role(role_name):
                    return view_func(request, *args, **kwargs)
                else:
                    # Log dell'accesso negato
                    AuditLog.log_action(
                        user=request.user,
                        action_type='SECURITY_EVENT',
                        description=f'Tentativo di accesso negato alla vista {view_func.__name__} - Ruolo richiesto: {role_name}',
                        severity='HIGH',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        error_message=f'Ruolo mancante: {role_name}'
                    )
                    
                    if redirect_url:
                        messages.error(request, f'Non hai il ruolo necessario per accedere a questa funzionalità.')
                        return redirect(redirect_url)
                    else:
                        return HttpResponseForbidden('Accesso negato: ruolo insufficiente.')
                        
            except UserProfile.DoesNotExist:
                messages.error(request, 'Profilo utente non trovato.')
                return redirect('Cripto1:login')
                
        return _wrapped_view
    return decorator


def admin_required(redirect_url=None):
    """
    Decoratore per verificare se un utente è amministratore (staff o superuser).
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('Cripto1:login')
            
            if not (request.user.is_staff or request.user.is_superuser):
                # Log dell'accesso negato
                AuditLog.log_action(
                    user=request.user,
                    action_type='SECURITY_EVENT',
                    description=f'Tentativo di accesso negato alla vista amministrativa {view_func.__name__}',
                    severity='HIGH',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message='Privilegi amministrativi richiesti'
                )
                
                if redirect_url:
                    messages.error(request, 'Accesso negato: privilegi amministrativi richiesti.')
                    return redirect(redirect_url)
                else:
                    return HttpResponseForbidden('Accesso negato: privilegi amministrativi richiesti.')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def active_user_required(redirect_url=None):
    """
    Decoratore per verificare se un utente è attivo e non bloccato.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('Cripto1:login')
            
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                
                if not user_profile.is_active:
                    messages.error(request, 'Il tuo account è stato disattivato.')
                    return redirect('Cripto1:login')
                
                if user_profile.is_locked():
                    messages.error(request, 'Il tuo account è temporaneamente bloccato.')
                    return redirect('Cripto1:login')
                
                return view_func(request, *args, **kwargs)
                
            except UserProfile.DoesNotExist:
                messages.error(request, 'Profilo utente non trovato.')
                return redirect('Cripto1:login')
                
        return _wrapped_view
    return decorator


def external_forbidden(view_func):
    """Decoratore per impedire l'accesso agli utenti con ruolo 'external'"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('Cripto1:login')
        
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            if user_profile.has_role('external'):
                messages.error(request, 'Gli utenti con ruolo "external" non possono accedere a questa funzionalità')
                return redirect('Cripto1:dashboard')
            return view_func(request, *args, **kwargs)
        except UserProfile.DoesNotExist:
            messages.error(request, 'Profilo utente non trovato.')
            return redirect('Cripto1:login')
    return _wrapped_view


def user_manager_forbidden(view_func):
    """Decoratore per impedire l'accesso agli utenti con ruolo 'User Manager'"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('Cripto1:login')
        
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            
            # Verifica se l'utente ha il ruolo User Manager
            if user_profile.has_role('User Manager'):
                messages.error(request, 'Gli utenti con ruolo "User Manager" non possono accedere a questa funzionalità')
                return redirect('Cripto1:dashboard')
                
            return view_func(request, *args, **kwargs)
        except UserProfile.DoesNotExist:
            messages.error(request, 'Profilo utente non trovato.')
            return redirect('Cripto1:login')
    return _wrapped_view