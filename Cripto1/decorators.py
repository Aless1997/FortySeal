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


def organization_admin_required(redirect_url=None):
    """
    Decoratore per verificare se un utente è amministratore della propria organizzazione.
    L'utente deve avere il ruolo 'Organization Admin' o essere superuser.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('Cripto1:login')
            
            # I superuser hanno sempre accesso
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            try:
                user_profile = UserProfile.objects.get(user=request.user)
                
                if not user_profile.is_active:
                    messages.error(request, 'Il tuo account è stato disattivato.')
                    return redirect('Cripto1:login')
                
                if user_profile.is_locked():
                    messages.error(request, 'Il tuo account è temporaneamente bloccato.')
                    return redirect('Cripto1:login')
                
                # Verifica se l'utente ha il ruolo di Organization Admin
                if user_profile.has_role('Organization Admin'):
                    return view_func(request, *args, **kwargs)
                else:
                    # Log dell'accesso negato
                    AuditLog.log_action(
                        user=request.user,
                        action_type='SECURITY_EVENT',
                        description=f'Tentativo di accesso negato alla vista amministrativa organizzazione {view_func.__name__}',
                        severity='HIGH',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        error_message='Privilegi di amministratore organizzazione richiesti'
                    )
                    
                    if redirect_url:
                        messages.error(request, 'Accesso negato: privilegi di amministratore organizzazione richiesti.')
                        return redirect(redirect_url)
                    else:
                        return HttpResponseForbidden('Accesso negato: privilegi di amministratore organizzazione richiesti.')
                        
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


def sharing_permission_required(permission_level):
    """Decorator per verificare i permessi di condivisione"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            share_id = kwargs.get('share_id')
            if not share_id:
                raise PermissionDenied("ID condivisione mancante")
            
            try:
                shared_doc = SharedDocument.objects.get(
                    share_id=share_id,
                    shared_with=request.user,
                    is_active=True
                )
                
                if shared_doc.is_expired():
                    raise PermissionDenied("Condivisione scaduta")
                
                # Verifica il livello di permesso richiesto
                if permission_level == 'read' and shared_doc.permission_level in ['read', 'write', 'download', 'full']:
                    pass
                elif permission_level == 'write' and shared_doc.can_write():
                    pass
                elif permission_level == 'download' and shared_doc.can_download():
                    pass
                else:
                    raise PermissionDenied("Permessi insufficienti")
                
                # Registra l'accesso
                shared_doc.record_access()
                
                # Aggiungi il documento condiviso al request
                request.shared_document = shared_doc
                
            except SharedDocument.DoesNotExist:
                raise PermissionDenied("Condivisione non trovata o non autorizzata")
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def can_share_document(user, document_type, document_id):
    """Verifica se un utente può condividere un documento"""
    if document_type == 'transaction':
        try:
            transaction = Transaction.objects.get(id=document_id)
            return transaction.sender == user or transaction.receiver == user
        except Transaction.DoesNotExist:
            return False
    elif document_type == 'personal_document':
        try:
            doc = PersonalDocument.objects.get(id=document_id, user=user)
            return True
        except PersonalDocument.DoesNotExist:
            return False
    elif document_type == 'created_document':
        try:
            doc = CreatedDocument.objects.get(id=document_id, user=user)
            return True
        except CreatedDocument.DoesNotExist:
            return False
    return False