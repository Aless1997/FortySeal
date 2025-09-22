from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from datetime import timedelta
import json
from datetime import datetime

from .models import UserProfile, Role, Permission, UserRole, AuditLog, Organization, Transaction, Block
from .decorators import organization_admin_required
from .forms import UserProfileEditForm, OrganizationFileRetentionForm


@organization_admin_required()
def org_admin_dashboard(request):
    """Dashboard amministrativa per l'admin dell'organizzazione"""
    user_profile = UserProfile.objects.get(user=request.user)
    organization = user_profile.organization
    
    if not organization:
        messages.error(request, 'Non sei associato a nessuna organizzazione.')
        return redirect('Cripto1:dashboard')
    
    # Statistiche organizzazione
    total_users = UserProfile.objects.filter(organization=organization).count()
    active_users = UserProfile.objects.filter(organization=organization, is_active=True).count()
    total_transactions = Transaction.objects.filter(organization=organization).count()
    total_blocks = Block.objects.filter(organization=organization).count()
    
    # Statistiche per ruolo nella propria organizzazione
    role_stats = {}
    for role in Role.objects.filter(is_active=True):
        count = UserRole.objects.filter(
            role=role, 
            is_active=True,
            user__userprofile__organization=organization
        ).exclude(expires_at__lt=timezone.now()).count()
        if count > 0:
            role_stats[role.name] = count
    
    # Utenti recenti dell'organizzazione
    recent_users = UserProfile.objects.filter(
        organization=organization
    ).select_related('user').order_by('-created_at')[:10]
    
    # Attività recenti dell'organizzazione
    recent_activities = AuditLog.objects.filter(
        user__userprofile__organization=organization,
        action_type__in=['USER_MANAGEMENT', 'ROLE_ASSIGNMENT', 'USER_ACTIVATION', 'USER_DEACTIVATION']
    ).order_by('-timestamp')[:10]
    
    # Transazioni recenti dell'organizzazione
    recent_transactions = Transaction.objects.filter(
        organization=organization
    ).order_by('-timestamp')[:10]
    
    context = {
        'organization': organization,
        'total_users': total_users,
        'active_users': active_users,
        'total_transactions': total_transactions,
        'total_blocks': total_blocks,
        'role_stats': role_stats,
        'recent_users': recent_users,
        'recent_activities': recent_activities,
        'recent_transactions': recent_transactions,
    }
    
    return render(request, 'Cripto1/admin_dashboard.html', context)


@organization_admin_required()
def org_user_management(request):
    user_profile = request.user.userprofile
    organization = user_profile.organization
    
    if not organization:
        messages.error(request, 'Non sei associato a nessuna organizzazione.')
        return redirect('Cripto1:dashboard')
    
    # DEBUG: Aggiungi queste righe per il debug
    print(f"DEBUG ORG ADMIN: Admin user: {request.user.username}")
    print(f"DEBUG ORG ADMIN: Organization ID: {organization.id}")
    print(f"DEBUG ORG ADMIN: Organization name: {organization.name}")
    
    # Filtri
    search_query = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    status_filter = request.GET.get('status', '')
    
    # Query base per utenti dell'organizzazione
    users = UserProfile.objects.filter(organization=organization).select_related('user')
    
    # DEBUG: Verifica quanti utenti ci sono
    print(f"DEBUG ORG ADMIN: Total users in organization: {users.count()}")
    print(f"DEBUG ORG ADMIN: Users found:")
    for user in users:
        print(f"  - User: {user.user.username} (ID: {user.user.id}), Organization: {user.organization.name}")
    
    print(f"DEBUG ORG ADMIN: All users in DB with organization:")
    all_users_with_org = UserProfile.objects.filter(organization__isnull=False).select_related('user', 'organization')
    for user in all_users_with_org:
        print(f"  - User: {user.user.username}, Organization: {user.organization.name} (ID: {user.organization.id})")
    
    for user in users:
        print(f"DEBUG: User: {user.user.username}, Organization: {user.organization.name if user.organization else 'None'}")
    
    # Applicazione filtri
    if search_query:
        users = users.filter(
            Q(user__username__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(user__email__icontains=search_query)
        )
    
    if role_filter:
        users = users.filter(
            user__user_roles__role__name=role_filter,
            user__user_roles__is_active=True
        )
    
    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    elif status_filter == 'locked':
        users = users.filter(locked_until__gt=timezone.now())
    
    # Paginazione
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Ruoli disponibili per il filtro
    available_roles = Role.objects.filter(
        is_active=True,
        user_assignments__user__userprofile__organization=organization
    ).distinct()
    
    context = {
        'organization': organization,
        'page_obj': page_obj,
        'search_query': search_query,
        'role_filter': role_filter,
        'status_filter': status_filter,
        'available_roles': available_roles,
    }
    
    return render(request, 'Cripto1/user_management/user_list.html', context)


@organization_admin_required()
def org_role_management(request):
    """Gestione ruoli dell'organizzazione"""
    user_profile = UserProfile.objects.get(user=request.user)
    organization = user_profile.organization
    
    if not organization:
        messages.error(request, 'Non sei associato a nessuna organizzazione.')
        return redirect('Cripto1:dashboard')
    
    # Ruoli utilizzati nell'organizzazione
    roles = Role.objects.filter(
        is_active=True,
        user_assignments__user__userprofile__organization=organization
    ).annotate(
        user_count=Count('user_assignments', filter=Q(
            user_assignments__is_active=True,
            user_assignments__user__userprofile__organization=organization
        ))
    ).distinct()
    
    context = {
        'organization': organization,
        'roles': roles,
    }
    
    return render(request, 'Cripto1/user_management/role_list.html', context)


@login_required
def org_audit_logs(request):
    """Log di audit dell'organizzazione"""
    user_profile = UserProfile.objects.get(user=request.user)
    organization = user_profile.organization
    
    # Debug temporaneo - sostituisci le righe di debug esistenti (175-186)
    print(f"DEBUG: User: {request.user.username}")
    print(f"DEBUG: Organization: {organization}")
    
    if not organization:
        messages.error(request, 'Non sei associato a nessuna organizzazione.')
        return redirect('Cripto1:dashboard')
    
    # Debug più dettagliato
    print(f"DEBUG: Organization ID: {organization.id if organization else 'None'}")
    
    # Verifica tutti i log per l'utente corrente
    user_logs = AuditLog.objects.filter(user=request.user)
    print(f"DEBUG: Direct user logs: {user_logs.count()}")
    
    # Verifica se l'utente ha un UserProfile
    try:
        user_profile = request.user.userprofile
        print(f"DEBUG: User has profile: True, org: {user_profile.organization}")
    except:
        print(f"DEBUG: User has profile: False")
    
    # Query base per log dell'organizzazione
    logs = AuditLog.objects.filter(
        user__userprofile__organization=organization
    ).select_related('user')
    
    print(f"DEBUG: Logs found with org filter: {logs.count()}")
    print(f"DEBUG: SQL Query: {logs.query}")
    
    # Verifica tutti gli utenti dell'organizzazione
    org_users = User.objects.filter(userprofile__organization=organization)
    print(f"DEBUG: Users in organization: {org_users.count()}")
    for u in org_users:
        u_logs = AuditLog.objects.filter(user=u)
        print(f"DEBUG: User {u.username} has {u_logs.count()} total logs")
    
    # Filtri
    action_type = request.GET.get('action_type', '')
    severity = request.GET.get('severity', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    success_filter = request.GET.get('success', '')
    
    # Applica filtri
    if action_type:
        logs = logs.filter(action_type=action_type)
    if severity:
        logs = logs.filter(severity=severity)
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    if success_filter:
        if success_filter == 'true':
            logs = logs.filter(success=True)
        elif success_filter == 'false':
            logs = logs.filter(success=False)
    
    # Debug temporaneo
    print(f"DEBUG: Final logs count after filters: {logs.count()}")
    
    # Ordina per timestamp
    logs = logs.order_by('-timestamp')
    
    # Paginazione
    paginator = Paginator(logs, 25)
    page_number = request.GET.get('page')
    
    try:
        page_obj = paginator.get_page(page_number)
    except PageNotAnInteger:
        page_obj = paginator.get_page(1)
    except EmptyPage:
        page_obj = paginator.get_page(paginator.num_pages)
    
    print(f"DEBUG: Paginated logs count: {len(page_obj)}")
    print(f"DEBUG: Paginated logs object: {page_obj}")
    
    # Opzioni per i filtri con nomi più leggibili
    ACTION_TYPE_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('create', 'Creazione'),
        ('update', 'Modifica'),
        ('delete', 'Eliminazione'),
        ('view', 'Visualizzazione'),
        ('export', 'Esportazione'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Bassa'),
        ('medium', 'Media'),
        ('high', 'Alta'),
        ('critical', 'Critica'),
    ]
    
    # Filtra solo i tipi di azione e severità effettivamente presenti
    existing_actions = set(AuditLog.objects.filter(
        user__userprofile__organization=organization
    ).values_list('action_type', flat=True).distinct())
    
    existing_severities = set(AuditLog.objects.filter(
        user__userprofile__organization=organization
    ).values_list('severity', flat=True).distinct())
    
    action_types = [(code, name) for code, name in ACTION_TYPE_CHOICES if code in existing_actions]
    severities = [(code, name) for code, name in SEVERITY_CHOICES if code in existing_severities]
    
    context = {
        'organization': organization,
        'logs': page_obj,  # Cambiato da page_obj a logs per il template
        'action_type': action_type,
        'severity': severity,
        'date_from': date_from,
        'date_to': date_to,
        'action_types': action_types,
        'severities': severities,
    }
    
    return render(request, 'Cripto1/audit_logs.html', context)


@organization_admin_required()
def org_sessions(request):
    """Gestione sessioni dell'organizzazione"""
    user_profile = UserProfile.objects.get(user=request.user)
    organization = user_profile.organization
    
    if not organization:
        messages.error(request, 'Non sei associato a nessuna organizzazione.')
        return redirect('Cripto1:dashboard')
    
    # Sessioni attive degli utenti dell'organizzazione
    from django.contrib.sessions.models import Session
    from django.contrib.auth.models import User
    
    active_sessions = []
    org_users = User.objects.filter(userprofile__organization=organization)
    
    for session in Session.objects.filter(expire_date__gte=timezone.now()):
        session_data = session.get_decoded()
        user_id = session_data.get('_auth_user_id')
        if user_id and int(user_id) in org_users.values_list('id', flat=True):
            user = User.objects.get(id=user_id)
            active_sessions.append({
                'session_key': session.session_key,
                'user': user,
                'expire_date': session.expire_date,
                'last_activity': user.userprofile.last_login_date,
            })
    
    context = {
        'organization': organization,
        'active_sessions': active_sessions,
    }
    
    return render(request, 'Cripto1/session_management.html', context)


@login_required
@organization_admin_required()
def org_admin_dashboard(request):
    user_org = request.user.userprofile.organization
    
    # Statistiche dell'organizzazione
    org_users = UserProfile.objects.filter(organization=user_org)
    total_users = org_users.count()
    active_users = org_users.filter(user__is_active=True).count()
    
    # CORREZIONE: Usa il campo organization direttamente
    total_transactions = Transaction.objects.filter(organization=user_org).count()
    
    # CORREZIONE: Filtra i blocchi per organizzazione
    total_blocks = Block.objects.filter(organization=user_org).count()
    
    # Attività recenti dell'organizzazione
    org_user_ids = org_users.values_list('user_id', flat=True)
    recent_activities = AuditLog.objects.filter(
        user_id__in=org_user_ids
    ).select_related('user').order_by('-timestamp')[:10]
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_transactions': total_transactions,
        'total_blocks': total_blocks,
        'recent_activities': recent_activities,
        'organization': user_org,
    }
    
    return render(request, 'Cripto1/org_admin_dashboard.html', context)


@organization_admin_required()
# Rimuovi tutti i log DEBUG ORG ADMIN
def file_retention_settings(request):
    """Gestione impostazioni retention file per l'organizzazione"""
    user_profile = UserProfile.objects.get(user=request.user)
    organization = user_profile.organization
    
    if request.method == 'POST':
        form = OrganizationFileRetentionForm(request.POST, instance=organization)
        if form.is_valid():
            form.save()
            messages.success(request, 'Impostazioni di retention file aggiornate con successo!')
            return redirect('Cripto1:file_retention_settings')
    else:
        form = OrganizationFileRetentionForm(instance=organization)
    
    # Statistiche sui file
    total_transaction_files = Transaction.objects.filter(
        organization=organization,
        file__isnull=False
    ).exclude(file='').count()
    
    context = {
        'form': form,
        'organization': organization,
        'total_transaction_files': total_transaction_files,
    }
    
    return render(request, 'Cripto1/organization_management/file_retention_settings.html', context)