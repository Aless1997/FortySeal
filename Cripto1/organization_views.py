from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.db import transaction
from django.utils import timezone
from .models import Organization, UserProfile, User, AuditLog, Block, Transaction, UserRole
from .decorators import admin_required
from django.core.paginator import Paginator
from django.db.models import Count, Sum, Q, Max
import json
import uuid

@admin_required()
def organization_list(request):
    """Lista delle organizzazioni"""
    organizations = Organization.objects.annotate(
        users_count=Count('user_profiles', distinct=True),
        active_users_count=Count('user_profiles', filter=Q(user_profiles__is_active=True), distinct=True),
        transactions_count=Count('transactions', distinct=True),
        blocks_count=Count('blocks', distinct=True),
        storage_used=Sum('user_profiles__storage_used_bytes')
    ).order_by('name')
    
    context = {
        'organizations': organizations,
        'total_organizations': organizations.count(),
    }
    return render(request, 'Cripto1/organization/organization_list.html', context)

@admin_required()
def organization_detail(request, org_id):
    """Dettaglio organizzazione"""
    organization = get_object_or_404(Organization, id=org_id)
    
    # Statistiche utenti
    users_stats = organization.user_profiles.aggregate(
        total_users=Count('id'),
        active_users=Count('id', filter=models.Q(is_active=True)),
        total_storage_used=Sum('storage_used_bytes')
    )
    
    # Statistiche transazioni
    transactions_stats = organization.transactions.aggregate(
        total_transactions=Count('id'),
        text_transactions=Count('id', filter=Q(type='text')),
        file_transactions=Count('id', filter=Q(type='file'))
        # Rimossa la riga pending_transactions poiché il campo 'status' non esiste
    )
    
    # Statistiche blockchain
    blockchain_stats = organization.blocks.aggregate(
        total_blocks=Count('id'),
        total_transactions_in_blocks=Sum('transactions__count')
    )
    
    context = {
        'organization': organization,
        'users_stats': users_stats,
        'transactions_stats': transactions_stats,
        'blockchain_stats': blockchain_stats,
    }
    return render(request, 'Cripto1/organization/organization_detail.html', context)

@admin_required()
def organization_create(request):
    """Crea nuova organizzazione"""
    if request.method == 'POST':
        try:
            with transaction.atomic():
                name = request.POST.get('name')
                slug = request.POST.get('slug')
                description = request.POST.get('description', '')
                domain = request.POST.get('domain', '')
                max_users = int(request.POST.get('max_users', 100))
                max_storage_gb = int(request.POST.get('max_storage_gb', 100))
                
                # Validazioni
                if Organization.objects.filter(slug=slug).exists():
                    messages.error(request, 'Slug già esistente')
                    return render(request, 'Cripto1/organization/organization_form.html')
                
                if domain and Organization.objects.filter(domain=domain).exists():
                    messages.error(request, 'Dominio già esistente')
                    return render(request, 'Cripto1/organization/organization_form.html')
                
                # Crea organizzazione
                organization = Organization.objects.create(
                    name=name,
                    slug=slug,
                    description=description,
                    domain=domain,
                    max_users=max_users,
                    max_storage_gb=max_storage_gb,
                    registration_code=f"ORG_{uuid.uuid4().hex[:8].upper()}",
                    features_enabled={
                        'blockchain': True,
                        '2fa': True,
                        'audit_logs': True,
                        'file_sharing': True,
                        'smart_contracts': False,
                    }
                )
                
                # Invia email di benvenuto per l'organizzazione
                from .email_utils import send_organization_welcome_email
                send_organization_welcome_email(organization, request.user.email, request)
                
                messages.success(request, f'Organizzazione {name} creata con successo')
                # Riga 110 - nella funzione organization_create
                return redirect('Cripto1:organization_management_detail', org_id=organization.id)
                
                # Riga 141 - nella funzione organization_edit  
                return redirect('Cripto1:organization_management_detail', org_id=organization.id)
                
        except Exception as e:
            messages.error(request, f'Errore durante la creazione: {str(e)}')
    
    return render(request, 'Cripto1/organization/organization_form.html')

@admin_required()
def organization_edit(request, org_id):
    """Modifica organizzazione"""
    organization = get_object_or_404(Organization, id=org_id)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Salva lo stato precedente per il log
                was_active = organization.is_active
                
                organization.name = request.POST.get('name')
                organization.description = request.POST.get('description', '')
                organization.domain = request.POST.get('domain', '')
                organization.max_users = int(request.POST.get('max_users', 100))
                organization.max_storage_gb = int(request.POST.get('max_storage_gb', 100))
                organization.max_file_size_mb = int(request.POST.get('max_file_size_mb', 10))
                
                # Validazione dimensione file
                if organization.max_file_size_mb > 10240:  # 10 GB in MB
                    messages.error(request, 'La dimensione massima dei file non può superare 10 GB (10240 MB)')
                    context = {
                        'organization': organization,
                        'features': organization.features_enabled or {}
                    }
                    return render(request, 'Cripto1/organization/organization_form.html', context)
                
                organization.require_2fa = request.POST.get('require_2fa') == 'on'
                organization.session_timeout_hours = int(request.POST.get('session_timeout_hours', 24))
                
                # Gestione stato organizzazione
                organization.is_active = request.POST.get('is_active') == 'on'
                
                # Campi di auto-eliminazione
                organization.auto_delete_enabled = request.POST.get('auto_delete_enabled') == 'on'
                organization.auto_delete_after_value = int(request.POST.get('auto_delete_after_value', 30))
                organization.auto_delete_after_unit = request.POST.get('auto_delete_after_unit', 'days')
                organization.cleanup_check_interval = int(request.POST.get('cleanup_check_interval', 30))
                
                # Aggiorna features
                features = {}
                for feature in ['blockchain', '2fa', 'audit_logs', 'file_sharing', 'smart_contracts']:
                    features[feature] = request.POST.get(f'feature_{feature}') == 'on'
                organization.features_enabled = features
                
                # Se l'organizzazione viene disattivata, disattiva tutti gli utenti
                if was_active and not organization.is_active:
                    affected_users = UserProfile.objects.filter(organization=organization, is_active=True)
                    users_count = affected_users.count()
                    affected_users.update(is_active=False)
                    
                    # Log dell'azione
                    AuditLog.log_action(
                        user=request.user,
                        action_type='ADMIN_ACTION',
                        description=f'Organizzazione {organization.name} disattivata. {users_count} utenti disattivati automaticamente.',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
                    )
                    
                    messages.warning(request, f'Organizzazione disattivata. {users_count} utenti sono stati automaticamente disattivati.')
                
                # Se l'organizzazione viene riattivata, riattiva automaticamente tutti gli utenti
                elif not was_active and organization.is_active:
                    inactive_users = UserProfile.objects.filter(organization=organization, is_active=False)
                    users_count = inactive_users.count()
                    inactive_users.update(is_active=True)  # Riattiva automaticamente gli utenti
                    
                    # Log dell'azione
                    AuditLog.log_action(
                        user=request.user,
                        action_type='ADMIN_ACTION',
                        description=f'Organizzazione {organization.name} riattivata. {users_count} utenti riattivati automaticamente.',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
                    )
                    
                    messages.success(request, f'Organizzazione riattivata. {users_count} utenti sono stati automaticamente riattivati.')
                    
                    # Se l'organizzazione viene riattivata, chiedi conferma per riattivare gli utenti
                elif not was_active and organization.is_active:
                    inactive_users = UserProfile.objects.filter(organization=organization, is_active=False)
                    users_count = inactive_users.count()
                    
                    # Log dell'azione
                    AuditLog.objects.create(
                        user=request.user,
                        action_type='ADMIN_ACTION',  # Cambiato da 'action' a 'action_type'
                        description=f'Organizzazione {organization.name} riattivata. {users_count} utenti disponibili per riattivazione.',
                        ip_address=request.META.get('REMOTE_ADDR'),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
                    )
                    
                    messages.info(request, f'Organizzazione riattivata. {users_count} utenti possono essere riattivati manualmente dalla gestione utenti.')
                
                organization.save()
                messages.success(request, f'Organizzazione {organization.name} aggiornata con successo')
                return redirect('Cripto1:organization_management_detail', org_id=organization.id)
                
        except Exception as e:
            messages.error(request, f'Errore durante l\'aggiornamento: {str(e)}')
    
    context = {
        'organization': organization,
        'features': organization.features_enabled or {}
    }
    return render(request, 'Cripto1/organization/organization_form.html', context)

@admin_required()
def organization_delete(request, org_id):
    """Elimina organizzazione"""
    organization = get_object_or_404(Organization, id=org_id)
    
    if request.method == 'POST':
        try:
            name = organization.name
            organization.delete()
            messages.success(request, f'Organizzazione {name} eliminata con successo')
            return redirect('Cripto1:organization_management_list')  # Cambia da organization_list a organization_management_list
        except Exception as e:
            messages.error(request, f'Errore durante l\'eliminazione: {str(e)}')
    
    # Calcola il conteggio degli utenti prima di passare al template
    users_count = organization.user_profiles.count() if organization.pk else 0
    
    context = {
        'organization': organization,
        'users_count': users_count
    }
    return render(request, 'Cripto1/organization/organization_confirm_delete.html', context)

@admin_required()
def organization_users(request, org_id):
    """Gestione utenti dell'organizzazione"""
    organization = get_object_or_404(Organization, id=org_id)
    users = organization.user_profiles.select_related('user').order_by('user__username')
    
    # Paginazione
    paginator = Paginator(users, 20)
    page = request.GET.get('page')
    users_page = paginator.get_page(page)
    
    context = {
        'organization': organization,
        'users': users_page,
        'total_users': users.count(),
    }
    return render(request, 'Cripto1/organization/organization_users.html', context)

@admin_required()
def organization_settings(request, org_id):
    """Impostazioni avanzate organizzazione"""
    organization = get_object_or_404(Organization, id=org_id)
    
    if request.method == 'POST':
        try:
            # Aggiorna configurazioni avanzate
            organization.primary_color = request.POST.get('primary_color', '#007bff')
            organization.secondary_color = request.POST.get('secondary_color', '#6c757d')
            
            # Aggiorna politiche password
            password_policy = {
                'min_length': int(request.POST.get('min_length', 8)),
                'require_uppercase': request.POST.get('require_uppercase') == 'on',
                'require_lowercase': request.POST.get('require_lowercase') == 'on',
                'require_numbers': request.POST.get('require_numbers') == 'on',
                'require_special': request.POST.get('require_special') == 'on',
                'max_age_days': int(request.POST.get('max_age_days', 90)),
            }
            organization.password_policy = password_policy
            
            organization.save()
            messages.success(request, 'Impostazioni aggiornate con successo')
            
        except Exception as e:
            messages.error(request, f'Errore durante l\'aggiornamento: {str(e)}')
    
    context = {
        'organization': organization,
        'password_policy': organization.password_policy or {}
    }
    return render(request, 'Cripto1/organization/organization_settings.html', context)


def is_superuser(user):
    return user.is_superuser

@user_passes_test(is_superuser)
@login_required
def organization_management_dashboard(request):
    """Dashboard principale per la gestione organizzazioni (solo superuser)"""
    
    # Statistiche generali
    total_organizations = Organization.objects.count()
    active_organizations = Organization.objects.filter(is_active=True).count()
    inactive_organizations = Organization.objects.filter(is_active=False).count()
    
    # Statistiche utenti per organizzazione
    total_users_in_orgs = UserProfile.objects.filter(organization__isnull=False).count()
    active_users_in_orgs = UserProfile.objects.filter(
        organization__isnull=False, 
        is_active=True
    ).count()
    
    # Calcolo statistiche mancanti per il template
    total_users = UserProfile.objects.count()  # Tutti gli utenti del sistema
    total_transactions = Transaction.objects.count()  # Tutte le transazioni del sistema
    
    # Organizzazioni recenti
    recent_organizations = Organization.objects.order_by('-created_at')[:10]
    
    # Top organizzazioni per utenti
    top_orgs_by_users = Organization.objects.annotate(
        users_count=Count('user_profiles')
    ).order_by('-users_count')[:5]
    
    # Top organizzazioni per transazioni
    top_orgs_by_transactions = Organization.objects.annotate(
        transactions_count=Count('transactions')
    ).order_by('-transactions_count')[:5]
    
    # Statistiche storage
    storage_stats = Organization.objects.aggregate(
        total_allocated_storage=Sum('max_storage_gb'),
        total_used_storage=Sum('user_profiles__storage_used_bytes')
    )
    
    # Attività recenti delle organizzazioni
    recent_activities = AuditLog.objects.filter(
        user__userprofile__organization__isnull=False
    ).select_related('user', 'user__userprofile__organization').order_by('-timestamp')[:20]
    
    # Calcolo media utenti per organizzazione
    avg_users_per_org = 0
    if total_organizations > 0:
        avg_users_per_org = round(total_users_in_orgs / total_organizations, 1)
    
    # Calcolo crescita mensile (esempio: confronto con il mese precedente)
    from datetime import datetime, timedelta
    last_month = datetime.now() - timedelta(days=30)
    orgs_last_month = Organization.objects.filter(created_at__lt=last_month).count()
    monthly_growth = 0
    if orgs_last_month > 0:
        monthly_growth = round(((total_organizations - orgs_last_month) / orgs_last_month) * 100, 1)
    
    # Calcolo percentuale organizzazioni attive
    active_organizations_percentage = 0
    if total_organizations > 0:
        active_organizations_percentage = round((active_organizations / total_organizations) * 100, 1)
    
    context = {
        'total_organizations': total_organizations,
        'active_organizations': active_organizations,
        'inactive_organizations': inactive_organizations,
        'total_users_in_orgs': total_users_in_orgs,
        'active_users_in_orgs': active_users_in_orgs,
        'total_users': total_users,
        'total_transactions': total_transactions,
        'recent_organizations': recent_organizations,
        'top_orgs_by_users': top_orgs_by_users,
        'top_orgs_by_transactions': top_orgs_by_transactions,
        'storage_stats': storage_stats,
        'recent_activities': recent_activities,
        'avg_users_per_org': avg_users_per_org,
        'monthly_growth': monthly_growth,
        'active_organizations_percentage': active_organizations_percentage,
    }
    
    return render(request, 'Cripto1/organization_management/dashboard.html', context)

@user_passes_test(is_superuser)
@login_required
def organization_management_list(request):
    """Lista completa organizzazioni con filtri e ricerca (solo superuser)"""
    
    # Filtri
    search_query = request.GET.get('search', '')
    status_filter = request.GET.get('status', 'all')
    sort_by = request.GET.get('sort', 'name')
    
    # Query base
    organizations = Organization.objects.annotate(
        users_count=Count('user_profiles', distinct=True),
        active_users_count=Count('user_profiles', filter=Q(user_profiles__is_active=True), distinct=True),
        transactions_count=Count('transactions', distinct=True),
        blocks_count=Count('blocks', distinct=True),
        storage_used=Sum('user_profiles__storage_used_bytes')
    ).order_by('name')
    
    # Applicazione filtri
    if search_query:
        organizations = organizations.filter(
            Q(name__icontains=search_query) |
            Q(domain__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    if status_filter == 'active':
        organizations = organizations.filter(is_active=True)
    elif status_filter == 'inactive':
        organizations = organizations.filter(is_active=False)
    
    # Ordinamento
    if sort_by == 'users':
        organizations = organizations.order_by('-users_count')
    elif sort_by == 'transactions':
        organizations = organizations.order_by('-transactions_count')
    elif sort_by == 'created':
        organizations = organizations.order_by('-created_at')
    else:
        organizations = organizations.order_by('name')
    
    # Calcolo statistiche aggiuntive
    total_organizations = organizations.count()
    active_count = organizations.filter(is_active=True).count()
    total_users = UserProfile.objects.filter(organization__in=organizations).count()
    avg_users = round(total_users / total_organizations, 1) if total_organizations > 0 else 0
    
    # Paginazione
    paginator = Paginator(organizations, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'status_filter': status_filter,
        'sort_by': sort_by,
        'total_organizations': total_organizations,
        'active_count': active_count,
        'total_users': total_users,
        'avg_users': avg_users,
    }
    
    return render(request, 'Cripto1/organization_management/list.html', context)

@user_passes_test(is_superuser)
@login_required
def organization_management_detail(request, org_id):
    """Dettaglio completo organizzazione con tutti gli utenti (solo superuser)"""
    
    organization = get_object_or_404(Organization, id=org_id)
    
    # Statistiche dettagliate
    users_stats = organization.user_profiles.aggregate(
        total_users=Count('id'),
        active_users=Count('id', filter=Q(is_active=True)),
        inactive_users=Count('id', filter=Q(is_active=False)),
        locked_users=Count('id', filter=Q(locked_until__gt=timezone.now())),
        total_storage_used=Sum('storage_used_bytes')
    )
    
    # Calcolo statistiche storage
    storage_stats = {
        'total_allocated_storage': organization.max_storage_gb,
        'total_used_storage': users_stats['total_storage_used'] or 0
    }
    
    # Lista completa utenti dell'organizzazione
    users = organization.user_profiles.select_related('user').annotate(
        roles_count=Count('user__user_roles'),
        transactions_count=Count('user__sent_transactions') + Count('user__received_transactions'),
        last_login=Max('user__last_login')
    ).order_by('user__username')
    
    # Paginazione utenti
    users_paginator = Paginator(users, 50)
    users_page_number = request.GET.get('users_page')
    users_page_obj = users_paginator.get_page(users_page_number)
    
    # Statistiche transazioni
    transactions_stats = organization.transactions.aggregate(
        total_transactions=Count('id'),
        text_transactions=Count('id', filter=Q(type='text')),
        file_transactions=Count('id', filter=Q(type='file'))
        # Rimossa la riga pending_transactions poiché il campo 'status' non esiste
    )
    
    # Statistiche blockchain
    blockchain_stats = organization.blocks.aggregate(
        total_blocks=Count('id')
        # Rimossa la riga total_block_size poiché il campo 'size_bytes' non esiste
    )
    
    # Attività recenti dell'organizzazione
    recent_activities = AuditLog.objects.filter(
        user__userprofile__organization=organization
    ).select_related('user').order_by('-timestamp')[:50]
    
    # Ruoli nell'organizzazione
    org_roles = UserRole.objects.filter(
        user__userprofile__organization=organization,
        is_active=True
    ).select_related('role', 'user__userprofile').order_by('role__name')
    
    # Calcolo percentuale storage utilizzato
    storage_percentage = 0
    if storage_stats['total_allocated_storage'] and storage_stats['total_used_storage']:
        total_allocated_bytes = storage_stats['total_allocated_storage'] * 1024 * 1024 * 1024  # GB to bytes
        storage_percentage = (storage_stats['total_used_storage'] / total_allocated_bytes) * 100
    
    context = {
        'organization': organization,
        'users_stats': users_stats,
        'users_page_obj': users_page_obj,
        'organization_users': users_page_obj,
        'organization_users_count': users_stats['total_users'],  # Aggiungi questa riga
        'transactions_stats': transactions_stats,
        'blockchain_stats': blockchain_stats,
        'recent_activities': recent_activities,
        'org_roles': org_roles,
        'storage_percentage': storage_percentage,
        'users_percentage': (users_stats['total_users'] or 0) / organization.max_users * 100 if organization.max_users > 0 else 0,
        # Aggiungi queste variabili per le statistiche
        'active_users_count': users_stats['active_users'],
        'total_transactions': transactions_stats['total_transactions'],
        'total_blocks': blockchain_stats['total_blocks'],
    }
    
    return render(request, 'Cripto1/organization_management/detail.html', context)

import logging

logger = logging.getLogger('Cripto1')

# Nella funzione dove gestisci max_file_size_mb
def your_view_function(request):
    raw_value = request.POST.get('max_file_size_mb', 10)
    logger.debug(f"Valore raw da POST: {raw_value} (tipo: {type(raw_value)})")
    
    try:
        converted_value = int(raw_value)
        logger.debug(f"Valore convertito: {converted_value} (tipo: {type(converted_value)})")
        organization.max_file_size_mb = converted_value
    except ValueError as e:
        logger.error(f"Errore conversione max_file_size_mb: {e}")
        logger.error(f"Valore problematico: '{raw_value}'")
    
    # ... existing code ...