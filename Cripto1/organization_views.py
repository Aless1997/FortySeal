from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse
from django.db import transaction
from .models import Organization, UserProfile, User
from .decorators import admin_required
from django.core.paginator import Paginator
from django.db.models import Count, Sum
import json
import uuid

@admin_required()
def organization_list(request):
    """Lista delle organizzazioni"""
    organizations = Organization.objects.annotate(
        users_count=Count('user_profiles'),
        active_users_count=Count('user_profiles', filter=models.Q(user_profiles__is_active=True)),
        transactions_count=Count('transactions'),
        blocks_count=Count('blocks')
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
        text_transactions=Count('id', filter=models.Q(type='text')),
        file_transactions=Count('id', filter=models.Q(type='file'))
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
                
                messages.success(request, f'Organizzazione {name} creata con successo')
                return redirect('Cripto1:organization_detail', org_id=organization.id)
                
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
                organization.name = request.POST.get('name')
                organization.description = request.POST.get('description', '')
                organization.domain = request.POST.get('domain', '')
                organization.max_users = int(request.POST.get('max_users', 100))
                organization.max_storage_gb = int(request.POST.get('max_storage_gb', 100))
                organization.require_2fa = request.POST.get('require_2fa') == 'on'
                organization.session_timeout_hours = int(request.POST.get('session_timeout_hours', 24))
                
                # Aggiorna features
                features = {}
                for feature in ['blockchain', '2fa', 'audit_logs', 'file_sharing', 'smart_contracts']:
                    features[feature] = request.POST.get(f'feature_{feature}') == 'on'
                organization.features_enabled = features
                
                organization.save()
                messages.success(request, f'Organizzazione {organization.name} aggiornata con successo')
                return redirect('Cripto1:organization_detail', org_id=organization.id)
                
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
            return redirect('Cripto1:organization_list')
        except Exception as e:
            messages.error(request, f'Errore durante l\'eliminazione: {str(e)}')
    
    context = {'organization': organization}
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