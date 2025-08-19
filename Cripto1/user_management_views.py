from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone
from datetime import timedelta
import json
from datetime import datetime

from .models import UserProfile, Role, Permission, UserRole, AuditLog
from .decorators import permission_required, admin_required
from .forms import UserProfileEditForm


@admin_required()
def user_management_dashboard(request):
    """Dashboard principale per la gestione utenti"""
    total_users = User.objects.count()
    active_users = UserProfile.objects.filter(is_active=True).count()
    inactive_users = UserProfile.objects.filter(is_active=False).count()
    locked_users = UserProfile.objects.filter(locked_until__gt=timezone.now()).count()
    
    # Statistiche per ruolo
    role_stats = {}
    for role in Role.objects.filter(is_active=True):
        count = UserRole.objects.filter(role=role, is_active=True).exclude(
            expires_at__lt=timezone.now()
        ).count()
        role_stats[role.name] = count
    
    # Utenti recenti
    recent_users = UserProfile.objects.select_related('user').order_by('-created_at')[:10]
    
    # Attività recenti
    recent_activities = AuditLog.objects.filter(
        action_type__in=['USER_MANAGEMENT', 'ROLE_ASSIGNMENT', 'USER_ACTIVATION', 'USER_DEACTIVATION']
    ).order_by('-timestamp')[:10]
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'locked_users': locked_users,
        'role_stats': role_stats,
        'recent_users': recent_users,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'Cripto1/user_management/dashboard.html', context)


@permission_required('view_users')
def user_list(request):
    """Lista degli utenti con filtri e paginazione"""
    users = UserProfile.objects.select_related('user').all()
    
    # Filtri
    search = request.GET.get('search', '')
    status = request.GET.get('status', '')
    role_filter = request.GET.get('role', '')
    
    if search:
        users = users.filter(
            Q(user__username__icontains=search) |
            Q(user__email__icontains=search) |
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search) |
            Q(department__icontains=search) |
            Q(position__icontains=search)
        )
    
    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)
    elif status == 'locked':
        users = users.filter(locked_until__gt=timezone.now())
    
    if role_filter:
        users = users.filter(
            user_roles__role__name=role_filter,
            user_roles__is_active=True
        ).exclude(
            user_roles__expires_at__lt=timezone.now()
        )
    
    # Paginazione
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Ruoli disponibili per il filtro
    roles = Role.objects.filter(is_active=True)
    
    context = {
        'page_obj': page_obj,
        'search': search,
        'status': status,
        'role_filter': role_filter,
        'roles': roles,
    }
    
    return render(request, 'Cripto1/user_management/user_list.html', context)


@permission_required('edit_users')
def user_detail(request, user_id):
    """Dettaglio utente con gestione ruoli"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    user_roles = UserRole.objects.filter(user=user_profile.user).select_related('role', 'assigned_by')
    
    # Ruoli disponibili per l'assegnazione
    available_roles = Role.objects.filter(is_active=True).exclude(
        user_assignments__user=user_profile.user,
        user_assignments__is_active=True
    )
    
    # Attività recenti dell'utente
    recent_activities = AuditLog.objects.filter(user=user_profile.user).order_by('-timestamp')[:20]
    
    # Aggiungi questa riga per passare tutti i ruoli al template
    all_roles = Role.objects.filter(is_active=True)
    
    context = {
        'user_profile': user_profile,
        'user_roles': user_roles,
        'recent_activities': recent_activities,
        'now': timezone.now(),
        'all_roles': all_roles,  # Aggiungi questa riga
    }
    
    return render(request, 'Cripto1/user_management/user_detail.html', context)


@permission_required('add_users')
def create_user(request):
    """Creazione nuovo utente"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        department = request.POST.get('department', '')
        position = request.POST.get('position', '')
        phone = request.POST.get('phone', '')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username già esistente')
            return redirect('Cripto1:create_user')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email già esistente')
            return redirect('Cripto1:create_user')
        
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )
            
            user_profile = UserProfile.objects.create(
                user=user,
                department=department,
                position=position,
                phone=phone
            )
            
            # Assegna ruolo di default se specificato
            default_role = request.POST.get('default_role')
            if default_role:
                try:
                    role = Role.objects.get(name=default_role)
                    user_profile.assign_role(role, assigned_by=request.user)
                except Role.DoesNotExist:
                    pass
            
            # Log dell'azione
            AuditLog.log_action(
                user=request.user,
                action_type='USER_MANAGEMENT',
                description=f'Creato nuovo utente: {username}',
                severity='MEDIUM',
                ip_address=request.META.get('REMOTE_ADDR'),
                related_object_type='UserProfile',
                related_object_id=user_profile.id,
                additional_data={
                    'created_user': username,
                    'department': department,
                    'position': position,
                    'default_role': default_role
                }
            )
            
            messages.success(request, f'Utente {username} creato con successo')
            return redirect('Cripto1:user_detail', user_id=user.id)
            
        except Exception as e:
            messages.error(request, f'Errore durante la creazione dell\'utente: {str(e)}')
    
    # Ruoli disponibili per l'assegnazione di default
    roles = Role.objects.filter(is_active=True)
    
    context = {
        'roles': roles,
    }
    
    return render(request, 'Cripto1/user_management/create_user.html', context)


@permission_required('edit_users')
def edit_user(request, user_id):
    """Modifica dati utente"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    
    if request.method == 'POST':
        form = UserProfileEditForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            form.save()
            
            # Log dell'azione
            AuditLog.log_action(
                user=request.user,
                action_type='USER_MANAGEMENT',
                description=f'Modificato utente: {user_profile.user.username}',
                severity='MEDIUM',
                ip_address=request.META.get('REMOTE_ADDR'),
                related_object_type='UserProfile',
                related_object_id=user_profile.id
            )
            
            messages.success(request, 'Utente modificato con successo')
            return redirect('Cripto1:user_detail', user_id=user_id)
    else:
        form = UserProfileEditForm(instance=user_profile)
    
    context = {
        'form': form,
        'user_profile': user_profile,
    }
    
    return render(request, 'Cripto1/user_management/edit_user.html', context)


@permission_required('activate_users')
@require_POST
def toggle_user_status(request, user_id):
    """Attiva/disattiva utente"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    
    if user_profile.user == request.user:
        messages.error(request, 'Non puoi modificare il tuo stesso stato')
        return redirect('Cripto1:user_detail', user_id=user_id)
    
    user_profile.is_active = not user_profile.is_active
    user_profile.save()
    
    action = 'attivato' if user_profile.is_active else 'disattivato'
    
    # Log dell'azione
    AuditLog.log_action(
        user=request.user,
        action_type='USER_ACTIVATION' if user_profile.is_active else 'USER_DEACTIVATION',
        description=f'Utente {action}: {user_profile.user.username}',
        severity='HIGH',
        ip_address=request.META.get('REMOTE_ADDR'),
        related_object_type='UserProfile',
        related_object_id=user_profile.id
    )
    
    messages.success(request, f'Utente {user_profile.user.username} {action} con successo')
    return redirect('Cripto1:user_detail', user_id=user_id)


@permission_required('assign_roles')
@require_POST
def assign_role(request, user_id):
    """Assegna ruolo a utente"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    role_id = request.POST.get('role_id')
    expires_at = request.POST.get('expires_at')
    notes = request.POST.get('notes', '')
    
    try:
        role = Role.objects.get(id=role_id)
        
        # Converti la data di scadenza se fornita
        expires_date = None
        if expires_at:
            try:
                # Modifica qui: utilizziamo timezone.make_aware con timezone.get_default_timezone()
                naive_date = datetime.strptime(expires_at, '%Y-%m-%d')
                expires_date = timezone.make_aware(naive_date)
            except ValueError:
                messages.error(request, 'Formato data non valido')
                return redirect('Cripto1:user_detail', user_id=user_id)
        
        user_profile.assign_role(role, assigned_by=request.user, expires_at=expires_date, notes=notes)
        
        # Log dell'azione
        AuditLog.log_action(
            user=request.user,
            action_type='ROLE_ASSIGNMENT',
            description=f'Assegnato ruolo {role.name} a {user_profile.user.username}',
            severity='MEDIUM',
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='UserProfile',
            related_object_id=user_profile.id,
            additional_data={
                'assigned_role': role.name,
                'expires_at': expires_at,
                'notes': notes
            }
        )
        
        messages.success(request, f'Ruolo {role.name} assegnato con successo')
        
    except Role.DoesNotExist:
        messages.error(request, 'Ruolo non trovato')
    except Exception as e:
        messages.error(request, f'Errore durante l\'assegnazione del ruolo: {str(e)}')
    
    return redirect('Cripto1:user_detail', user_id=user_id)


@permission_required('assign_roles')
@require_POST
def remove_role(request, user_id, role_id):
    """Rimuove ruolo da utente"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    
    try:
        user_role = UserRole.objects.get(user=user_profile.user, role_id=role_id)
        role_name = user_role.role.name
        user_profile.remove_role(user_role.role)
        
        # Log dell'azione
        AuditLog.log_action(
            user=request.user,
            action_type='ROLE_ASSIGNMENT',
            description=f'Rimosso ruolo {role_name} da {user_profile.user.username}',
            severity='MEDIUM',
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='UserProfile',
            related_object_id=user_profile.id,
            additional_data={'removed_role': role_name}
        )
        
        messages.success(request, f'Ruolo {role_name} rimosso con successo')
        
    except UserRole.DoesNotExist:
        messages.error(request, 'Ruolo non trovato')
    except Exception as e:
        messages.error(request, f'Errore durante la rimozione del ruolo: {str(e)}')
    
    return redirect('Cripto1:user_detail', user_id=user_id)


@permission_required('manage_roles')
def role_list(request):
    """Lista dei ruoli"""
    roles = Role.objects.all().prefetch_related('permissions')
    
    context = {
        'roles': roles,
    }
    
    return render(request, 'Cripto1/user_management/role_list.html', context)


@permission_required('manage_roles')
def role_detail(request, role_id):
    """Dettaglio ruolo con gestione permessi"""
    role = get_object_or_404(Role, id=role_id)
    role_users = UserRole.objects.filter(role=role).select_related('user', 'assigned_by')
    
    # Permessi disponibili per l'aggiunta
    available_permissions = Permission.objects.filter(is_active=True).exclude(
        role=role
    )
    
    context = {
        'role': role,
        'role_users': role_users,
        'available_permissions': available_permissions,
    }
    
    return render(request, 'Cripto1/user_management/role_detail.html', context)


@permission_required('manage_roles')
def create_role(request):
    """Creazione nuovo ruolo"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        permissions = request.POST.getlist('permissions')
        
        if Role.objects.filter(name=name).exists():
            messages.error(request, 'Nome ruolo già esistente')
            return redirect('Cripto1:create_role')
        
        try:
            role = Role.objects.create(name=name, description=description)
            
            # Assegna i permessi
            for permission_id in permissions:
                try:
                    permission = Permission.objects.get(id=permission_id)
                    role.permissions.add(permission)
                except Permission.DoesNotExist:
                    pass
            
            # Log dell'azione
            AuditLog.log_action(
                user=request.user,
                action_type='PERMISSION_CHANGE',
                description=f'Creato nuovo ruolo: {name}',
                severity='MEDIUM',
                ip_address=request.META.get('REMOTE_ADDR'),
                related_object_type='Role',
                related_object_id=role.id,
                additional_data={
                    'role_name': name,
                    'permissions_count': len(permissions)
                }
            )
            
            messages.success(request, f'Ruolo {name} creato con successo')
            return redirect('Cripto1:role_detail', role_id=role.id)
            
        except Exception as e:
            messages.error(request, f'Errore durante la creazione del ruolo: {str(e)}')
    
    # Permessi disponibili raggruppati per categoria
    permissions_by_category = {}
    for permission in Permission.objects.filter(is_active=True).order_by('category', 'name'):
        if permission.category not in permissions_by_category:
            permissions_by_category[permission.category] = []
        permissions_by_category[permission.category].append(permission)
    
    context = {
        'permissions_by_category': permissions_by_category,
    }
    
    return render(request, 'Cripto1/user_management/create_role.html', context)


@permission_required('manage_roles')
@require_POST
def add_permission_to_role(request, role_id):
    """Aggiunge permesso a ruolo"""
    role = get_object_or_404(Role, id=role_id)
    permission_id = request.POST.get('permission_id')
    
    try:
        permission = Permission.objects.get(id=permission_id)
        role.permissions.add(permission)
        
        # Log dell'azione
        AuditLog.log_action(
            user=request.user,
            action_type='PERMISSION_CHANGE',
            description=f'Aggiunto permesso {permission.name} al ruolo {role.name}',
            severity='MEDIUM',
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='Role',
            related_object_id=role.id,
            additional_data={
                'permission_name': permission.name,
                'permission_codename': permission.codename
            }
        )
        
        messages.success(request, f'Permesso {permission.name} aggiunto con successo')
        
    except Permission.DoesNotExist:
        messages.error(request, 'Permesso non trovato')
    except Exception as e:
        messages.error(request, f'Errore durante l\'aggiunta del permesso: {str(e)}')
    
    return redirect('Cripto1:role_detail', role_id=role_id)


@permission_required('manage_roles')
@require_POST
def remove_permission_from_role(request, role_id, permission_id):
    """Rimuove permesso da ruolo"""
    role = get_object_or_404(Role, id=role_id)
    
    try:
        permission = Permission.objects.get(id=permission_id)
        role.permissions.remove(permission)
        
        # Log dell'azione
        AuditLog.log_action(
            user=request.user,
            action_type='PERMISSION_CHANGE',
            description=f'Rimosso permesso {permission.name} dal ruolo {role.name}',
            severity='MEDIUM',
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='Role',
            related_object_id=role.id,
            additional_data={
                'permission_name': permission.name,
                'permission_codename': permission.codename
            }
        )
        
        messages.success(request, f'Permesso {permission.name} rimosso con successo')
        
    except Permission.DoesNotExist:
        messages.error(request, 'Permesso non trovato')
    except Exception as e:
        messages.error(request, f'Errore durante la rimozione del permesso: {str(e)}')
    
    return redirect('Cripto1:role_detail', role_id=role_id)


def user_permissions_ajax(request):
    """Endpoint AJAX per ottenere i permessi di un utente"""
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Non autorizzato'}, status=401)
    
    user_id = request.GET.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'ID utente richiesto'}, status=400)
    
    try:
        user_profile = UserProfile.objects.get(user_id=user_id)
        permissions = user_profile.get_all_permissions()
        
        permissions_data = []
        for permission in permissions:
            permissions_data.append({
                'id': permission.id,
                'name': permission.name,
                'codename': permission.codename,
                'category': permission.category,
                'description': permission.description
            })
        
        return JsonResponse({
            'permissions': permissions_data,
            'total_count': len(permissions_data)
        })
        
    except UserProfile.DoesNotExist:
        return JsonResponse({'error': 'Utente non trovato'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500) 


def debug_permissions(request):
    """Vista di debug per testare i permessi dell'utente corrente"""
    if not request.user.is_authenticated:
        return redirect('Cripto1:login')
    
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        
        # Test dei permessi principali
        test_permissions = [
            'view_users', 'add_users', 'edit_users', 'delete_users', 
            'activate_users', 'assign_roles', 'manage_roles',
            'view_transactions', 'create_transactions', 'view_blockchain'
        ]
        
        permission_results = user_profile.test_permissions(test_permissions)
        permissions_summary = user_profile.get_permissions_summary()
        
        context = {
            'user': request.user,
            'profile': user_profile,
            'roles': [role.name for role in user_profile.get_roles()],
            'permission_tests': permission_results,
            'permissions_summary': permissions_summary
        }
        
        return render(request, 'Cripto1/debug_permissions.html', context)
        
    except UserProfile.DoesNotExist:
        messages.error(request, 'Profilo utente non trovato.')
        return redirect('Cripto1:dashboard')
    except Exception as e:
        messages.error(request, f'Errore durante il debug: {str(e)}')
        return redirect('Cripto1:dashboard')


@permission_required('edit_users')
def view_user_2fa_qrcode(request, user_id):
    """Visualizza il QR code 2FA di un utente per l'amministratore"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    
    # Verifica se dobbiamo abilitare il 2FA
    enable_2fa = request.GET.get('enable') == 'true'
    
    # Se il 2FA non è abilitato e non è richiesta l'abilitazione, reindirizza
    if not user_profile.two_factor_enabled and not enable_2fa:
        messages.error(request, "L'utente non ha l'autenticazione a due fattori abilitata.")
        return redirect('Cripto1:user_detail', user_id=user_id)
    
    # Se richiesto, abilita il 2FA
    if enable_2fa and not user_profile.two_factor_enabled:
        # Genera il segreto 2FA se non esiste
        user_profile.generate_2fa_secret()
        # Abilita il 2FA ma richiedi verifica da parte dell'utente
        user_profile.two_factor_enabled = True
        user_profile.two_factor_verified = False
        user_profile.save()
        messages.success(request, "2FA abilitato con successo per l'utente. L'utente dovrà verificare il codice al primo accesso.")
    
    # Rigenera il QR code se richiesto
    if request.method == 'POST' and 'regenerate_qrcode' in request.POST:
        user_profile.regenerate_2fa_secret()
        messages.success(request, "QR code rigenerato con successo. L'utente dovrà verificare nuovamente l'autenticazione.")
    
    # Genera l'URI per il QR code
    qr_uri = user_profile.get_totp_uri()
    
    # Genera il QR code come immagine
    import qrcode
    from io import BytesIO
    import base64
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    qr_image = base64.b64encode(buffer.getvalue()).decode()
    
    context = {
        'user_profile': user_profile,
        'qr_image': qr_image,
        'secret_key': user_profile.two_factor_secret
    }
    
    return render(request, 'Cripto1/user_management/user_2fa_qrcode.html', context)


@permission_required('assign_roles')
def assign_role_form(request, user_id):
    """Form per assegnazione ruolo"""
    user_profile = get_object_or_404(UserProfile, user_id=user_id)
    
    # Ruoli disponibili per l'assegnazione
    all_roles = Role.objects.filter(is_active=True)
    
    context = {
        'user_profile': user_profile,
        'all_roles': all_roles,
    }
    
    return render(request, 'Cripto1/user_management/assign_role_form.html', context)