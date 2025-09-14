from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from .models import AuditLog, UserProfile
import json
from datetime import timedelta
import threading
import time
from django.core.cache import cache
from datetime import timedelta
import threading
from .models import Organization, Transaction
import os
import logging

logger = logging.getLogger(__name__)

class SmartAutoCleanupMiddleware:
    """Middleware MRP che rispetta gli intervalli configurati da ogni admin"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Controlla per ogni organizzazione se è ora del cleanup
        self.check_and_run_cleanup()
        response = self.get_response(request)
        return response
    
    def check_and_run_cleanup(self):
        """Controlla ogni organizzazione e esegue cleanup se necessario"""
        now = timezone.now()
        
        for org in Organization.objects.filter(auto_delete_enabled=True):
            cache_key = f'last_cleanup_org_{org.id}'
            last_cleanup = cache.get(cache_key)
            
            # Usa l'intervallo configurato dall'admin
            interval_minutes = org.cleanup_check_interval
            check_interval = timedelta(minutes=interval_minutes)
            
            # Controlla se è ora di fare cleanup per questa organizzazione
            if not last_cleanup or (now - last_cleanup) >= check_interval:
                # Esegui cleanup in background per questa organizzazione
                threading.Thread(
                    target=self.run_org_cleanup, 
                    args=(org,), 
                    daemon=True
                ).start()
                
                # Aggiorna cache per questa organizzazione
                cache.set(cache_key, now, timeout=interval_minutes * 60)
    
    def run_org_cleanup(self, org):
        """Esegue cleanup per una specifica organizzazione"""
        try:
            # Usa i nomi corretti dei campi
            if not org.auto_delete_enabled:
                return
                
            # Calcola retention usando il metodo del modello
            retention_delta = org.get_auto_delete_timedelta()
            if not retention_delta:
                return
                
            cutoff_time = timezone.now() - retention_delta
            cutoff_timestamp = cutoff_time.timestamp()
            
            expired_transactions = Transaction.objects.filter(
                organization=org,
                timestamp__lt=cutoff_timestamp
            )
            
            deleted_count = 0
            for transaction in expired_transactions:
                try:
                    file_deleted = False
                    if transaction.file and os.path.exists(transaction.file.path):
                        file_path = transaction.file.path
                        os.remove(file_path)
                        file_deleted = True
                    
                    if file_deleted:
                        transaction.file = None
                        transaction.save()
                        deleted_count += 1
                except Exception as e:
                    logger.error(f'Errore cleanup transazione {transaction.id}: {e}')
            
            if deleted_count > 0:
                logger.info(
                    f'Org {org.name}: {deleted_count} file eliminati '
                    f'(controllo ogni {org.cleanup_check_interval} min)'
                )
                
        except Exception as e:
            logger.error(f'Errore cleanup org {org.id}: {e}')
print("=== AuditLogMiddleware caricato ===")

class AuditLogMiddleware(MiddlewareMixin):
    """
    Middleware per tracciare automaticamente le azioni degli utenti
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        # Mappa i view names agli action types del modello
        self.tracked_actions = {
            'Cripto1:login_view': 'LOGIN',
            'Cripto1:logout_view': 'LOGOUT',
            'Cripto1:register': 'REGISTER',
            'Cripto1:create_transaction': 'CREATE_TRANSACTION',
            'Cripto1:transaction_details': 'VIEW_TRANSACTION',
            'Cripto1:download_file': 'DOWNLOAD_FILE',
            'Cripto1:decrypt_transaction': 'DECRYPT_MESSAGE',
            'Cripto1:mine_block': 'MINE_BLOCK',
            'Cripto1:personal_profile': 'EDIT_PROFILE',
            'Cripto1:personal_statistics': 'VIEW_TRANSACTION',
            'Cripto1:dashboard': 'SYSTEM_EVENT',
            'Cripto1:users_feed': 'SYSTEM_EVENT',
            # Aggiungi altre mappature secondo necessità
        }

    def process_request(self, request):
        # Salva informazioni della richiesta per uso successivo
        request.audit_info = {
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'session_id': request.session.session_key or '',
        }
        return None

    def process_response(self, request, response):
        print(f"[DEBUG] process_response chiamato per path: {request.path}")
        if hasattr(request, 'resolver_match'):
            view_name = getattr(request.resolver_match, 'view_name', None)
            print(f"[DEBUG] view_name: {view_name}")
        else:
            view_name = None
            print("[DEBUG] Nessun resolver_match su request")
        # Loggo tutte le view per test
        self.log_action(request, view_name, response)
        return response

    def get_client_ip(self, request):
        """Ottiene l'IP reale del client anche dietro proxy"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def log_action(self, request, view_name, response):
        try:
            # Usa la mappatura per convertire view_name in action_type valido
            action_type = self.tracked_actions.get(view_name, 'SYSTEM_EVENT')
            print(f"[AUDIT DEBUG] user={getattr(request, 'user', None)}, view_name={view_name}, mapped_action_type={action_type}, path={request.path}")
            # Determina la severità basata sul tipo di azione
            severity = self.get_severity(action_type)
            # Crea la descrizione
            description = self.create_description(request, view_name, response)
            # Dati aggiuntivi
            additional_data = self.get_additional_data(request, view_name)
            # Determina se l'azione è stata completata con successo
            success = response.status_code < 400
            # Messaggio di errore se presente
            error_message = ""
            if not success:
                error_message = f"HTTP {response.status_code}"
            # Crea l'audit log
            from Cripto1.models import AuditLog
            AuditLog.log_action(
                user=request.user if hasattr(request, 'user') and getattr(request, 'user', None) and request.user.is_authenticated else None,
                action_type=action_type,
                description=description,
                severity=severity,
                ip_address=getattr(request, 'audit_info', {}).get('ip_address'),
                user_agent=getattr(request, 'audit_info', {}).get('user_agent'),
                session_id=getattr(request, 'audit_info', {}).get('session_id'),
                additional_data=additional_data,
                success=success,
                error_message=error_message
            )
        except Exception as e:
            import traceback
            print(f"ERROR: Failed to create audit log: {e}")
            traceback.print_exc()

    def get_severity(self, action_type):
        """Determina la severità dell'azione"""
        high_severity = ['LOGIN', 'LOGOUT', 'REGISTER', 'ADMIN_ACTION']
        critical_severity = ['SECURITY_EVENT']
        
        if action_type in critical_severity:
            return 'CRITICAL'
        elif action_type in high_severity:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def create_description(self, request, view_name, response):
        """Crea una descrizione dettagliata dell'azione"""
        descriptions = {
            'login_view': f"Tentativo di login per utente",
            'logout_view': f"Logout utente",
            'register': f"Registrazione nuovo utente",
            'create_transaction': f"Creazione nuova transazione",
            'transaction_details': f"Visualizzazione dettagli transazione",
            'download_file': f"Download file da transazione",
            'decrypt_transaction': f"Decifratura messaggio",
            'mine_block': f"Mining nuovo blocco",
            'edit_profile': f"Modifica profilo utente",

            'admin_dashboard': f"Accesso dashboard amministrativa",
            'verify_blockchain': f"Verifica integrità blockchain",
            'export_csv': f"Export dati in CSV",
            'admin_user_detail': f"Visualizzazione dettagli utente",

        }
        
        base_description = descriptions.get(view_name, f"Azione: {view_name}")
        
        # Aggiungi dettagli specifici
        if view_name == 'create_transaction':
            transaction_type = request.POST.get('type', 'unknown')
            base_description += f" (Tipo: {transaction_type})"
        elif view_name == 'transaction_details':
            transaction_id = request.resolver_match.kwargs.get('transaction_id', 'unknown')
            base_description += f" (ID: {transaction_id})"
        elif view_name == 'download_file':
            transaction_id = request.resolver_match.kwargs.get('transaction_id', 'unknown')
            base_description += f" (ID: {transaction_id})"
        elif view_name == 'admin_user_detail':
            user_id = request.resolver_match.kwargs.get('user_id', 'unknown')
            base_description += f" (User ID: {user_id})"
        
        return base_description

    def get_additional_data(self, request, view_name):
        """Raccoglie dati aggiuntivi per l'audit log"""
        data = {
            'method': request.method,
            'path': request.path,
            'view_name': view_name,
        }
        
        # Aggiungi parametri specifici per alcune azioni
        if view_name == 'create_transaction':
            data['transaction_type'] = request.POST.get('type', '')
            data['is_encrypted'] = request.POST.get('is_encrypted', 'false')
        elif view_name == 'transaction_details':
            data['transaction_id'] = request.resolver_match.kwargs.get('transaction_id')
        elif view_name == 'download_file':
            data['transaction_id'] = request.resolver_match.kwargs.get('transaction_id')
        elif view_name == 'admin_user_detail':
            data['target_user_id'] = request.resolver_match.kwargs.get('user_id')
        
        return data


class SecurityMiddleware(MiddlewareMixin):
    """
    Middleware per la gestione della sicurezza e dei tentativi di login
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        # Percorsi esenti dal controllo di sicurezza
        self.exempt_paths = [
            '/admin/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]
    
    # Aggiungi questa classe al file middleware.py esistente
    
class FileUploadSecurityMiddleware(MiddlewareMixin):


    def __init__(self, get_response):
        super().__init__(get_response)
        self.allowed_extensions = [
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv', 'jpg', 'jpeg', 'png', 'gif'
        ]
        self.max_file_size = 10 * 1024 * 1024  # 10MB

    def process_request(self, request):
        if request.method == 'POST' and request.FILES and request.user.is_authenticated:
            # Controlla la quota storage dell'utente
            try:
                user_profile = request.user.userprofile
                user_profile.update_storage_usage()  # Aggiorna l'utilizzo corrente
                
                total_upload_size = sum(file.size for file in request.FILES.values())
                
                if not user_profile.has_storage_available(total_upload_size):
                    messages.error(request, f'Quota storage superata. Hai a disposizione {user_profile.get_storage_quota_gb():.1f}GB, attualmente utilizzati {user_profile.get_storage_used_gb():.1f}GB.')
                    return redirect(request.path)
                    
            except Exception as e:
                print(f"Errore controllo quota storage: {e}")
            
            for field_name, file in request.FILES.items():
                # 1. Controllo estensione
                file_extension = file.name.split('.')[-1].lower()
                if file_extension not in self.allowed_extensions:
                    messages.error(request, f'Estensione file non consentita: {file.name}')
                    return redirect(request.path)
                
                # 2. Controllo dimensione
                if file.size > self.max_file_size:
                    messages.error(request, f'File troppo grande: {file.name}')
                    return redirect(request.path)
                
                # 3. Scansione antivirus (se disponibile)
                try:
                    from django_clamd import clamd
                    from tempfile import NamedTemporaryFile
                    import os
                    
                    with NamedTemporaryFile(delete=False) as temp_file:
                        for chunk in file.chunks():
                            temp_file.write(chunk)
                        temp_file_path = temp_file.name
                    
                    try:
                        scanner = clamd.ClamdUnixSocket()
                        scan_result = scanner.scan_file(temp_file_path)
                        
                        if scan_result and temp_file_path in scan_result and scan_result[temp_file_path][0] == 'FOUND':
                            os.unlink(temp_file_path)
                            virus_name = scan_result[temp_file_path][1]
                            
                            # Registra l'evento di sicurezza
                            AuditLog.log_action(
                                user=request.user if request.user.is_authenticated else None,
                                action_type='SECURITY_EVENT',
                                description=f'Tentativo di caricamento file infetto: {file.name}',
                                severity='HIGH',
                                additional_data={'virus_detected': virus_name},
                                success=False,
                                error_message=f'Virus rilevato: {virus_name}'
                            )
                            
                            messages.error(request, f'File {file.name} contiene codice malevolo e non può essere caricato.')
                            return redirect(request.path)
                        
                        # Riavvolgi il file per l'uso successivo
                        file.seek(0)
                        os.unlink(temp_file_path)
                        
                    except Exception as e:
                        os.unlink(temp_file_path)
                        print(f"Errore durante la scansione antivirus: {str(e)}")
                except ImportError:
                    print("django-clamd non è installato. La scansione antivirus è disabilitata.")
        
        return None

    def handle_login_attempt(self, request):
        """Gestisce i tentativi di login e il blocco account"""
        username = request.POST.get('username')
        if not username:
            return
        
        try:
            user = UserProfile.objects.get(user__username=username)
            
            # Se l'account è bloccato, incrementa i tentativi e logga
            if user.is_locked():
                user.increment_login_attempts()
                
                # Log dell'evento di sicurezza
                AuditLog.log_action(
                    action_type='SECURITY_EVENT',
                    description=f'Tentativo di login su account bloccato: {username}',
                    severity='HIGH',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message='Account temporaneamente bloccato'
                )
                
                messages.error(request, 'Account temporaneamente bloccato. Riprova più tardi.')
                return
            
            # Se il login fallisce, incrementa i tentativi
            if request.method == 'POST' and hasattr(request, 'resolver_match') and request.resolver_match and 'login_view' in request.resolver_match.view_name:
                # Il controllo del successo del login viene fatto nella view
                # Qui gestiamo solo il fallimento
                pass
                
        except UserProfile.DoesNotExist:
            # Log del tentativo di login con username inesistente
            AuditLog.log_action(
                action_type='SECURITY_EVENT',
                description=f'Tentativo di login con username inesistente: {username}',
                severity='MEDIUM',
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                error_message='Username non trovato'
            )

    def check_user_status(self, request):
        """Controlla lo stato dell'utente autenticato"""
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            
            # Controlla se l'account è attivo
            if not user_profile.is_active:
                messages.error(request, 'Il tuo account è stato disattivato.')
                from django.contrib.auth import logout
                logout(request)
                return redirect('Cripto1:login')
            
            # Controlla se l'account è bloccato
            if user_profile.is_locked():
                messages.error(request, 'Il tuo account è temporaneamente bloccato.')
                from django.contrib.auth import logout
                logout(request)
                return redirect('Cripto1:login')
            
            # Aggiorna le informazioni dell'ultimo login
            if not hasattr(request, '_last_login_updated'):
                user_profile.update_last_login(self.get_client_ip(request))
                request._last_login_updated = True
                
        except UserProfile.DoesNotExist:
            # Se non esiste un profilo, creane uno
            UserProfile.objects.create(user=request.user)

    def get_client_ip(self, request):
        """Ottiene l'IP reale del client anche dietro proxy"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RoleExpirationMiddleware(MiddlewareMixin):
    """Middleware per disattivare automaticamente i ruoli scaduti"""
    
    def process_request(self, request):
        # Esegui questa operazione solo occasionalmente per non sovraccaricare il sistema
        # Ad esempio, con una probabilità del 5%
        import random
        if random.random() < 0.05:  # 5% delle richieste
            from Cripto1.models import UserRole
            from django.utils import timezone
            
            # Trova tutti i ruoli scaduti ma ancora attivi
            expired_roles = UserRole.objects.filter(
                is_active=True,
                expires_at__lt=timezone.now()
            )
            
            # Disattivali
            count = expired_roles.count()
            if count > 0:
                expired_roles.update(is_active=False)
                print(f"[INFO] Disattivati {count} ruoli scaduti")
        
        return None


class MultiTenantMiddleware(MiddlewareMixin):
    """
    Middleware per gestire il multi-tenancy basato su dominio o subdomain
    """
    
    def process_request(self, request):
        # Determina l'organizzazione basandosi sul dominio
        organization = self.get_organization_from_request(request)
        
        if organization:
            request.organization = organization
            # Imposta il database per l'organizzazione se necessario
            # self.set_organization_database(organization)
        else:
            # Organizzazione di default o errore
            request.organization = None
        
        return None
    
    def get_organization_from_request(self, request):
        """Determina l'organizzazione dal request"""
        host = request.get_host().lower()
        
        # Rimuovi la porta se presente
        if ':' in host:
            host = host.split(':')[0]
        
        # Controlla se è un subdomain (es: org1.fortyseal.com)
        if '.' in host:
            subdomain = host.split('.')[0]
            
            # Ignora www e altri subdomain comuni
            if subdomain not in ['www', 'api', 'admin', 'mail']:
                try:
                    from Cripto1.models import Organization
                    return Organization.objects.get(slug=subdomain, is_active=True)
                except Organization.DoesNotExist:
                    pass
        
        # Controlla se è un dominio personalizzato
        try:
            from Cripto1.models import Organization
            return Organization.objects.get(domain=host, is_active=True)
        except Organization.DoesNotExist:
            pass
        
        # Se non trova nulla, usa l'organizzazione di default
        try:
            from Cripto1.models import Organization
            return Organization.objects.filter(is_active=True).first()
        except Exception:
            return None
    
    def set_organization_database(self, organization):
        """Imposta il database per l'organizzazione specifica"""
        # Per implementazioni più avanzate con database separati
        pass


class Require2FAMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # URL che non richiedono il controllo 2FA
        exempt_urls = [
            '/setup-2fa/',
            '/logout/',
            '/login/',
            '/admin/',
        ]
        
        if (request.user.is_authenticated and 
            hasattr(request.user, 'userprofile') and
            not any(request.path.startswith(url) for url in exempt_urls)):
            
            user_profile = request.user.userprofile
            if (user_profile.organization and 
                user_profile.organization.require_2fa and 
                not user_profile.two_factor_verified):
                
                from django.shortcuts import redirect
                return redirect('Cripto1:setup_2fa')
        
        response = self.get_response(request)
        return response