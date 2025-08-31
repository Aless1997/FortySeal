from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from .models import Block, Transaction, UserProfile, SmartContract, AuditLog, Permission, Role, UserRole, PersonalDocument, BlockchainState, SharedDocument, ShareNotification, CreatedDocument, Organization
from django.db import transaction, models
import hashlib
import json
import time
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
import datetime
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from django.utils import timezone
import random
from .forms import UserProfileEditForm
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Sum, Q
import csv
import os
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from django.contrib.auth.forms import UserChangeForm, PasswordResetForm
import uuid
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.urls import reverse
from datetime import datetime, timedelta
from django.core.exceptions import PermissionDenied
from django.views.decorators.http import require_POST
import pyotp
import qrcode
import io
import re
from .decorators import permission_required, role_required, admin_required, active_user_required, external_forbidden, user_manager_forbidden
from .email_utils import send_welcome_email, send_transaction_notification, send_block_confirmation_emails
from django.core.cache import caches
from django.contrib.sessions.models import Session
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count
from django.template.loader import render_to_string
import traceback
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
import zipfile

cipher_suite = Fernet(settings.FERNET_KEY)

def homepage(request):
    return render(request, 'Cripto1/index.html')

def register_organization(request):
    """Registrazione di una nuova organizzazione con amministratore"""
    if request.method == 'POST':
        from .forms import OrganizationRegistrationForm
        form = OrganizationRegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # 1. Crea l'organizzazione
                    organization = Organization.objects.create(
                        name=form.cleaned_data['organization_name'],
                        slug=form.cleaned_data['organization_slug'],
                        description=form.cleaned_data.get('organization_description', ''),
                        domain=form.cleaned_data.get('organization_domain', ''),
                        registration_code=f"ORG_{uuid.uuid4().hex[:8].upper()}",
                        max_users=50,  # Default per nuove organizzazioni
                        max_storage_gb=10,  # Default per nuove organizzazioni
                        is_active=True,  # Attiva automaticamente alla registrazione
                        features_enabled={
                            'blockchain': True,
                            '2fa': True,
                            'audit_logs': True,
                            'file_sharing': True,
                            'smart_contracts': False,
                        }
                    )
                    
                    # 2. Crea l'utente amministratore
                    admin_user = User.objects.create_user(
                        username=form.cleaned_data['admin_username'],
                        email=form.cleaned_data['admin_email'],
                        password=form.cleaned_data['admin_password'],
                        first_name=form.cleaned_data['admin_first_name'],
                        last_name=form.cleaned_data['admin_last_name']
                    )
                    
                    # 3. Crea il profilo amministratore
                    admin_profile = UserProfile.objects.create(
                        user=admin_user,
                        organization=organization,
                        position='Amministratore',
                        is_active=True  # Attiva automaticamente alla registrazione
                    )
                    
                    # 4. Genera chiavi crittografiche
                    admin_profile.generate_key_pair(password=form.cleaned_data['admin_password'].encode())
                    admin_profile.generate_2fa_secret()

                    try:
                        org_admin_role = Role.objects.get(name='Organization Admin')
                        admin_profile.assign_role(org_admin_role)
                    except Role.DoesNotExist:
                        # Se il ruolo non esiste, logga l'errore ma non bloccare la registrazione
                        import logging
                        logger = logging.getLogger(__name__)
                        logger.error(f"Ruolo 'Organization Admin' non trovato durante la registrazione dell'organizzazione {organization.name}")

                    except Role.DoesNotExist:
                        # Se il ruolo non esiste, logga l'errore ma non bloccare la registrazione
                        import logging
                        logger = logging.getLogger(__name__)
                        logger.error(f"Ruolo 'Organization Admin' non trovato durante la registrazione dell'organizzazione {organization.name}")
                    
                    messages.success(
                        request, 
                        f'Organizzazione "{organization.name}" registrata con successo! '
                        f'La registrazione è in attesa di approvazione da parte degli amministratori.'
                    )
                    return redirect('Cripto1:organization_registration_success')
                    
            except Exception as e:
                messages.error(request, f'Errore durante la registrazione: {str(e)}')
                return render(request, 'Cripto1/register_organization.html', {'form': form})
    else:
        from .forms import OrganizationRegistrationForm
        form = OrganizationRegistrationForm()
    
    return render(request, 'Cripto1/register_organization.html', {'form': form})

def organization_registration_success(request):
    """Pagina di successo registrazione organizzazione"""
    return render(request, 'Cripto1/organization_registration_success.html')

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        private_key_password = request.POST.get('private_key_password')
        organization_code = request.POST.get('organization_code')
        
        # Verifica la robustezza della password
        if len(password) < 8:
            messages.error(request, 'La password deve essere di almeno 8 caratteri')
            return render(request, 'Cripto1/register.html')
        
        # Verifica che la password contenga almeno un numero e una lettera
        if not (any(c.isdigit() for c in password) and any(c.isalpha() for c in password)):
            messages.error(request, 'La password deve contenere almeno un numero e una lettera')
            return render(request, 'Cripto1/register.html')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username già esistente')
            return render(request, 'Cripto1/register.html')
        
        # Trova l'organizzazione dal codice
        try:
            organization = Organization.objects.get(registration_code=organization_code, is_active=True)
        except Organization.DoesNotExist:
            messages.error(request, 'Codice organizzazione non valido')
            return render(request, 'Cripto1/register.html')
            
        user = User.objects.create_user(username=username, email=email, password=password)
        
        user_profile = UserProfile.objects.create(
            user=user,
            organization=organization
        )
        user_profile.generate_key_pair(password=private_key_password.encode())  # Usa la password scelta
        
        # Genera un segreto 2FA per l'utente
        user_profile.generate_2fa_secret()
        
        # Assegna il ruolo "external" all'utente
        try:
            external_role = Role.objects.get(name='external')
            user_profile.assign_role(external_role)
        except Role.DoesNotExist:
            # Se il ruolo non esiste, log dell'errore
            print(f"ERRORE: Ruolo 'external' non trovato durante la registrazione dell'utente {username}")
        
        # Invia email di benvenuto
        email_sent = send_welcome_email(user, user_profile, request)
        if email_sent:
            messages.success(request, 'Registrazione completata! Controlla la tua email per i dettagli del tuo account.')
        else:
            messages.warning(request, 'Registrazione completata, ma si è verificato un problema nell\'invio dell\'email di benvenuto.')
        
        # Autentica l'utente
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Configura ora l\'autenticazione a due fattori.')
            return redirect('Cripto1:setup_2fa')  # Reindirizza alla configurazione 2FA
        
    return render(request, 'Cripto1/register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Controlla se l'utente esiste e il suo stato
        try:
            user_profile = UserProfile.objects.get(user__username=username)
            
            # Controlla se l'account è attivo
            if not user_profile.is_active:
                messages.error(request, 'Il tuo account è stato disattivato. Contatta l\'amministratore.')
                return render(request, 'Cripto1/login.html')
            
            # Controlla se l'account è bloccato
            if user_profile.is_locked():
                messages.error(request, 'Il tuo account è temporaneamente bloccato. Riprova più tardi.')
                return render(request, 'Cripto1/login.html')
            
        except UserProfile.DoesNotExist:
            # Se non esiste un profilo, continua con l'autenticazione normale
            pass
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Login riuscito
            try:
                user_profile = UserProfile.objects.get(user=user)
                
                # Verifica se l'utente ha 2FA abilitato
                if user_profile.two_factor_enabled:
                    # Salva l'ID utente in sessione e reindirizza alla verifica 2FA
                    request.session['user_id'] = user.id
                    return redirect('Cripto1:verify_2fa')
                
                # Se non ha 2FA, procedi con il login normale
                login(request, user)
                
                # Resetta i tentativi di login e aggiorna le informazioni
                user_profile.reset_login_attempts()
                user_profile.update_last_login(request.META.get('REMOTE_ADDR'))
                
                messages.success(request, "Benvenuto! Hai effettuato l'accesso con successo.", extra_tags='welcome_toast')
                return redirect('Cripto1:dashboard')
            except UserProfile.DoesNotExist:
                # Se non esiste un profilo, procedi con il login normale
                login(request, user)
                messages.success(request, "Benvenuto! Hai effettuato l'accesso con successo.", extra_tags='welcome_toast')
                return redirect('Cripto1:dashboard')
        else:
            # Login fallito
            try:
                user_profile = UserProfile.objects.get(user__username=username)
                user_profile.increment_login_attempts()
                
                # Log dell'evento di sicurezza
                AuditLog.log_action(
                    action_type='LOGIN',
                    description=f'Tentativo di login fallito per utente: {username}',
                    severity='HIGH',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message='Credenziali non valide'
                )
                
                if user_profile.is_locked():
                    messages.error(request, 'Troppi tentativi di login falliti. Il tuo account è stato temporaneamente bloccato.')
                else:
                    remaining_attempts = 5 - user_profile.login_attempts
                    messages.error(request, f'Credenziali non valide. Tentativi rimanenti: {remaining_attempts}')
                    
            except UserProfile.DoesNotExist:
                messages.error(request, 'Credenziali non valide')
            
    return render(request, 'Cripto1/login.html')

@login_required
def all_transactions_view(request):
    user_org = request.user.userprofile.organization
    
    # Se l'utente è un superuser, mostra tutte le transazioni della sua organizzazione
    if request.user.is_superuser:
        transactions_list = Transaction.objects.filter(
            sender__userprofile__organization=user_org,
            receiver__userprofile__organization=user_org
        ).order_by('-timestamp')
    else:
        # Altrimenti mostra solo le transazioni dell'utente corrente nella sua organizzazione
        transactions_list = Transaction.objects.filter(
            models.Q(sender__userprofile__organization=user_org) & 
            models.Q(receiver__userprofile__organization=user_org) &
            (models.Q(sender=request.user) | models.Q(receiver=request.user))
        ).order_by('-timestamp')

    for tx in transactions_list:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        # Determine direction for display
        if tx.sender == request.user:
            tx.direction = "Inviata"
        elif tx.receiver == request.user:
            tx.direction = "Ricevuta"
        else:
            # Per i superuser che visualizzano transazioni di altri utenti
            tx.direction = "Tra altri utenti"
    
    paginator = Paginator(transactions_list, 10) # Show 10 transactions per page
    page = request.GET.get('page')
    try:
        transactions = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        transactions = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        transactions = paginator.page(paginator.num_pages)

    context = {
        'all_transactions': transactions,
    }
    return render(request, 'Cripto1/all_transactions.html', context)

@login_required
def unviewed_transactions_list(request):
    user_org = request.user.userprofile.organization
    transactions_list = Transaction.objects.filter(
        receiver=request.user,
        is_viewed=False,
        sender__userprofile__organization=user_org
    ).order_by('-timestamp')

    for tx in transactions_list:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        tx.direction = "Ricevuta" # All these transactions are received
    
    paginator = Paginator(transactions_list, 10) # Show 10 transactions per page
    page = request.GET.get('page')
    try:
        transactions = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        transactions = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        transactions = paginator.page(paginator.num_pages)

    context = {
        'unviewed_transactions': transactions,
    }
    return render(request, 'Cripto1/unviewed_transactions.html', context)

@login_required
def dashboard(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    if created or not user_profile.public_key or not user_profile.private_key:
        user_profile.generate_key_pair()

    blockchain_state = BlockchainState.objects.first()
    percentage_mined = 0
    if blockchain_state and blockchain_state.max_supply > 0:
        percentage_mined = (blockchain_state.current_supply / blockchain_state.max_supply) * 100

    # Recupera i blocchi più recenti filtrati per organizzazione
    user_org = request.user.userprofile.organization
    latest_blocks = list(Block.objects.filter(organization=user_org).order_by('-index')[:10])
    for block in latest_blocks:
        block.timestamp_datetime = datetime.fromtimestamp(block.timestamp, tz=timezone.get_current_timezone())

    # Recupera le transazioni recenti filtrate correttamente per organizzazione
    user_transactions = []
    transactions_queryset = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user))
    ).order_by('-timestamp')[:10]
    for tx in transactions_queryset:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        user_transactions.append(tx)

    # Conta le transazioni in sospeso filtrate per organizzazione
    pending_count = Transaction.objects.filter(
        block__isnull=True,
        sender__userprofile__organization=user_org
    ).count()
    
    # Conta le transazioni ricevute e non ancora visualizzate filtrate per organizzazione
    unviewed_received_transactions_count = Transaction.objects.filter(
        receiver=request.user,
        is_viewed=False,
        sender__userprofile__organization=user_org
    ).count()
    
    # Dati per i grafici
    # Conteggio transazioni per tipo filtrate per organizzazione
    text_transactions_count = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        type='text'
    ).count()
    
    file_transactions_count = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        type='file'
    ).count()
    
    # Dati per il grafico dell'attività blockchain
    blocks_with_tx_count = []
    for block in latest_blocks:
        tx_count = block.transactions.count()
        blocks_with_tx_count.append({
            'index': block.index,
            'tx_count': tx_count
        })

    # Aggiungi queste righe prima di definire il context
    blockchain_info = None
    if blockchain_state:
        last_block = Block.objects.filter(organization=user_org).order_by('-index').first()
        first_block = Block.objects.filter(organization=user_org).order_by('index').first()  # Ottieni il primo blocco
        
        # Converti i timestamp in datetime
        if last_block:
            last_block.timestamp_datetime = datetime.fromtimestamp(last_block.timestamp, tz=timezone.get_current_timezone())
        if first_block:
            first_block.timestamp_datetime = datetime.fromtimestamp(first_block.timestamp, tz=timezone.get_current_timezone())
        
        # Verifica la validità della blockchain
        is_valid = True
        message = "Blockchain valida"
        
        # Verifica semplificata della blockchain
        if last_block and last_block.index > 1:
            current_block = last_block
            while current_block.index > 1:
                previous_block = Block.objects.filter(index=current_block.index - 1).first()
                if not previous_block or previous_block.hash != current_block.previous_hash:
                    is_valid = False
                    message = "Hash non corrispondenti"
                    break
                current_block = previous_block
        
        blockchain_info = {
            'blocks': Block.objects.filter(organization=user_org).count(),
            'transactions': Transaction.objects.filter(
                sender__userprofile__organization=user_org,
                receiver__userprofile__organization=user_org
            ).count(),
            'last_block_time': last_block.timestamp_datetime if last_block else None,
            'first_block_time': first_block.timestamp_datetime if first_block else None,
            'is_valid': is_valid,
            'validity_message': message
        }
    
    # Aggiungi questa verifica
    is_external_user = user_profile.has_role('external')
    
    context = {
        'user_profile': user_profile,
        'blockchain_state': blockchain_state,
        'blockchain_info': blockchain_info,  # Aggiungi questa riga
        'blocks': latest_blocks,
        'transactions': user_transactions,
        'percentage_mined': percentage_mined,
        'pending_count': pending_count,
        'unviewed_received_transactions_count': unviewed_received_transactions_count,
        'create_transaction_url': reverse('Cripto1:create_transaction'),
        'all_transactions_url': reverse('Cripto1:all_transactions'),
        'text_transactions_count': text_transactions_count,
        'file_transactions_count': file_transactions_count,
        'block_data': json.dumps(blocks_with_tx_count),
        'is_external_user': is_external_user,
    }
    return render(request, 'Cripto1/dashboard.html', context)

def calculate_hash(block_data):
    """Calculate the SHA-256 hash of a block"""
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def proof_of_work(last_proof, difficulty=3):
    """Simple proof of work algorithm with more secure nonce generation"""
    # Generate a random starting point for the nonce
    nonce = random.randint(1000000, 9999999)  # Start with a random 7-digit number
    
    while True:
        # Combine the last proof, nonce, and a timestamp for more randomness
        guess = f"{last_proof}{nonce}{time.time()}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        
        # Check if the hash meets the difficulty requirement (hardcoded to 3)
        if guess_hash[:difficulty] == '0' * difficulty:
            return nonce
        
        # Increment nonce by a random amount to make it less predictable
        nonce += random.randint(1, 1000)

from django.core.exceptions import ValidationError

@login_required
@external_forbidden
@user_manager_forbidden
def create_transaction(request):
    # Verifica se l'utente ha il ruolo "external"
    user_profile = UserProfile.objects.get(user=request.user)
    if user_profile.has_role('external'):
        return JsonResponse({'success': False, 'message': 'Gli utenti con ruolo "external" non possono inviare transazioni.'})
    
    if request.method == 'POST':
        try:
            transaction_type = request.POST.get('type')
            receiver_key = request.POST.get('receiver_key')
            content = request.POST.get('content', '')
            is_encrypted = request.POST.get('is_encrypted', 'false').lower() in ['true', 'on', '1']
            is_shareable = request.POST.get('is_shareable', 'false').lower() in ['true', 'on', '1']
            private_key_password = request.POST.get('private_key_password')
            max_downloads_str = request.POST.get('max_downloads')
            max_downloads = int(max_downloads_str) if max_downloads_str and max_downloads_str.isdigit() else None
            
            user_org = request.user.userprofile.organization
            receiver_profile = UserProfile.objects.filter(
                user_key=receiver_key,
                organization=user_org
            ).first()
            if not receiver_profile:
                return JsonResponse({'success': False, 'message': 'Receiver not found.'})
            receiver = receiver_profile.user

            # Cifratura del contenuto se richiesto (solo per testo)
            encrypted_content = content
            sender_encrypted_content = None
            if is_encrypted and transaction_type == 'text' and content:
                print(f"DEBUG: Original content length before encryption: {len(content.encode())} bytes")
                # Crittografia per il destinatario
                receiver_public_key = serialization.load_pem_public_key(
                    receiver_profile.public_key.encode(),
                    backend=default_backend()
                )
                encrypted_content = receiver_public_key.encrypt(
                    content.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex()
                
                # Crittografia per il mittente
                sender_public_key_obj = serialization.load_pem_public_key(
                    user_profile.public_key.encode(),
                    backend=default_backend()
                )
                sender_encrypted_content = sender_public_key_obj.encrypt(
                    content.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex()

            # Salva la chiave pubblica del mittente
            sender_public_key = user_profile.public_key

            # Create transaction data
            transaction_data = {
                'type': transaction_type,
                'sender': request.user.id,
                'receiver': receiver.id,
                'sender_public_key': sender_public_key,
                'content': encrypted_content,
                'sender_encrypted_content': sender_encrypted_content,
                'timestamp': time.time(),
                'is_encrypted': is_encrypted
            }
            
            # Aggiungi is_shareable solo per i file
            if transaction_type == 'file':
                transaction_data['is_shareable'] = is_shareable

            # Handle file upload if present
            if transaction_type == 'file' and request.FILES.get('file'):
                file = request.FILES['file']
                
                # Controllo sicurezza del file
                try:
                    from .validators import validate_file_security
                    validate_file_security(file)
                except ValidationError as e:
                    # Registra l'evento di sicurezza
                    AuditLog.log_action(
                        user=request.user,
                        action_type='SECURITY_EVENT',
                        description=f'Tentativo di caricamento file non sicuro in una transazione: {file.name}',
                        severity='HIGH',
                        additional_data={'error': str(e)},
                        success=False,
                        error_message=str(e)
                    )
                    return JsonResponse({'success': False, 'message': str(e)})
                
                file_content = file.read()
                encrypted_symmetric_key_for_db = None

                if is_encrypted:
                    try:
                        # Generate a symmetric key for file encryption
                        symmetric_key = Fernet.generate_key()
                        print(f"DEBUG: Generated symmetric_key type: {type(symmetric_key)}, value: {symmetric_key[:5]}...") # print first few bytes
                        f = Fernet(symmetric_key)
                        encrypted_file_content = f.encrypt(file_content)
                        print(f"DEBUG: File content encrypted with symmetric key. Encrypted length: {len(encrypted_file_content)}")

                        # Encrypt the symmetric key with the receiver's public RSA key
                        print(f"DEBUG: Receiver public key (from DB): {receiver_profile.public_key[:50]}...") # print first 50 chars
                        receiver_public_key = serialization.load_pem_public_key(
                            receiver_profile.public_key.encode(),
                            backend=default_backend()
                        )
                        print(f"DEBUG: Receiver public key loaded successfully.")
                        encrypted_symmetric_key_for_db = receiver_public_key.encrypt(
                            symmetric_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        # Encrypt symmetric key for sender
                        sender_public_key_obj = serialization.load_pem_public_key(
                            user_profile.public_key.encode(),
                            backend=default_backend()
                        )
                        sender_encrypted_symmetric_key = sender_public_key_obj.encrypt(
                            symmetric_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        print(f"DEBUG: Symmetric key encrypted with RSA. Encrypted length: {len(encrypted_symmetric_key_for_db)}")
                        filename = f"{uuid.uuid4().hex}.encrypted"
                        file_to_save = ContentFile(encrypted_file_content)
                        transaction_data['original_filename'] = file.name # Store original filename for encrypted files
                        transaction_data['encrypted_symmetric_key'] = encrypted_symmetric_key_for_db.hex() # Store as hex string for JSON serialization
                        transaction_data['sender_encrypted_symmetric_key'] = sender_encrypted_symmetric_key.hex() # Store sender's encrypted key
                        transaction_data['receiver_public_key_at_encryption'] = receiver_profile.public_key # Store receiver's public key at time of encryption

                    except Exception as e:
                        print(f"ERROR: Exception during file encryption: {e}") # More detailed error logging
                        return JsonResponse({'success': False, 'message': f'Errore durante la cifratura del file: {str(e)}'})
                else:
                    filename = f"{time.time()}_{file.name}"
                    file_to_save = ContentFile(file_content)

                file_path = default_storage.save(f'transaction_files/{filename}', file_to_save)
                transaction_data['file'] = file_path

            # Calculate transaction hash
            transaction_string_for_signing = json.dumps(transaction_data, sort_keys=True).encode()
            print(f"[DEBUG SIGNING] transaction_data: {transaction_data}")
            print(f"[DEBUG SIGNING] transaction_string_for_signing: {transaction_string_for_signing}")
            transaction_hash = hashlib.sha256(transaction_string_for_signing).hexdigest()
            
            # Sign the transaction
            private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
            if not private_key:
                return JsonResponse({
                    'success': False,
                    'message': 'Errore durante il recupero della chiave privata.'
                })
            
            data_to_sign = transaction_hash.encode()
            signature = private_key.sign(
                data_to_sign,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Create transaction
            new_tx = Transaction.objects.create(
                type=transaction_type,
                sender=request.user,
                receiver=receiver,
                sender_public_key=sender_public_key,
                content=encrypted_content,
                sender_encrypted_content=transaction_data.get('sender_encrypted_content'),
                file=transaction_data.get('file'),
                timestamp=transaction_data['timestamp'],
                transaction_hash=transaction_hash,
                signature=signature.hex(),
                is_encrypted=is_encrypted,
                is_shareable=transaction_data.get('is_shareable', False),
                original_filename=transaction_data.get('original_filename', ''), # Save original filename if present
                # Convert back to bytes for BinaryField
                encrypted_symmetric_key=bytes.fromhex(transaction_data['encrypted_symmetric_key']) if 'encrypted_symmetric_key' in transaction_data and transaction_data['encrypted_symmetric_key'] else None,
                sender_encrypted_symmetric_key=bytes.fromhex(transaction_data['sender_encrypted_symmetric_key']) if 'sender_encrypted_symmetric_key' in transaction_data and transaction_data['sender_encrypted_symmetric_key'] else None,
                receiver_public_key_at_encryption=transaction_data.get('receiver_public_key_at_encryption', ''),
                max_downloads=max_downloads
            )

            # Invia notifiche email
            try:
                # Email al mittente
                send_transaction_notification(new_tx, request.user, request, direction='sent')
                
                # Email al destinatario
                send_transaction_notification(new_tx, receiver, request, direction='received')
            except Exception as e:
                print(f"Errore nell'invio delle notifiche email per la transazione {new_tx.id}: {str(e)}")

            # Add to pending transactions
            pending_transactions_ids = request.session.get('pending_transactions_ids', [])
            pending_transactions_ids.append(new_tx.id)
            request.session['pending_transactions_ids'] = pending_transactions_ids

            return JsonResponse({
                'success': True,
                'message': 'Transazione creata e firmata. In attesa di mining. Notifiche email inviate.',
                'requires_mining': True,
                'pending_count': len(pending_transactions_ids)
            })

        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            })

    # Se GET, mostra il form
    return render(request, 'Cripto1/create_transaction.html')

@login_required
@external_forbidden
@csrf_exempt
def mine_block(request):
    if request.method == 'POST':
        user_org = request.user.userprofile.organization
        # Recupera tutte le transazioni non ancora incluse in un blocco per l'organizzazione
        pending_transactions = Transaction.objects.filter(
            block__isnull=True,
            sender__userprofile__organization=user_org
        )
        if not pending_transactions.exists():
            return JsonResponse({'success': False, 'message': 'Nessuna transazione in sospeso da minare.'})

        # Recupera l'ultimo blocco dell'organizzazione
        last_block = Block.objects.filter(organization=user_org).order_by('-index').first()
        index = 1 if not last_block else last_block.index + 1
        previous_hash = '0' * 64 if not last_block else last_block.hash
        timestamp = time.time()

        # Calcola la radice di Merkle (qui semplificata come hash concatenato delle transazioni)
        tx_hashes = [tx.transaction_hash for tx in pending_transactions]
        merkle_root = hashlib.sha256(''.join(tx_hashes).encode()).hexdigest() if tx_hashes else ''

        # Proof of Work: trova un nonce tale che l'hash inizi con 3 zeri (hardcoded)
        nonce = 0
        while True:
            block_data = {
                'index': index,
                'timestamp': timestamp,
                'proof': str(nonce),
                'previous_hash': previous_hash,
                'nonce': str(nonce),
                'merkle_root': merkle_root,
            }
            block_hash = calculate_hash(block_data)
            if block_hash.startswith('000'):  # 3 zeri hardcoded
                break
            nonce += 1

        # Crea il nuovo blocco
        new_block = Block.objects.create(
            index=index,
            timestamp=timestamp,
            proof=str(nonce),
            previous_hash=previous_hash,
            hash=block_hash,
            nonce=str(nonce),
            merkle_root=merkle_root,
            organization=user_org,
        )

        # Associa le transazioni al nuovo blocco
        pending_transactions.update(block=new_block)
        
        # Recupera le transazioni appena associate al blocco per l'invio delle email
        block_transactions = Transaction.objects.filter(block=new_block)
        
        # Invia email di CONFERMA BLOCCO a tutti gli utenti coinvolti
        try:
            send_block_confirmation_emails(new_block, block_transactions)
        except Exception as e:
            print(f"Errore nell'invio delle email di conferma blocco #{index}: {str(e)}")

        return JsonResponse({
            'success': True, 
            'message': f'Blocco #{index} creato con successo con PoW! Nonce trovato: {nonce}. Email di conferma inviate.', 
            'block_index': index, 
            'nonce': nonce
        })
    else:
        return JsonResponse({'success': False, 'message': 'Method not allowed'})

def calculate_merkle_root(transactions_hashes):
    if not transactions_hashes:
        return ""

    # If odd number of hashes, duplicate the last one
    if len(transactions_hashes) % 2 != 0:
        transactions_hashes.append(transactions_hashes[-1])

    # Recursively calculate parent hashes
    new_level_hashes = []
    for i in range(0, len(transactions_hashes), 2):
        combined_hashes = transactions_hashes[i] + transactions_hashes[i+1]
        new_hash = hashlib.sha256(combined_hashes.encode()).hexdigest()
        new_level_hashes.append(new_hash)

    # If we are down to a single hash, it's the Merkle root
    if len(new_level_hashes) == 1:
        return new_level_hashes[0]
    else:
        # Otherwise, recurse with the new level of hashes
        return calculate_merkle_root(new_level_hashes)

@login_required
@csrf_exempt
def decrypt_transaction(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            transaction_id = data.get('transaction_id')
            password = data.get('password', 'securepassword').encode()  # default per retrocompatibilità
            tx = Transaction.objects.get(id=transaction_id)
            user_profile = UserProfile.objects.get(user=request.user)

            if tx.sender != request.user and tx.receiver != request.user:
                return JsonResponse({
                    'success': False,
                    'message': 'Non sei autorizzato a decriptare questa transazione'
                })

            decrypted_content = None
            if tx.is_encrypted and tx.type == 'text':
                if tx.receiver == request.user:
                    # Decrittazione per il destinatario
                    decrypted_content = user_profile.decrypt_message(tx.content, password=password)
                elif tx.sender == request.user and tx.sender_encrypted_content:
                    # Decrittazione per il mittente
                    decrypted_content = user_profile.decrypt_message(tx.sender_encrypted_content, password=password)
                else:
                    decrypted_content = tx.content
            else:
                decrypted_content = tx.content

            return JsonResponse({
                'success': True,
                'decrypted_content': decrypted_content,
                'sender': tx.sender.id
            })

        except Transaction.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Transazione non trovata'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            })

    return JsonResponse({'success': False, 'message': 'Metodo non consentito'})

@login_required
def get_blockchain_stats(request):
    blockchain_state = BlockchainState.objects.first()
    return JsonResponse({
        'current_supply': blockchain_state.current_supply,
        'max_supply': blockchain_state.max_supply,
        'current_reward': blockchain_state.current_reward,
        'halving_count': blockchain_state.halving_count,
        'percentage_mined': (blockchain_state.current_supply / blockchain_state.max_supply) * 100
    })

def index(request):
    if request.user.is_authenticated:
        return redirect('Cripto1:dashboard')
    return render(request, 'Cripto1/index.html')

def landing_page_view(request):
    if request.user.is_authenticated:
        return redirect('Cripto1:dashboard')  # Redirect to original dashboard
    else:
        return render(request, 'Cripto1/landing_page.html')

@login_required
@external_forbidden
def users_feed(request):
    # I superuser vedono tutti gli utenti, gli altri solo della loro organizzazione
    if request.user.is_superuser:
        users = UserProfile.objects.all().select_related('user', 'organization')
    else:
        user_org = request.user.userprofile.organization
        users = UserProfile.objects.filter(organization=user_org).select_related('user')
    
    context = {
        'users': users,
    }
    return render(request, 'Cripto1/users_feed.html', context)

def logout_view(request):
    if request.method == 'POST':
        logout(request)
        messages.success(request, "You have been logged out.")
    return redirect('Cripto1:home') # Redirect to home page after logout



@login_required
def personal_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    if not user_profile.public_key or not user_profile.private_key:
        user_profile.generate_key_pair()
        user_profile.refresh_from_db()
    
    # Recupera solo le transazioni recenti per la pagina del profilo filtrate per organizzazione
    user_org = request.user.userprofile.organization
    recent_transactions = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user))
    ).order_by('-timestamp')[:5] # Limit to 5 recent transactions
    
    processed_recent_transactions = []
    for tx in recent_transactions:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        if tx.receiver == request.user:
            tx.direction = 'Ricevuta'
        elif tx.sender == request.user:
            tx.direction = 'Inviata'
        else:
            tx.direction = 'Sconosciuta'
        processed_recent_transactions.append(tx)

    context = {
        'user_profile': user_profile,
        'recent_transactions': processed_recent_transactions,
        'organization_registration_code': user_org.registration_code if user_org else None,
    }
    return render(request, 'Cripto1/personal_profile.html', context)

@login_required
def transaction_details(request, transaction_id):
    tx = get_object_or_404(Transaction, id=transaction_id)
    
    # Check if user is either sender or receiver or a superuser
    if request.user != tx.sender and request.user != tx.receiver and not request.user.is_superuser:
        messages.error(request, 'You do not have permission to view this transaction.')
        return redirect('Cripto1:dashboard')
    
    # Convert timestamp to datetime
    tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())

    # Mark as viewed if the current user is the receiver and it's not already viewed
    if request.user == tx.receiver and not tx.is_viewed:
        tx.is_viewed = True
        tx.save()

    # Verify signature
    is_valid = tx.verify_signature()
    
    context = {
        'transaction': tx,
        'is_valid': is_valid,
        'is_sender': request.user == tx.sender,
        'is_receiver': request.user == tx.receiver,
        'is_superuser': request.user.is_superuser,
    }
    
    return render(request, 'Cripto1/transaction_details.html', context)

@login_required
def download_file(request, transaction_id):
    tx = get_object_or_404(Transaction, id=transaction_id)
    
    # Check if user is either sender or receiver or a superuser
    if request.user != tx.sender and request.user != tx.receiver and not request.user.is_superuser:
        messages.error(request, 'You do not have permission to download this file.')
        return redirect('Cripto1:dashboard')
    
    if not tx.file:
        messages.error(request, 'No file associated with this transaction.')
        return redirect('Cripto1:transaction_details', transaction_id=transaction_id)
    
    # Check download limits
    if tx.max_downloads is not None:
        if tx.current_downloads >= tx.max_downloads:
            messages.error(request, 'Questo file ha raggiunto il numero massimo di download consentiti.')
            return redirect('Cripto1:transaction_details', transaction_id=transaction_id)

    user_profile = request.user.userprofile

    if tx.is_encrypted:
        # Ensure only the receiver can download encrypted files
        if request.user != tx.receiver:
            messages.error(request, 'Non sei autorizzato a decifrare e scaricare questo file.')
            return redirect('Cripto1:dashboard')

        # Check if the receiver's current public key matches the one used for encryption
        if user_profile.public_key != tx.receiver_public_key_at_encryption:
            messages.error(request, 'Impossibile decifrare il file. La chiave pubblica del destinatario è cambiata dopo la cifratura della transazione.')
            return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})

        if request.method == 'POST':
            private_key_password = request.POST.get('private_key_password')
            if not private_key_password:
                messages.error(request, 'Inserisci la password della chiave privata.')
                return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})

            try:
                # Read the encrypted file content
                with default_storage.open(tx.file.name, 'rb') as f:
                    encrypted_file_content = f.read()
                print(f"DEBUG: Encrypted file content length: {len(encrypted_file_content)}")
                
                # Decrypt the symmetric key with the user's private RSA key
                decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                if not decrypted_private_key:
                    messages.error(request, 'Password della chiave privata errata.')
                    return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})
                
                print(f"DEBUG: Encrypted symmetric key (from DB): {tx.encrypted_symmetric_key[:10]}...") # First 10 bytes
                
                # Converti memoryview in bytes prima della decifratura RSA
                encrypted_symmetric_key_bytes = bytes(tx.encrypted_symmetric_key) if isinstance(tx.encrypted_symmetric_key, memoryview) else tx.encrypted_symmetric_key
                
                # Use the RSA private key to decrypt the symmetric key
                symmetric_key = decrypted_private_key.decrypt(
                    encrypted_symmetric_key_bytes,  # Usa la versione convertita in bytes
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"DEBUG: Symmetric key decrypted. Length: {len(symmetric_key)}, value: {symmetric_key[:10]}...") # First 10 bytes
                
                # Decrypt the file content with the symmetric key
                f = Fernet(symmetric_key)
                decrypted_content = f.decrypt(encrypted_file_content)
                print(f"DEBUG: File content decrypted successfully. Length: {len(decrypted_content)}")

                if decrypted_content is None:
                    messages.error(request, 'Errore di decifratura del contenuto del file.')
                    return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})

                # Serve the decrypted file with its original filename
                response = HttpResponse(decrypted_content, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{tx.original_filename}"'
                
                # Increment download count for encrypted files
                if tx.max_downloads is not None:
                    tx.current_downloads += 1
                    tx.save()
                
                return response

            except Exception as e:
                print(f"ERROR: Exception type during decryption/download: {type(e).__name__}") # Added for more specific error
                print(f"ERROR: Exception during decryption/download: {e}") # More detailed error logging
                messages.error(request, f'Errore durante la decifratura o il download del file: {str(e)}')
                return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})
        else:
            # If GET request for an encrypted file, show the password form
            return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})
    else:
        # If not encrypted, proceed with the existing download logic
        file_path = tx.file.path
        file_name = os.path.basename(file_path) # Or tx.original_filename if you want to save original name for unencrypted too
        
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            
            # Increment download count for unencrypted files
            if tx.max_downloads is not None:
                tx.current_downloads += 1
                tx.save()

            return response

@login_required
def view_transaction_file(request, transaction_id):
    tx = get_object_or_404(Transaction, id=transaction_id)
    
    # Check if user is either sender or receiver or a superuser
    if request.user != tx.sender and request.user != tx.receiver and not request.user.is_superuser:
        messages.error(request, 'Non hai il permesso di visualizzare questo file.')
        return redirect('Cripto1:dashboard')
    
    if not tx.file:
        messages.error(request, 'Nessun file associato a questa transazione.')
        return redirect('Cripto1:transaction_details', transaction_id=transaction_id)
    
    # Check download limits
    if tx.max_downloads is not None:
        if tx.current_downloads >= tx.max_downloads:
            messages.error(request, 'Questo file ha raggiunto il numero massimo di visualizzazioni consentite.')
            return redirect('Cripto1:transaction_details', transaction_id=transaction_id)

    # Controlla le estensioni supportate per la visualizzazione
    filename = tx.original_filename if hasattr(tx, 'original_filename') and tx.original_filename else os.path.basename(tx.file.name)
    file_extension = os.path.splitext(filename)[1].lower()
    
    # Lista delle estensioni che possono essere visualizzate nel browser
    viewable_extensions = ['.pdf', '.txt', '.csv', '.png', '.jpg', '.jpeg', '.gif']
    
    if file_extension not in viewable_extensions:
        messages.warning(request, f'Il formato {file_extension} non può essere visualizzato direttamente. Utilizzare l\'opzione di download.')
        return redirect('Cripto1:transaction_details', transaction_id=transaction_id)

    user_profile = request.user.userprofile

    if tx.is_encrypted:
        # Ensure only the receiver can view encrypted files
        if request.user != tx.receiver:
            messages.error(request, 'Non sei autorizzato a decifrare e visualizzare questo file.')
            return redirect('Cripto1:dashboard')

        # Check if the receiver's current public key matches the one used for encryption
        if user_profile.public_key != tx.receiver_public_key_at_encryption:
            messages.error(request, 'Impossibile decifrare il file. La chiave pubblica del destinatario è cambiata dopo la cifratura della transazione.')
            return render(request, 'Cripto1/view_transaction_file.html', {'transaction': tx})

        if request.method == 'POST':
            private_key_password = request.POST.get('private_key_password')
            if not private_key_password:
                messages.error(request, 'Inserisci la password della chiave privata.')
                return render(request, 'Cripto1/view_transaction_file.html', {'transaction': tx})

            try:
                # Read the encrypted file content
                with default_storage.open(tx.file.name, 'rb') as f:
                    encrypted_file_content = f.read()
                
                # Decrypt the symmetric key with the user's private RSA key
                decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                if not decrypted_private_key:
                    messages.error(request, 'Password della chiave privata errata.')
                    return render(request, 'Cripto1/view_transaction_file.html', {'transaction': tx})
                
                # Converti memoryview in bytes prima della decifratura RSA
                encrypted_symmetric_key_bytes = bytes(tx.encrypted_symmetric_key) if isinstance(tx.encrypted_symmetric_key, memoryview) else tx.encrypted_symmetric_key
                
                # Use the RSA private key to decrypt the symmetric key
                symmetric_key = decrypted_private_key.decrypt(
                    encrypted_symmetric_key_bytes,  # Usa la versione convertita in bytes
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt the file content with the symmetric key
                f = Fernet(symmetric_key)
                decrypted_content = f.decrypt(encrypted_file_content)

                # Determina il content type appropriato
                if file_extension == '.pdf':
                    content_type = 'application/pdf'
                elif file_extension == '.txt':
                    content_type = 'text/plain'
                elif file_extension == '.csv':
                    content_type = 'text/csv'
                elif file_extension in ['.png', '.jpg', '.jpeg', '.gif']:
                    content_type = f'image/{file_extension[1:]}'
                else:
                    content_type = 'application/octet-stream'
                
                # Increment view count for encrypted files
                if tx.max_downloads is not None:
                    tx.current_downloads += 1
                    tx.save()
                
                # Restituisci il contenuto per la visualizzazione inline
                response = HttpResponse(decrypted_content, content_type=content_type)
                response['Content-Disposition'] = f'inline; filename="{filename}"'
                return response

            except Exception as e:
                messages.error(request, f'Errore durante la decifratura o la visualizzazione del file: {str(e)}')
                return render(request, 'Cripto1/view_transaction_file.html', {'transaction': tx})
        else:
            # If GET request for an encrypted file, show the password form
            return render(request, 'Cripto1/view_transaction_file.html', {'transaction': tx})
    else:
        # If not encrypted, proceed with the existing view logic
        file_path = tx.file.path
        
        # Determina il content type appropriato
        if file_extension == '.pdf':
            content_type = 'application/pdf'
        elif file_extension == '.txt':
            content_type = 'text/plain'
        elif file_extension == '.csv':
            content_type = 'text/csv'
        elif file_extension in ['.png', '.jpg', '.jpeg', '.gif']:
            content_type = f'image/{file_extension[1:]}'
        else:
            content_type = 'application/octet-stream'
        
        # Increment view count for unencrypted files
        if tx.max_downloads is not None:
            tx.current_downloads += 1
            tx.save()
        
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type=content_type)
            response['Content-Disposition'] = f'inline; filename="{os.path.basename(file_path)}"'
            return response

@login_required
def edit_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    if request.method == 'POST':
        form = UserProfileEditForm(request.POST, request.FILES, instance=user_profile)
        print("Form is valid:", form.is_valid())
        if not form.is_valid():
            print("Form errors:", form.errors)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profilo aggiornato con successo')
            return redirect('Cripto1:personal_profile')
    else:
        form = UserProfileEditForm(instance=user_profile)
    return render(request, 'Cripto1/edit_profile.html', {'form': form, 'user_profile': user_profile})

@staff_member_required
def admin_dashboard(request):
    # I superuser vedono tutti gli utenti, gli altri solo della loro organizzazione
    if request.user.is_superuser:
        user_profiles = UserProfile.objects.all().select_related('user', 'organization')
        total_users = User.objects.count()
        total_transactions = Transaction.objects.count()
        total_blocks = Block.objects.count()
        
        # Per i grafici, i superuser vedono dati globali
        user_activity_data = []
        for profile in user_profiles[:10]:  # Limita a 10 per il grafico
            sent_count = Transaction.objects.filter(sender=profile.user).count()
            received_count = Transaction.objects.filter(receiver=profile.user).count()
            user_activity_data.append({
                'username': profile.user.username,
                'sent': sent_count,
                'received': received_count
            })
            
        # Dati distribuzione transazioni globali
        transaction_distribution_data = {
            'text_count': Transaction.objects.filter(type='text').count(),
            'file_count': Transaction.objects.filter(type='file').count(),
            'encrypted_count': Transaction.objects.filter(is_encrypted=True).count(),
            'unencrypted_count': Transaction.objects.filter(is_encrypted=False).count(),
        }
        
    else:
        user_org = request.user.userprofile.organization
        user_profiles = UserProfile.objects.filter(organization=user_org).select_related('user', 'organization')
        total_users = User.objects.filter(userprofile__organization=user_org).count()
        total_transactions = Transaction.objects.filter(
            sender__userprofile__organization=user_org,
            receiver__userprofile__organization=user_org
        ).count()
        total_blocks = Block.objects.filter(organization=user_org).count()
        
        # Per gli admin di org, dati filtrati per organizzazione
        user_activity_data = []
        for profile in user_profiles[:10]:
            sent_count = Transaction.objects.filter(
                sender=profile.user,
                receiver__userprofile__organization=user_org
            ).count()
            received_count = Transaction.objects.filter(
                receiver=profile.user,
                sender__userprofile__organization=user_org
            ).count()
            user_activity_data.append({
                'username': profile.user.username,
                'sent': sent_count,
                'received': received_count
            })
            
        # Dati distribuzione transazioni per organizzazione
        org_transactions = Transaction.objects.filter(
            sender__userprofile__organization=user_org,
            receiver__userprofile__organization=user_org
        )
        transaction_distribution_data = {
            'text_count': org_transactions.filter(type='text').count(),
            'file_count': org_transactions.filter(type='file').count(),
            'encrypted_count': org_transactions.filter(is_encrypted=True).count(),
            'unencrypted_count': org_transactions.filter(is_encrypted=False).count(),
        }

    # Get active addresses (last 24 hours) - Temporarily commented out due to TypeError
    # now = timezone.now()
    # day_ago = now - timezone.timedelta(days=1)
    # active_addresses = Transaction.objects.filter(
    #     timestamp__gte=day_ago
    # ).values('sender', 'receiver').distinct().count()
    active_addresses = "N/A" # Placeholder value

    # Get total transaction volume
    total_volume = 0  # Il campo 'amount' non esiste, quindi imposto a 0 o placeholder
    
    # Dati per i grafici
    
    # Crescita blockchain negli ultimi 30 giorni
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)
    
    # Prepara i dati per il grafico di crescita
    blockchain_growth_data = []
    current_date = start_date
    while current_date <= end_date:
        next_date = current_date + timedelta(days=1)
        
        if request.user.is_superuser:
            # Conta i blocchi creati in questo giorno (globali)
            day_blocks = Block.objects.filter(
                timestamp__gte=current_date.timestamp(),
                timestamp__lt=next_date.timestamp()
            ).count()
            
            # Conta le transazioni create in questo giorno (globali)
            day_transactions = Transaction.objects.filter(
                timestamp__gte=current_date.timestamp(),
                timestamp__lt=next_date.timestamp()
            ).count()
        else:
            # Conta i blocchi creati in questo giorno (per organizzazione)
            day_blocks = Block.objects.filter(
                organization=user_org,
                timestamp__gte=current_date.timestamp(),
                timestamp__lt=next_date.timestamp()
            ).count()
            
            # Conta le transazioni create in questo giorno (per organizzazione)
            day_transactions = Transaction.objects.filter(
                sender__userprofile__organization=user_org,
                receiver__userprofile__organization=user_org,
                timestamp__gte=current_date.timestamp(),
                timestamp__lt=next_date.timestamp()
            ).count()
        
        blockchain_growth_data.append({
            'date': current_date.strftime('%d/%m'),
            'blocks': day_blocks,
            'transactions': day_transactions
        })
        
        current_date = next_date
    
    # Difficoltà mining nel tempo (rimossa perché il campo difficulty non esiste)
    mining_difficulty_data = []

    context = {
        'total_users': total_users,
        'total_transactions': total_transactions,
        'total_blocks': total_blocks,
        'active_addresses': active_addresses,
        'total_volume': total_volume,
        'user_profiles': user_profiles,
        'blockchain_growth_data': json.dumps(blockchain_growth_data),
        'transaction_distribution_data': json.dumps(transaction_distribution_data),
        'user_activity_data': json.dumps(user_activity_data),
    }
    return render(request, 'Cripto1/admin_dashboard.html', context)

@login_required
def verify_blockchain(request):
    # Verifica che l'utente sia staff o admin di organizzazione
    user_profile = request.user.userprofile
    if not request.user.is_staff and not user_profile.has_role('Organization Admin'):
        return JsonResponse({
            'is_valid': False,
            'message': 'Non hai i permessi per verificare la blockchain.'
        })

    # Ottieni l'organizzazione dell'utente
    user_org = request.user.userprofile.organization
    
    # Verifica solo i blocchi dell'organizzazione
    last_block = Block.objects.filter(organization=user_org).order_by('-index').first()
    if not last_block:
        return JsonResponse({'is_valid': True, 'message': 'Blockchain vuota, considerata valida.'})

    # Start verification from the second to last block
    current_block = last_block
    while current_block.index > 1:
        # Cerca il blocco precedente nell'organizzazione
        previous_block = Block.objects.filter(
            organization=user_org,
            index=current_block.index - 1
        ).first()

        # Check if previous block exists and if hashes match
        if not previous_block or previous_block.hash != current_block.previous_hash:
            return JsonResponse({
                'is_valid': False,
                'message': f'Blockchain non valida: Hash del blocco precedente {current_block.index-1} non corrisponde al previous_hash del blocco {current_block.index}.'
            })

        # Recalculate the hash using the EXACT same structure as mining
        previous_block_data = {
            'index': previous_block.index,
            'timestamp': previous_block.timestamp,
            'proof': str(previous_block.proof),
            'previous_hash': previous_block.previous_hash,
            'nonce': str(previous_block.nonce),
            'merkle_root': previous_block.merkle_root if previous_block.merkle_root is not None else '',
        }
        recalculated_hash = calculate_hash(previous_block_data)

        # Debug per verificare il calcolo dell'hash
        print(f"DEBUG - Blocco {previous_block.index}:")
        print(f"  Hash memorizzato: {previous_block.hash}")
        print(f"  Hash ricalcolato: {recalculated_hash}")
        print(f"  Dati usati: {previous_block_data}")
        
        if recalculated_hash != previous_block.hash:
             return JsonResponse({
                'is_valid': False,
                'message': f'Blockchain non valida: Hash ricalcolato per il blocco {previous_block.index} non corrisponde all\'hash memorizzato.'
            })

        current_block = previous_block

    # Check the genesis block's previous_hash (should be all zeros)
    genesis_block = Block.objects.filter(organization=user_org, index=1).first()
    if genesis_block and genesis_block.previous_hash != '0' * 64:
         return JsonResponse({
            'is_valid': False,
            'message': 'Blockchain non valida: Il previous_hash del genesis block non è corretto.'
        })

    return JsonResponse({'is_valid': True, 'message': 'Blockchain verificata con successo! L\'integrità è confermata.'})

@staff_member_required
def export_csv(request, model):
    model_map = {
        'userprofile': UserProfile,
        'transaction': Transaction,
        'block': Block,
        'blockchainstate': BlockchainState,
        'smartcontract': SmartContract
    }
    
    if model not in model_map:
        return HttpResponse("Model not found", status=404)
    
    Model = model_map[model]
    queryset = Model.objects.all()
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{model}.csv"'
    
    writer = csv.writer(response)
    # Write headers
    writer.writerow([field.name for field in Model._meta.fields])
    
    # Write data
    for obj in queryset:
        writer.writerow([getattr(obj, field.name) for field in Model._meta.fields])
    
    return response

@staff_member_required
def admin_user_detail(request, user_id):
    user_profile = get_object_or_404(UserProfile, user__id=user_id)
    user = user_profile.user
    # Statistiche transazioni
    sent_count = user.sent_transactions.count()
    received_count = user.received_transactions.count()
    total_transactions = sent_count + received_count
    # Blocchi in cui l'utente è coinvolto
    blocks = Block.objects.filter(transactions__sender=user).distinct() | Block.objects.filter(transactions__receiver=user).distinct()
    blocks = blocks.distinct()
    blocks_count = blocks.count()
    # Peso movimenti: se non hai un campo amount, mostra solo il numero
    # Se hai un campo amount, puoi sommare qui
    # Esempio: total_weight = user.sent_transactions.aggregate(Sum('amount'))['amount__sum'] or 0
    # Qui mostro solo il numero di transazioni
    total_weight = total_transactions
    # Gestione credenziali
    if request.method == 'POST':
        if 'reset_password' in request.POST:
            form = PasswordResetForm({'email': user.email})
            if form.is_valid():
                form.save(request=request, use_https=request.is_secure(),
                          email_template_name='registration/password_reset_email.html')
                messages.success(request, 'Email di reset password inviata!')
        elif 'update_user' in request.POST:
            form = UserChangeForm(request.POST, instance=user)
            if form.is_valid():
                form.save()
                messages.success(request, 'Dati utente aggiornati!')
        elif 'update_permissions' in request.POST:
            # Assicurati che solo un superuser possa modificare i permessi di staff/superuser
            if not request.user.is_superuser:
                messages.error(request, 'Non hai i permessi per modificare lo status di superuser/staff.')
            else:
                # Aggiorna lo status is_staff e is_superuser
                user.is_staff = 'is_staff' in request.POST
                user.is_superuser = 'is_superuser' in request.POST
                user.save()
                messages.success(request, 'Permessi utente aggiornati con successo!')

        return redirect('Cripto1:admin_user_detail', user_id=user.id)
    else:
        form = UserChangeForm(instance=user)
    context = {
        'user_profile': user_profile,
        'user': user,
        'sent_count': sent_count,
        'received_count': received_count,
        'total_transactions': total_transactions,
        'blocks_count': blocks_count,
        'total_weight': total_weight,
        'form': form,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
    }
    return render(request, 'Cripto1/admin_user_detail.html', context)



# ==================== AUDIT LOG VIEWS ====================

@staff_member_required
def audit_logs_view(request):
    """Vista principale per visualizzare gli audit log"""
    
    # Parametri di filtro
    action_type = request.GET.get('action_type', '')
    severity = request.GET.get('severity', '')
    user_id = request.GET.get('user_id', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    success_only = request.GET.get('success_only', '')
    
    # Query base
    queryset = AuditLog.objects.select_related('user').all()
    
    # Applica filtri
    if action_type:
        queryset = queryset.filter(action_type=action_type)
    if severity:
        queryset = queryset.filter(severity=severity)
    if user_id:
        queryset = queryset.filter(user_id=user_id)
    if date_from:
        try:
            date_from_obj = timezone.strptime(date_from, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__gte=date_from_obj.date())
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = timezone.strptime(date_to, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__lte=date_to_obj.date())
        except ValueError:
            pass
    if success_only == 'true':
        queryset = queryset.filter(success=True)
    
    # Statistiche
    total_logs = queryset.count()
    success_count = queryset.filter(success=True).count()
    error_count = total_logs - success_count
    
    # Statistiche per severità
    severity_stats = queryset.values('severity').annotate(count=models.Count('id'))
    
    # Statistiche per tipo di azione
    action_stats = queryset.values('action_type').annotate(count=models.Count('id')).order_by('-count')[:10]
    
    # Paginazione
    paginator = Paginator(queryset, 50)  # 50 log per pagina
    page = request.GET.get('page')
    try:
        logs = paginator.page(page)
    except PageNotAnInteger:
        logs = paginator.page(1)
    except EmptyPage:
        logs = paginator.page(paginator.num_pages)
    
    # Lista utenti per il filtro
    users = User.objects.filter(audit_logs__isnull=False).distinct()
    
    context = {
        'logs': logs,
        'total_logs': total_logs,
        'success_count': success_count,
        'error_count': error_count,
        'severity_stats': severity_stats,
        'action_stats': action_stats,
        'users': users,
        'action_types': AuditLog.ACTION_TYPES,
        'severity_levels': AuditLog.SEVERITY_LEVELS,
        'filters': {
            'action_type': action_type,
            'severity': severity,
            'user_id': user_id,
            'date_from': date_from,
            'date_to': date_to,
            'success_only': success_only,
        }
    }
    
    return render(request, 'Cripto1/audit_logs.html', context)

@staff_member_required
def audit_log_detail(request, log_id):
    """Vista dettagliata di un singolo audit log"""
    log = get_object_or_404(AuditLog, id=log_id)
    
    # Ottieni l'oggetto correlato se esiste
    related_object = log.get_related_object()
    
    context = {
        'log': log,
        'related_object': related_object,
    }
    
    return render(request, 'Cripto1/audit_log_detail.html', context)

@staff_member_required
def export_audit_logs(request):
    """Export degli audit log in CSV"""
    
    # Parametri di filtro (stessi della vista principale)
    action_type = request.GET.get('action_type', '')
    severity = request.GET.get('severity', '')
    user_id = request.GET.get('user_id', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    success_only = request.GET.get('success_only', '')
    
    # Query base
    queryset = AuditLog.objects.select_related('user').all()
    
    # Applica filtri
    if action_type:
        queryset = queryset.filter(action_type=action_type)
    if severity:
        queryset = queryset.filter(severity=severity)
    if user_id:
        queryset = queryset.filter(user_id=user_id)
    if date_from:
        try:
            date_from_obj = timezone.strptime(date_from, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__gte=date_from_obj.date())
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = timezone.strptime(date_to, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__lte=date_to_obj.date())
        except ValueError:
            pass
    if success_only == 'true':
        queryset = queryset.filter(success=True)
    
    # Crea il file CSV
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    # Scrivi BOM per UTF-8
    response.write('\ufeff')
    
    writer = csv.writer(response)
    
    # Intestazioni
    headers = [
        'ID', 'Timestamp', 'Utente', 'Tipo Azione', 'Severità', 'Descrizione',
        'IP Address', 'User Agent', 'Session ID', 'Oggetto Correlato',
        'Tipo Oggetto', 'ID Oggetto', 'Successo', 'Messaggio Errore',
        'Dati Aggiuntivi'
    ]
    writer.writerow(headers)
    
    # Dati
    for log in queryset:
        row = [
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'Anonymous',
            log.get_action_type_display(),
            log.get_severity_display(),
            log.description,
            log.ip_address or '',
            log.user_agent or '',
            log.session_id or '',
            log.related_object_type or '',
            log.related_object_id or '',
            'Sì' if log.success else 'No',
            log.error_message or '',
            json.dumps(log.additional_data, ensure_ascii=False) if log.additional_data else ''
        ]
        writer.writerow(row)
    
    return response

@staff_member_required
def audit_logs_analytics(request):
    """Dashboard analitica per gli audit log"""
    
    # Periodo di analisi (ultimi 30 giorni di default)
    days = int(request.GET.get('days', 30))
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    # Log nel periodo
    logs_in_period = AuditLog.objects.filter(
        timestamp__range=(start_date, end_date)
    )
    
    # Statistiche generali
    total_actions = logs_in_period.count()
    unique_users = logs_in_period.values('user').distinct().count()
    success_count = logs_in_period.filter(success=True).count()
    success_rate = (success_count / total_actions * 100) if total_actions > 0 else 0
    actions_per_day = (total_actions / days) if days > 0 else 0
    
    # Azioni per giorno
    daily_actions = logs_in_period.extra(
        select={'day': 'date(timestamp)'}
    ).values('day').annotate(
        count=models.Count('id'),
        success_count=models.Count('id', filter=models.Q(success=True)),
        error_count=models.Count('id', filter=models.Q(success=False))
    ).order_by('day')
    
    # Top azioni
    top_actions = logs_in_period.values('action_type').annotate(
        count=models.Count('id')
    ).order_by('-count')[:10]
    for action in top_actions:
        action['percent'] = (action['count'] / total_actions * 100) if total_actions > 0 else 0
    
    # Top utenti
    top_users = logs_in_period.values('user__username').annotate(
        count=models.Count('id')
    ).order_by('-count')[:10]
    for user in top_users:
        user['percent'] = (user['count'] / total_actions * 100) if total_actions > 0 else 0
    
    # Severità distribution
    severity_distribution = logs_in_period.values('severity').annotate(
        count=models.Count('id')
    ).order_by('severity')
    
    # IP addresses più attivi
    top_ips = logs_in_period.values('ip_address').annotate(
        count=models.Count('id')
    ).filter(ip_address__isnull=False).order_by('-count')[:10]
    for ip in top_ips:
        ip['percent'] = (ip['count'] / total_actions * 100) if total_actions > 0 else 0
    
    context = {
        'days': days,
        'start_date': start_date,
        'end_date': end_date,
        'total_actions': total_actions,
        'unique_users': unique_users,
        'success_rate': round(success_rate, 2),
        'actions_per_day': round(actions_per_day, 1),
        'daily_actions': list(daily_actions),
        'top_actions': list(top_actions),
        'top_users': list(top_users),
        'severity_distribution': list(severity_distribution),
        'top_ips': list(top_ips),
    }
    
    return render(request, 'Cripto1/audit_logs_analytics.html', context)

@staff_member_required
def security_alerts(request):
    """Vista per gli alert di sicurezza"""
    
    # Eventi critici degli ultimi 7 giorni
    critical_events = AuditLog.objects.filter(
        severity='CRITICAL',
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).order_by('-timestamp')
    
    # Tentativi di login falliti
    failed_logins = AuditLog.objects.filter(
        action_type='LOGIN',
        success=False,
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).order_by('-timestamp')
    
    # Azioni amministrative
    admin_actions = AuditLog.objects.filter(
        action_type='ADMIN_ACTION',
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).order_by('-timestamp')
    
    # IP sospetti (troppi tentativi falliti)
    suspicious_ips = AuditLog.objects.filter(
        action_type='LOGIN',
        success=False,
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).values('ip_address').annotate(
        failed_attempts=models.Count('id')
    ).filter(
        failed_attempts__gte=5,
        ip_address__isnull=False
    ).order_by('-failed_attempts')
    
    context = {
        'critical_events': critical_events,
        'failed_logins': failed_logins,
        'admin_actions': admin_actions,
        'suspicious_ips': suspicious_ips,
    }
    
    return render(request, 'Cripto1/security_alerts.html', context)


def page_not_found(request, exception):
    return render(request, 'Cripto1/404.html', {},
                    status=404)

def permission_denied(request, exception):
    return render(request, 'Cripto1/403.html', {},
                    status=403)

# Funzione per verificare se l'utente è superuser o ha permessi di gestione utenti
def has_user_management_permission(user):
    """Verifica se l'utente ha i permessi di gestione utenti"""
    if user.is_superuser or user.is_staff:
        return True
    
    # Verifica se l'utente ha il permesso di gestione utenti
    try:
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        )
        
        for user_role in user_roles:
            if user_role.role.permissions.filter(codename__icontains='user_management').exists():
                return True
    except Exception:
        pass
    
    return False

# Decoratore personalizzato per la gestione utenti
def user_management_required(view_func):
    def wrapper(request, *args, **kwargs):
        # Per ora, permettiamo l'accesso a tutti gli utenti autenticati per testare
        if not request.user.is_authenticated:
            messages.error(request, "Devi essere autenticato per accedere a questa sezione.")
            return redirect('Cripto1:login')
        return view_func(request, *args, **kwargs)
    return wrapper

@login_required
@user_management_required
def user_management_dashboard(request):
    """Dashboard principale per la gestione utenti"""
    
    # I superuser vedono tutti gli utenti, gli altri solo della loro organizzazione
    if request.user.is_superuser:
        total_users = User.objects.count()
        active_users = UserProfile.objects.filter(is_active=True).count()
        inactive_users = UserProfile.objects.filter(is_active=False).count()
        locked_users = sum(
            1 for u in UserProfile.objects.all()
            if (u.is_locked() if callable(getattr(u, 'is_locked', None)) else getattr(u, 'is_locked', False))
        )
        recent_users = UserProfile.objects.select_related('user').order_by('-created_at')[:5]
        
        # Statistiche per ruolo per tutti gli utenti
        role_stats = {}
        for role in Role.objects.filter(is_active=True):
            count = UserRole.objects.filter(
                role=role, 
                is_active=True
            ).exclude(expires_at__lt=timezone.now()).count()
            if count > 0:
                role_stats[role.name] = count
        
        # Attività recenti per tutti gli utenti
        recent_activities = AuditLog.objects.filter(
            action_type__in=['USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'ROLE_ASSIGNED', 'ROLE_REMOVED']
        ).order_by('-timestamp')[:10]
    else:
        # Ottieni l'organizzazione dell'utente corrente
        user_org = request.user.userprofile.organization
        
        # Statistiche FILTRATE PER ORGANIZZAZIONE
        total_users = UserProfile.objects.filter(organization=user_org).count()
        active_users = UserProfile.objects.filter(organization=user_org, is_active=True).count()
        inactive_users = UserProfile.objects.filter(organization=user_org, is_active=False).count()
        locked_users = sum(
            1 for u in UserProfile.objects.filter(organization=user_org)
            if (u.is_locked() if callable(getattr(u, 'is_locked', None)) else getattr(u, 'is_locked', False))
        )
        recent_users = UserProfile.objects.filter(organization=user_org).order_by('-created_at')[:5]
        
        # Statistiche per ruolo FILTRATE PER ORGANIZZAZIONE
        role_stats = {}
        for role in Role.objects.filter(is_active=True):
            count = UserRole.objects.filter(
                role=role, 
                is_active=True,
                user__userprofile__organization=user_org
            ).exclude(expires_at__lt=timezone.now()).count()
            if count > 0:
                role_stats[role.name] = count
        
        # Attività recenti FILTRATE PER ORGANIZZAZIONE
        recent_activities = AuditLog.objects.filter(
            action_type__in=['USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'ROLE_ASSIGNED', 'ROLE_REMOVED'],
            user__userprofile__organization=user_org
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

@login_required
@user_management_required
def user_list(request):
    """Lista degli utenti con filtri e paginazione"""
    search = request.GET.get('search', '')
    status = request.GET.get('status', '')
    role_filter = request.GET.get('role', '')
    per_page = request.GET.get('per_page', '50')  # Nuovo parametro
    
    # Validazione per per_page
    try:
        per_page = int(per_page)
        if per_page not in [12, 24, 50, 100]:
            per_page = 50
    except (ValueError, TypeError):
        per_page = 50
    
    # Query base - I superuser vedono tutti gli utenti, gli altri solo della loro organizzazione
    if request.user.is_superuser:
        users = UserProfile.objects.all().select_related('user', 'organization')
    else:
        user_org = request.user.userprofile.organization
        users = UserProfile.objects.filter(organization=user_org).select_related('user')
    
    # Applica filtri
    if search:
        users = users.filter(
            Q(user__username__icontains=search) |
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search) |
            Q(user__email__icontains=search) |
            Q(department__icontains=search) |
            Q(position__icontains=search)
        )
    
    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)
    elif status == 'locked':
        # Filtra utenti bloccati (con troppi tentativi di login)
        locked_user_ids = []
        for user_profile in users:
            if user_profile.is_locked():
                locked_user_ids.append(user_profile.id)
        users = users.filter(id__in=locked_user_ids)
    
    if role_filter:
        # Filtra per ruolo
        users_with_role = UserRole.objects.filter(
            role__name=role_filter,
            is_active=True
        ).exclude(
            expires_at__lt=timezone.now()
        ).values_list('user_id', flat=True)
        users = users.filter(user_id__in=users_with_role)
    
    # Ordina per data di creazione (più recenti prima)
    users = users.order_by('-created_at')
    
    # Paginazione
    paginator = Paginator(users, per_page)
    page = request.GET.get('page')
    try:
        page_obj = paginator.page(page)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    # Ruoli disponibili per il filtro
    roles = Role.objects.all()
    
    context = {
        'page_obj': page_obj,
        'search': search,
        'status': status,
        'role_filter': role_filter,
        'roles': roles,
        'per_page': per_page,  # Aggiungi al context
    }
    
    return render(request, 'Cripto1/user_management/user_list.html', context)

@login_required
@user_management_required
def user_detail(request, user_id):
    """Dettaglio utente con gestione ruoli"""
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)
    
    # Ruoli dell'utente (solo quelli attivi e non scaduti)
    user_roles = UserRole.objects.filter(
        user=user,
        is_active=True
    ).select_related('role', 'assigned_by').order_by('-assigned_at')
    
    # Ruoli disponibili per l'assegnazione (escludi quelli già assegnati)
    assigned_role_ids = user_roles.values_list('role_id', flat=True)
    available_roles = Role.objects.filter(
        is_active=True
    ).exclude(
        id__in=assigned_role_ids
    ).order_by('name')
    
    # Attività recenti dell'utente
    recent_activities = AuditLog.objects.filter(
        Q(user=user) | Q(description__icontains=user.username)
    ).order_by('-timestamp')[:10]
    
    context = {
        'user_profile': user_profile,
        'user_roles': user_roles,
        'available_roles': available_roles,
        'recent_activities': recent_activities,
        'now': timezone.now(),
    }
    
    return render(request, 'Cripto1/user_management/user_detail.html', context)

@login_required
@user_management_required
def create_user(request):
    """Creazione nuovo utente"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        department = request.POST.get('department', '')
        position = request.POST.get('position', '')
        phone = request.POST.get('phone', '')
        emergency_contact = request.POST.get('emergency_contact', '')
        notes = request.POST.get('notes', '')
        default_role = request.POST.get('default_role', '')
        pk_password = request.POST.get('private_key_password', '')
        pk_confirm = request.POST.get('confirm_private_key_password', '')
        profile_picture = request.FILES.get('profile_picture')

        # Validazione
        if not username or not email or not password or not pk_password:
            messages.error(request, 'Username, email, password account e password chiave privata sono obbligatori')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if password != confirm_password:
            messages.error(request, 'Le password account non corrispondono')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if pk_password != pk_confirm:
            messages.error(request, 'Le password della chiave privata non corrispondono')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if len(password) < 8 or len(pk_password) < 8:
            messages.error(request, 'Le password devono essere di almeno 8 caratteri')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username già esistente')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email già esistente')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        try:
            with transaction.atomic():
                # Crea l'utente
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )

                # Crea il profilo
                user_profile = UserProfile.objects.create(
                    user=user,
                    department=department,
                    position=position,
                    phone=phone,
                    emergency_contact=emergency_contact,
                    notes=notes
                )
                if profile_picture:
                    user_profile.profile_picture = profile_picture

                # Genera le chiavi crittografiche per l'utente con la password fornita
                user_profile.generate_key_pair(password=pk_password.encode())
                user_profile.save()

                # Assegna ruolo di default se specificato
                if default_role:
                    try:
                        role = Role.objects.get(name=default_role)
                        user_profile.assign_role(
                            role=role,
                            assigned_by=request.user,
                            notes='Ruolo assegnato alla creazione'
                        )
                    except Role.DoesNotExist:
                        pass

                # Log dell'azione
                AuditLog.log_action(
                    action_type='USER_MANAGEMENT',
                    description=f'Utente {username} creato da {request.user.username}',
                    severity='MEDIUM',
                    user=request.user,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    related_object_type='UserProfile',
                    related_object_id=user_profile.id,
                    success=True
                )

                messages.success(request, f'Utente {username} creato con successo')
                return redirect('Cripto1:user_detail', user_id=user.id)

        except Exception as e:
            messages.error(request, f'Errore durante la creazione: {str(e)}')
            print(f"Errore creazione utente: {e}")

    context = {
        'roles': Role.objects.filter(is_active=True)
    }
    return render(request, 'Cripto1/user_management/create_user.html', context)

@login_required
@user_management_required
def edit_user(request, user_id):
    """Modifica utente"""
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)

    if request.method == 'POST':
        # Aggiorna i campi dell'utente
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        user.email = request.POST.get('email', '')
        user.save()

        # Aggiorna i campi del profilo
        user_profile.department = request.POST.get('department', '')
        user_profile.position = request.POST.get('position', '')
        user_profile.phone = request.POST.get('phone', '')
        user_profile.emergency_contact = request.POST.get('emergency_contact', '')
        user_profile.notes = request.POST.get('notes', '')
        
        # Gestione organizzazione (solo per superuser)
        if request.user.is_superuser:
            organization_id = request.POST.get('organization')
            if organization_id:
                try:
                    from .models import Organization
                    user_profile.organization = Organization.objects.get(id=organization_id)
                except Organization.DoesNotExist:
                    user_profile.organization = None
            else:
                user_profile.organization = None

        # Gestione sblocco account
        if request.POST.get('unlock_account') == '1' and user_profile.is_locked():
            user_profile.reset_login_attempts()
            messages.success(request, f'Account di {user.username} sbloccato con successo.')
            
            # Log dell'azione di sblocco
            AuditLog.log_action(
                action_type='USER_MANAGEMENT',
                description=f'Account di {user.username} sbloccato da {request.user.username}',
                severity='HIGH',
                user=request.user,
                ip_address=request.META.get('REMOTE_ADDR'),
                related_object_type='UserProfile',
                related_object_id=user_profile.id,
                success=True
            )

        # Gestione foto profilo
        if 'profile_picture' in request.FILES:
            user_profile.profile_picture = request.FILES['profile_picture']

        # Gestione password Django
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        if password:
            if password == confirm_password and len(password) >= 8:
                user.set_password(password)
                user.save()
                messages.info(request, 'Password account aggiornata.')
            else:
                messages.error(request, 'Le password account non corrispondono o sono troppo corte.')
                return redirect('Cripto1:edit_user', user_id=user.id)

        # Gestione password chiave privata
        pk_password = request.POST.get('private_key_password', '')
        pk_confirm = request.POST.get('confirm_private_key_password', '')
        if pk_password:
            if pk_password == pk_confirm and len(pk_password) >= 8:
                user_profile.generate_key_pair(password=pk_password.encode())
                messages.info(request, 'Chiave privata rigenerata con nuova password.')
            else:
                messages.error(request, 'Le password della chiave privata non corrispondono o sono troppo corte.')
                return redirect('Cripto1:edit_user', user_id=user.id)



        user_profile.save()

        # Log dell'azione
        AuditLog.log_action(
            action_type='USER_MANAGEMENT',
            description=f'Utente {user.username} modificato da {request.user.username}',
            severity='MEDIUM',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='UserProfile',
            related_object_id=user_profile.id,
            success=True
        )

        messages.success(request, 'Utente aggiornato con successo')
        return redirect('Cripto1:user_detail', user_id=user.id)
    else:
        form = UserProfileEditForm(instance=user_profile, user=request.user)

    context = {
        'user_profile': user_profile,
        'form': form,
        'is_locked': user_profile.is_locked(),
        'can_edit_organization': request.user.is_superuser
    }
    return render(request, 'Cripto1/user_management/edit_user.html', context)

@login_required
@user_management_required
@require_POST
def toggle_user_status(request, user_id):
    """Attiva/disattiva utente"""
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)
    
    # Non permettere di disattivare se stessi
    if user == request.user:
        messages.error(request, 'Non puoi disattivare il tuo account')
        return redirect('Cripto1:user_detail', user_id=user.id)
    
    user_profile.is_active = not user_profile.is_active
    user_profile.save()
    
    action = 'attivato' if user_profile.is_active else 'disattivato'
    
    # Log dell'azione
    AuditLog.log_action(
        action_type='USER_ACTIVATION' if user_profile.is_active else 'USER_DEACTIVATION',
        description=f'Utente {user.username} {action} da {request.user.username}',
        severity='HIGH',
        user=request.user,
        ip_address=request.META.get('REMOTE_ADDR'),
        related_object_type='UserProfile',
        related_object_id=user_profile.id,
        success=True
    )
    
    messages.success(request, f'Utente {user.username} {action} con successo')
    return redirect('Cripto1:user_detail', user_id=user_id)

@login_required
@user_management_required
@require_POST
def assign_role(request, user_id):
    """Assegna ruolo a utente"""
    user = get_object_or_404(User, id=user_id)
    role_id = request.POST.get('role_id')
    expires_at = request.POST.get('expires_at')
    notes = request.POST.get('notes', '')
    
    if not role_id:
        messages.error(request, 'Ruolo non specificato')
        return redirect('Cripto1:user_detail', user_id=user_id)
    
    try:
        role = Role.objects.get(id=role_id, is_active=True)
        
        # Converti la data di scadenza se fornita
        expires_date = None
        if expires_at:
            try:
                expires_date = timezone.datetime.strptime(expires_at, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            except ValueError:
                messages.error(request, 'Formato data non valido')
                return redirect('Cripto1:user_detail', user_id=user_id)
        
        # Usa il metodo del modello UserProfile per assegnare il ruolo
        try:
            user_profile = UserProfile.objects.get(user=user)
            user_role = user_profile.assign_role(role, assigned_by=request.user, expires_at=expires_date, notes=notes)
            user_profile.refresh_roles_cache()
            
            # Log dell'azione
            AuditLog.log_action(
                action_type='ROLE_ASSIGNMENT',
                description=f'Ruolo {role.name} assegnato a {user.username} da {request.user.username}',
                severity='MEDIUM',
                user=request.user,
                ip_address=request.META.get('REMOTE_ADDR'),
                related_object_type='UserRole',
                related_object_id=user_role.id,
                additional_data={
                    'assigned_role': role.name,
                    'expires_at': expires_at,
                    'notes': notes
                },
                success=True
            )
            
            messages.success(request, f'Ruolo {role.name} assegnato con successo')
        except UserProfile.DoesNotExist:
            messages.error(request, 'Profilo utente non trovato')
            
    except Role.DoesNotExist:
        messages.error(request, 'Ruolo non trovato o non attivo')
    except Exception as e:
        messages.error(request, f'Errore durante l\'assegnazione del ruolo: {str(e)}')
        print(f"Errore assegnazione ruolo: {e}")
    
    return redirect('Cripto1:user_detail', user_id=user_id)

@login_required
@user_management_required
@require_POST
def remove_role(request, user_id, role_id):
    """Rimuove ruolo da utente"""
    user = get_object_or_404(User, id=user_id)
    role = get_object_or_404(Role, id=role_id)
    
    print(f"DEBUG: Tentativo di rimozione ruolo {role.name} da utente {user.username}")
    
    try:
        # Trova l'assegnazione ruolo attiva
        user_role = UserRole.objects.get(
            user=user, 
            role=role, 
            is_active=True
        )
        
        print(f"DEBUG: Trovata assegnazione ruolo: {user_role}")
        
        # Disattiva l'assegnazione
        user_role.is_active = False
        user_role.save()
        
        print(f"DEBUG: Ruolo disattivato con successo")
        
        # Aggiorna il profilo utente per riflettere i cambiamenti
        try:
            user_profile = UserProfile.objects.get(user=user)
            user_profile.refresh_roles_cache()
        except UserProfile.DoesNotExist:
            pass
        
        # Log dell'azione
        AuditLog.log_action(
            action_type='ROLE_ASSIGNMENT',
            description=f'Ruolo {role.name} rimosso da {user.username} da {request.user.username}',
            severity='MEDIUM',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='UserRole',
            related_object_id=user_role.id,
            additional_data={
                'removed_role': role.name,
                'removed_at': timezone.now().isoformat()
            },
            success=True
        )
        
        messages.success(request, f'Ruolo {role.name} rimosso con successo')
        
    except UserRole.DoesNotExist:
        print(f"DEBUG: Assegnazione ruolo non trovata")
        messages.error(request, f'Assegnazione ruolo {role.name} non trovata o già rimossa')
    except Exception as e:
        print(f"DEBUG: Errore durante la rimozione: {e}")
        messages.error(request, f'Errore durante la rimozione del ruolo: {str(e)}')
        print(f"Errore rimozione ruolo: {e}")
    
    return redirect('Cripto1:user_detail', user_id=user_id)

@login_required
@user_management_required
def role_list(request):
    """Lista dei ruoli"""
    roles = Role.objects.all().prefetch_related(
        'permissions', 
        'user_assignments'
    ).order_by('name')
    
    context = {
        'roles': roles
    }
    return render(request, 'Cripto1/user_management/role_list.html', context)

@login_required
@user_management_required
def role_detail(request, role_id):
    """Dettaglio ruolo"""
    role = get_object_or_404(Role, id=role_id)

    # Mostra solo utenti con ruolo attivo e non scaduto
    user_roles = UserRole.objects.filter(
        role=role,
        is_active=True
    ).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    ).select_related('user', 'assigned_by').order_by('-assigned_at')

    # Permessi disponibili per l'aggiunta
    available_permissions = Permission.objects.filter(
        is_active=True
    ).exclude(
        role=role
    ).order_by('category', 'name')

    # Calcola le statistiche corrette
    total_assignments = UserRole.objects.filter(role=role).count()
    active_assignments = UserRole.objects.filter(role=role, is_active=True).count()
    expired_assignments = UserRole.objects.filter(
        role=role, 
        is_active=True,
        expires_at__lt=timezone.now()
    ).count()

    context = {
        'role': role,
        'user_roles': user_roles,
        'available_permissions': available_permissions,
        'total_assignments': total_assignments,
        'active_assignments': active_assignments,
        'expired_assignments': expired_assignments,
    }
    return render(request, 'Cripto1/user_management/role_detail.html', context)

@login_required
@user_management_required
def create_role(request):
    """Creazione nuovo ruolo"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        permissions = request.POST.getlist('permissions')
        is_active = request.POST.get('is_active') == 'on'
        is_system_role = request.POST.get('is_system_role') == 'on'
        notes = request.POST.get('notes', '')
        
        if not name:
            messages.error(request, 'Nome ruolo è obbligatorio')
            return render(request, 'Cripto1/user_management/create_role.html', {'permissions': Permission.objects.filter(is_active=True)})
        
        if Role.objects.filter(name=name).exists():
            messages.error(request, 'Nome ruolo già esistente')
            return render(request, 'Cripto1/user_management/create_role.html', {'permissions': Permission.objects.filter(is_active=True)})
        
        try:
            with transaction.atomic():
                # Crea il ruolo
                role = Role.objects.create(
                    name=name,
                    description=description,
                    is_active=is_active,
                    is_system_role=is_system_role
                )
                
                # Assegna i permessi
                if permissions:
                    role.permissions.set(permissions)
                
                # Log dell'azione
                AuditLog.log_action(
                    action_type='USER_MANAGEMENT',
                    description=f'Ruolo {name} creato da {request.user.username}',
                    severity='MEDIUM',
                    user=request.user,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    related_object_type='Role',
                    related_object_id=role.id,
                    additional_data={
                        'created_role': name,
                        'permissions_count': len(permissions),
                        'is_system_role': is_system_role
                    },
                    success=True
                )
                
                messages.success(request, f'Ruolo {name} creato con successo')
                return redirect('Cripto1:role_detail', role_id=role.id)
                
        except Exception as e:
            messages.error(request, f'Errore durante la creazione: {str(e)}')
            print(f"Errore creazione ruolo: {e}")
    
    context = {
        'permissions': Permission.objects.filter(is_active=True).order_by('category', 'name')
    }
    return render(request, 'Cripto1/user_management/create_role.html', context)

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

@login_required
def backup_management(request):
    # Verifica se l'utente è staff o amministratore di organizzazione
    if not (request.user.is_staff or 
            request.user.user_roles.filter(
                role__name='Organization Admin', 
                is_active=True
            ).exists()):
        messages.error(request, 'Non hai i permessi per gestire i backup.')
        return redirect('Cripto1:dashboard')
    
    # Determina se l'utente può fare ripristini (solo staff)
    can_restore = request.user.is_staff
    
    backup_dir = 'blockchain_backups'
    os.makedirs(backup_dir, exist_ok=True)
    
    # Ottieni l'organizzazione dell'utente
    user_org = request.user.userprofile.organization
    
    # Elenco dei backup disponibili
    backups = []
    for file in os.listdir(backup_dir):
        if file.endswith('.zip') and file.startswith('blockchain_backup_'):
            file_path = os.path.join(backup_dir, file)
            
            # Verifica se il backup appartiene all'organizzazione dell'utente
            # Estrai e leggi i metadati dal file ZIP
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    if 'metadata.json' in zip_ref.namelist():
                        with zip_ref.open('metadata.json') as metadata_file:
                            metadata = json.load(metadata_file)
                            backup_org_id = metadata.get('organization_id')
                            
                            # Se l'utente è staff, può vedere tutti i backup
                            # Se è admin di organizzazione, può vedere solo i suoi
                            if request.user.is_staff or backup_org_id == user_org.id:
                                file_stats = os.stat(file_path)
                                backups.append({
                                    'filename': file,
                                    'path': file_path,
                                    'size': file_stats.st_size,
                                    'created': datetime.fromtimestamp(file_stats.st_mtime),
                                    'organization_name': metadata.get('organization_name', 'N/A'),
                                    'download_url': reverse('Cripto1:download_backup', args=[file])
                                })
            except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
                # Se non riesce a leggere i metadati, salta il file
                continue
    
    backups.sort(key=lambda x: x['created'], reverse=True)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'create_backup':
            include_files = request.POST.get('include_files') == 'on'
            
            # Ottieni l'organizzazione dell'utente
            user_org = request.user.userprofile.organization
            
            # Esegui il comando di backup in background
            from django.core.management import call_command
            try:
                # Usa il comando esistente con il parametro organization_id
                call_command('backup_blockchain', 
                            include_files=include_files,
                            organization_id=user_org.id)  # NUOVO PARAMETRO
                messages.success(request, f'Backup creato con successo per {user_org.name}!')
            except Exception as e:
                messages.error(request, f'Errore durante la creazione del backup: {str(e)}')
            
            return redirect('Cripto1:backup_management')
        
        elif action == 'restore_backup':
            # SOLO STAFF PUÒ RIPRISTINARE
            if not request.user.is_staff:
                messages.error(request, 'Solo gli amministratori di sistema possono ripristinare i backup.')
                return redirect('Cripto1:backup_management')
            
            backup_file = request.POST.get('backup_file')
            if not backup_file:
                messages.error(request, 'Nessun file di backup selezionato')
            else:
                backup_path = os.path.join(backup_dir, backup_file)
                if not os.path.exists(backup_path):
                    messages.error(request, 'File di backup non trovato')
                else:
                    # Esegui il comando di ripristino
                    from django.core.management import call_command
                    try:
                        call_command('restore_blockchain', backup_path, skip_confirmation=True)
                        messages.success(request, 'Ripristino completato con successo!')
                    except Exception as e:
                        messages.error(request, f'Errore durante il ripristino: {str(e)}')
            
            return redirect('Cripto1:backup_management')
        
        elif action == 'delete_backup':
            backup_file = request.POST.get('backup_file')
            if not backup_file:
                messages.error(request, 'Nessun file di backup selezionato')
            else:
                backup_path = os.path.join(backup_dir, backup_file)
                if os.path.exists(backup_path):
                    os.remove(backup_path)
                    messages.success(request, 'Backup eliminato con successo')
                else:
                    messages.error(request, 'File di backup non trovato')
            
            return redirect('Cripto1:backup_management')
    
    context = {
        'backups': backups,
        'can_restore': can_restore,  # Passa al template
    }
    
    return render(request, 'Cripto1/backup_management.html', context)

@staff_member_required
def organization_management(request):
    """Vista per la gestione delle organizzazioni (solo superuser)"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organizations = Organization.objects.all().order_by('-created_at')
    
    # Statistiche generali
    stats = {
        'total_organizations': organizations.count(),
        'active_organizations': organizations.filter(is_active=True).count(),
        'pending_organizations': organizations.filter(is_active=False).count(),
        'total_users': sum(org.get_user_count() for org in organizations),
    }
    
    context = {
        'organizations': organizations,
        'stats': stats,
    }
    
    return render(request, 'Cripto1/organization_management.html', context)

@staff_member_required
def organization_detail(request, org_id):
    """Vista dettagliata di un'organizzazione"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organization = get_object_or_404(Organization, id=org_id)
    
    # Statistiche dell'organizzazione
    users = UserProfile.objects.filter(organization=organization)
    transactions = Transaction.objects.filter(
        sender__userprofile__organization=organization,
        receiver__userprofile__organization=organization
    )
    blocks = Block.objects.filter(organization=organization)
    
    stats = {
        'total_users': users.count(),
        'active_users': users.filter(is_active=True).count(),
        'total_transactions': transactions.count(),
        'total_blocks': blocks.count(),
        'storage_used': sum(user.storage_used_bytes for user in users),
        'storage_limit': organization.max_storage_gb * 1024 * 1024 * 1024,
    }
    
    # Utenti recenti
    recent_users = users.order_by('-created_at')[:10]
    
    # Transazioni recenti
    recent_transactions = transactions.order_by('-timestamp')[:10]
    
    context = {
        'organization': organization,
        'stats': stats,
        'recent_users': recent_users,
        'recent_transactions': recent_transactions,
    }
    
    return render(request, 'Cripto1/organization_detail.html', context)

@staff_member_required
def toggle_organization_status(request, org_id):
    """Attiva/disattiva un'organizzazione"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organization = get_object_or_404(Organization, id=org_id)
    
    organization.is_active = not organization.is_active
    organization.save()
    
    status = 'attivata' if organization.is_active else 'disattivata'
    messages.success(request, f'Organizzazione "{organization.name}" {status} con successo.')
    
    # Log dell'azione
    AuditLog.log_action(
        action_type='ORGANIZATION_MANAGEMENT',
        description=f'Organizzazione {organization.name} {status} da {request.user.username}',
        severity='HIGH',
        user=request.user,
        ip_address=request.META.get('REMOTE_ADDR'),
        related_object_type='Organization',
        related_object_id=organization.id,
        success=True
    )
    
    return redirect('Cripto1:organization_detail', org_id=org_id)

@staff_member_required
def edit_organization(request, org_id):
    """Modifica un'organizzazione"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organization = get_object_or_404(Organization, id=org_id)
    
    if request.method == 'POST':
        # Aggiorna i campi dell'organizzazione
        organization.name = request.POST.get('name', organization.name)
        organization.description = request.POST.get('description', organization.description)
        organization.domain = request.POST.get('domain', organization.domain)
        organization.max_users = int(request.POST.get('max_users', organization.max_users))
        organization.max_storage_gb = int(request.POST.get('max_storage_gb', organization.max_storage_gb))
        
        # Aggiorna le funzionalità abilitate
        features = {
            'blockchain': request.POST.get('feature_blockchain') == 'on',
            '2fa': request.POST.get('feature_2fa') == 'on',
            'audit_logs': request.POST.get('feature_audit_logs') == 'on',
            'file_sharing': request.POST.get('feature_file_sharing') == 'on',
            'smart_contracts': request.POST.get('feature_smart_contracts') == 'on',
        }
        organization.features_enabled = features
        
        organization.save()
        
        # Log dell'azione
        AuditLog.log_action(
            action_type='ORGANIZATION_MANAGEMENT',
            description=f'Organizzazione {organization.name} modificata da {request.user.username}',
            severity='MEDIUM',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='Organization',
            related_object_id=organization.id,
            success=True
        )
        
        messages.success(request, f'Organizzazione "{organization.name}" aggiornata con successo.')
        return redirect('Cripto1:organization_detail', org_id=org_id)
    
    context = {
        'organization': organization,
    }
    
    return render(request, 'Cripto1/edit_organization.html', context)

@staff_member_required
def delete_organization(request, org_id):
    """Elimina un'organizzazione (solo se non ha utenti)"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organization = get_object_or_404(Organization, id=org_id)
    
    # Verifica che l'organizzazione non abbia utenti
    user_count = UserProfile.objects.filter(organization=organization).count()
    if user_count > 0:
        messages.error(request, f'Impossibile eliminare l\'organizzazione. Ha ancora {user_count} utenti associati.')
        return redirect('Cripto1:organization_detail', org_id=org_id)
    
    if request.method == 'POST':
        org_name = organization.name
        
        # Log dell'azione prima dell'eliminazione
        AuditLog.log_action(
            action_type='ORGANIZATION_MANAGEMENT',
            description=f'Organizzazione {org_name} eliminata da {request.user.username}',
            severity='CRITICAL',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='Organization',
            related_object_id=organization.id,
            success=True
        )
        
        organization.delete()
        messages.success(request, f'Organizzazione "{org_name}" eliminata con successo.')
        return redirect('Cripto1:organization_management')
    
    context = {
        'organization': organization,
    }
    
    return render(request, 'Cripto1/delete_organization.html', context)

@staff_member_required  
def create_organization(request):
    """Crea una nuova organizzazione (solo superuser)"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono creare organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    if request.method == 'POST':
        from .models import Organization
        import uuid
        
        try:
            with transaction.atomic():
                # Crea l'organizzazione
                organization = Organization.objects.create(
                    name=request.POST.get('name'),
                    slug=request.POST.get('slug'),
                    description=request.POST.get('description', ''),
                    domain=request.POST.get('domain', ''),
                    registration_code=f"ORG_{uuid.uuid4().hex[:8].upper()}",
                    max_users=int(request.POST.get('max_users', 50)),
                    max_storage_gb=int(request.POST.get('max_storage_gb', 10)),
                    is_active=request.POST.get('is_active') == 'on',
                    features_enabled={
                        'blockchain': request.POST.get('feature_blockchain') == 'on',
                        '2fa': request.POST.get('feature_2fa') == 'on',
                        'audit_logs': request.POST.get('feature_audit_logs') == 'on',
                        'file_sharing': request.POST.get('feature_file_sharing') == 'on',
                        'smart_contracts': request.POST.get('feature_smart_contracts') == 'on',
                    }
                )
                
                # Log dell'azione
                AuditLog.log_action(
                    action_type='ORGANIZATION_MANAGEMENT',
                    description=f'Organizzazione {organization.name} creata da {request.user.username}',
                    severity='HIGH',
                    user=request.user,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    related_object_type='Organization',
                    related_object_id=organization.id,
                    success=True
                )
                
                messages.success(request, f'Organizzazione "{organization.name}" creata con successo!')
                return redirect('Cripto1:organization_detail', org_id=organization.id)
                
        except Exception as e:
            messages.error(request, f'Errore durante la creazione: {str(e)}')
    
    return render(request, 'Cripto1/create_organization.html')

@staff_member_required
def download_backup(request, filename):
    backup_dir = 'blockchain_backups'
    file_path = os.path.join(backup_dir, filename)
    
    if not os.path.exists(file_path):
        messages.error(request, 'File di backup non trovato')
        return redirect('Cripto1:backup_management')
    
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

@staff_member_required
def organization_users(request, org_id):
    """Lista utenti di un'organizzazione"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organization = get_object_or_404(Organization, id=org_id)
    
    # Filtri
    search = request.GET.get('search', '')
    status = request.GET.get('status', '')
    
    users = UserProfile.objects.filter(organization=organization)
    
    if search:
        users = users.filter(
            Q(user__username__icontains=search) |
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search) |
            Q(user__email__icontains=search)
        )
    
    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)
    
    users = users.order_by('-created_at')
    
    # Paginazione
    paginator = Paginator(users, 25)
    page = request.GET.get('page')
    users = paginator.get_page(page)
    
    context = {
        'organization': organization,
        'users': users,
        'search': search,
        'status': status,
    }
    
    return render(request, 'Cripto1/organization_users.html', context)

@staff_member_required
def upload_backup(request):
    if request.method == 'POST' and request.FILES.get('backup_file'):
        backup_file = request.FILES['backup_file']
        
        # Verifica che il file sia un file ZIP
        if not backup_file.name.endswith('.zip'):
            messages.error(request, 'Il file deve essere in formato ZIP')
            return redirect('Cripto1:backup_management')
        
        # Crea la directory di backup se non esiste
        backup_dir = 'blockchain_backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        # Genera un nome file basato sulla data e ora corrente
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f'blockchain_backup_{timestamp}.zip'
        file_path = os.path.join(backup_dir, filename)
        
        # Salva il file caricato
        with open(file_path, 'wb+') as destination:
            for chunk in backup_file.chunks():
                destination.write(chunk)
        
        messages.success(request, f'Backup importato con successo come {filename}')
    else:
        messages.error(request, 'Nessun file selezionato')
    
    return redirect('Cripto1:backup_management')

@staff_member_required
def organization_statistics(request, org_id):
    """Statistiche dettagliate di un'organizzazione"""
    if not request.user.is_superuser:
        messages.error(request, 'Solo i superuser possono gestire le organizzazioni.')
        return redirect('Cripto1:dashboard')
    
    from .models import Organization
    organization = get_object_or_404(Organization, id=org_id)
    
    # Statistiche utenti
    users = UserProfile.objects.filter(organization=organization)
    user_stats = {
        'total': users.count(),
        'active': users.filter(is_active=True).count(),
        'inactive': users.filter(is_active=False).count(),
        'with_2fa': users.filter(two_factor_enabled=True).count(),
    }
    
    # Statistiche transazioni
    transactions = Transaction.objects.filter(
        sender__userprofile__organization=organization,
        receiver__userprofile__organization=organization
    )
    transaction_stats = {
        'total': transactions.count(),
        'text': transactions.filter(type='text').count(),
        'file': transactions.filter(type='file').count(),
        'encrypted': transactions.filter(is_encrypted=True).count(),
    }
    
    # Statistiche blockchain
    blocks = Block.objects.filter(organization=organization)
    blockchain_stats = {
        'total_blocks': blocks.count(),
        'avg_transactions_per_block': blocks.aggregate(
            avg=models.Avg('transactions__count')
        )['avg'] or 0,
    }
    
    # Statistiche storage
    total_storage_used = sum(user.storage_used_bytes for user in users)
    storage_stats = {
        'used_gb': round(total_storage_used / (1024**3), 2),
        'limit_gb': organization.max_storage_gb,
        'percentage': round((total_storage_used / (organization.max_storage_gb * 1024**3)) * 100, 1) if organization.max_storage_gb > 0 else 0,
    }
    
    # Attività mensile (ultimi 6 mesi)
    monthly_activity = []
    for i in range(6):
        month_start = timezone.now() - timedelta(days=30 * (i + 1))
        month_end = timezone.now() - timedelta(days=30 * i)
        
        month_transactions = transactions.filter(
            timestamp__gte=month_start.timestamp(),
            timestamp__lt=month_end.timestamp()
        ).count()
        
        month_users = users.filter(
            created_at__gte=month_start,
            created_at__lt=month_end
        ).count()
        
        monthly_activity.append({
            'month': month_start.strftime('%B %Y'),
            'transactions': month_transactions,
            'new_users': month_users,
        })
    
    monthly_activity.reverse()
    
    context = {
        'organization': organization,
        'user_stats': user_stats,
        'transaction_stats': transaction_stats,
        'blockchain_stats': blockchain_stats,
        'storage_stats': storage_stats,
        'monthly_activity': monthly_activity,
    }
    
    return render(request, 'Cripto1/organization_statistics.html', context)

@login_required
def personal_documents(request):
    documents = PersonalDocument.objects.filter(user=request.user).order_by('-uploaded_at')
    return render(request, 'Cripto1/personal_documents.html', {'documents': documents})

@login_required
def upload_personal_document(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description', '')
        is_encrypted = request.POST.get('is_encrypted', 'false').lower() in ['true', 'on', '1']
        private_key_password = request.POST.get('private_key_password')
        
        if not title or not request.FILES.get('file'):
            messages.error(request, 'Titolo e file sono obbligatori.')
            return redirect('Cripto1:personal_documents')
        
        file = request.FILES['file']
        print(f"DEBUG: Dimensione originale del file: {file.size} bytes")
        
        # Salva temporaneamente una copia del file per debug
        with open('debug_file_copy.bin', 'wb') as debug_file:
            for chunk in file.chunks():
                debug_file.write(chunk)
        
        # Riavvolgi il file per le operazioni successive
        file.seek(0)
        
        # 1. Controllo estensione e tipo MIME
        allowed_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv']
        file_extension = file.name.split('.')[-1].lower()
        
        if file_extension not in allowed_extensions:
            messages.error(request, f'Estensione file non consentita. Estensioni permesse: {", ".join(allowed_extensions)}')
            return redirect('Cripto1:personal_documents')
        
        # 2. Controllo dimensione file (max 10MB)
        if file.size > 10 * 1024 * 1024:  # 10MB in bytes
            messages.error(request, 'Il file è troppo grande. Dimensione massima: 10MB')
            return redirect('Cripto1:personal_documents')
        
        # 3. Scansione antivirus con ClamAV
        try:
            from django_clamd import validators
            # Salva temporaneamente il file per la scansione
            from tempfile import NamedTemporaryFile
            import os
            
            with NamedTemporaryFile(delete=False) as temp_file:
                for chunk in file.chunks():
                    temp_file.write(chunk)
                temp_file_path = temp_file.name
            
            try:
                # Esegui la scansione antivirus
                from django_clamd import clamd
                scanner = clamd.ClamdUnixSocket()
                scan_result = scanner.scan_file(temp_file_path)
                
                # Verifica il risultato della scansione
                if scan_result and temp_file_path in scan_result and scan_result[temp_file_path][0] == 'FOUND':
                    os.unlink(temp_file_path)  # Elimina il file temporaneo
                    virus_name = scan_result[temp_file_path][1]
                    
                    # Registra l'evento di sicurezza
                    AuditLog.log_action(
                        user=request.user,
                        action_type='SECURITY_EVENT',
                        description=f'Tentativo di caricamento file infetto: {file.name}',
                        severity='HIGH',
                        additional_data={'virus_detected': virus_name},
                        success=False,
                        error_message=f'Virus rilevato: {virus_name}'
                    )
                    
                    messages.error(request, 'Il file contiene codice malevolo e non può essere caricato.')
                    return redirect('Cripto1:personal_documents')
                
                os.unlink(temp_file_path)  # Elimina il file temporaneo
                
            except Exception as e:
                os.unlink(temp_file_path)  # Assicurati di eliminare il file temporaneo
                # Gestisci l'errore di scansione (opzionale: blocca il file se CLAMD_FAIL_BY_DEFAULT è True)
                print(f"Errore durante la scansione antivirus: {str(e)}")
                # Se vuoi bloccare il file in caso di errore di scansione, decommentare:
                # messages.error(request, 'Impossibile verificare la sicurezza del file. Riprova più tardi.')
                # return redirect('Cripto1:personal_documents')
        except ImportError:
            # Se django-clamd non è installato, registra un avviso
            print("django-clamd non è installato. La scansione antivirus è disabilitata.")
        
        # Continua con il codice esistente per la lettura e la crittografia del file
        file.seek(0)  # Reset del puntatore del file
        file_content = file.read()  # Rileggi il contenuto
        print(f"DEBUG: Tipo di file_content: {type(file_content)}")
        print(f"DEBUG: Primi 20 bytes: {file_content[:20].hex() if file_content else 'VUOTO'}")
        print(f"DEBUG: Estensione file: {file_extension}")
        print(f"DEBUG: MIME type: {file.content_type}")
        print(f"DEBUG: Dimensione file: {len(file_content)} bytes")
        print(f"DEBUG: Dimensione originale: {file.size} bytes")
        
        user_profile = UserProfile.objects.get(user=request.user)
        
        if is_encrypted:
            try:
                # Genera una chiave simmetrica per la cifratura del file
                symmetric_key = Fernet.generate_key()
                f = Fernet(symmetric_key)
                encrypted_file_content = f.encrypt(file_content)  # Questo mantiene il formato binario
                
                print(f"DEBUG: Tipo di encrypted_file_content: {type(encrypted_file_content)}")
                print(f"DEBUG: Primi 20 bytes cifrati: {encrypted_file_content[:20]}")
                
                # Cifra la chiave simmetrica con la chiave pubblica dell'utente
                user_public_key = serialization.load_pem_public_key(
                    user_profile.public_key.encode(),
                    backend=default_backend()
                )
                encrypted_symmetric_key = user_public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                filename = f"{uuid.uuid4().hex}.encrypted"
                file_to_save = ContentFile(encrypted_file_content)  # ContentFile gestisce correttamente i dati binari
                original_filename = file.name
            except Exception as e:
                messages.error(request, f'Errore durante la cifratura del file: {str(e)}')
                return redirect('Cripto1:personal_documents')
        else:
            filename = f"{time.time()}_{file.name}"
            file_to_save = ContentFile(file_content)  # ContentFile gestisce correttamente i dati binari
            original_filename = None
            encrypted_symmetric_key = None
        
        print(f"DEBUG: Prima di salvare il file con default_storage")
        file_path = default_storage.save(f'personal_documents/{filename}', file_to_save)
        print(f"DEBUG: Dopo il salvataggio, file_path: {file_path}")
        
        # Crea il documento personale
        PersonalDocument.objects.create(
            user=request.user,
            title=title,
            description=description,
            file=file_path,
            is_encrypted=is_encrypted,
            original_filename=original_filename,
            encrypted_symmetric_key=encrypted_symmetric_key
        )
        
        messages.success(request, 'Documento caricato con successo.')
        return redirect('Cripto1:personal_documents')
    
    return render(request, 'Cripto1/upload_personal_document.html')

@login_required
def download_personal_document(request, document_id):
    document = get_object_or_404(PersonalDocument, id=document_id, user=request.user)
    
    if not document.file:
        messages.error(request, 'Nessun file associato a questo documento.')
        return redirect('Cripto1:personal_documents')
    
    if document.is_encrypted:
        if request.method == 'POST':
            private_key_password = request.POST.get('private_key_password')
            if not private_key_password:
                messages.error(request, 'Inserisci la password della chiave privata.')
                return render(request, 'Cripto1/download_personal_document.html', {'document': document})
            
            try:
                # Leggi il contenuto cifrato del file
                with default_storage.open(document.file.name, 'rb') as f:
                    encrypted_file_content = f.read()
                
                # Decifra la chiave simmetrica con la chiave privata dell'utente
                user_profile = request.user.userprofile
                decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                if not decrypted_private_key:
                    messages.error(request, 'Password della chiave privata errata.')
                    return render(request, 'Cripto1/download_personal_document.html', {'document': document})
                
                # Converti memoryview in bytes prima della decifratura
                encrypted_symmetric_key_bytes = bytes(document.encrypted_symmetric_key) if isinstance(document.encrypted_symmetric_key, memoryview) else document.encrypted_symmetric_key
                
                symmetric_key = decrypted_private_key.decrypt(
                    encrypted_symmetric_key_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decifra il contenuto del file con la chiave simmetrica
                f = Fernet(symmetric_key)
                decrypted_content = f.decrypt(encrypted_file_content)
                
                # Servi il file decifrato con il nome originale
                response = HttpResponse(decrypted_content, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{document.original_filename}"'
                return response
            
            except Exception as e:
                messages.error(request, f'Errore durante la decifratura o il download del file: {str(e)}')
                return render(request, 'Cripto1/download_personal_document.html', {'document': document})
        else:
            return render(request, 'Cripto1/download_personal_document.html', {'document': document})
    else:
        # Se non è cifrato, procedi con il download normale
        file_path = document.file.path
        file_name = os.path.basename(file_path)
        
        with open(file_path, 'rb') as f:  # Assicurati che sia 'rb' per la lettura binaria
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            return response

@login_required
def view_personal_document(request, document_id):
    document = get_object_or_404(PersonalDocument, id=document_id, user=request.user)
    
    if not document.file:
        messages.error(request, 'Nessun file associato a questo documento.')
        return redirect('Cripto1:personal_documents')
    
    # Controlla le estensioni supportate per la visualizzazione
    filename = document.original_filename if document.is_encrypted else os.path.basename(document.file.name)
    file_extension = os.path.splitext(filename)[1].lower()
    
    # Lista delle estensioni che possono essere visualizzate nel browser
    viewable_extensions = ['.pdf', '.txt', '.csv', '.png', '.jpg', '.jpeg', '.gif']
    
    if file_extension not in viewable_extensions:
        messages.warning(request, f'Il formato {file_extension} non può essere visualizzato direttamente. Utilizzare l\'opzione di download.')
        return redirect('Cripto1:personal_documents')
    
    # Determina il content type appropriato
    if file_extension == '.pdf':
        content_type = 'application/pdf'
    elif file_extension == '.txt':
        content_type = 'text/plain'
    elif file_extension == '.csv':
        content_type = 'text/csv'
    elif file_extension in ['.png', '.jpg', '.jpeg', '.gif']:
        content_type = f'image/{file_extension[1:]}'
    else:
        content_type = 'application/octet-stream'
    
    if document.is_encrypted:
        if request.method == 'POST':
            private_key_password = request.POST.get('private_key_password')
            if not private_key_password:
                messages.error(request, 'Inserisci la password della chiave privata.')
                return render(request, 'Cripto1/view_personal_document.html', {'document': document})
            
            try:
                # Leggi il contenuto cifrato del file
                with default_storage.open(document.file.name, 'rb') as f:
                    encrypted_file_content = f.read()
                
                # Decifra la chiave simmetrica con la chiave privata dell'utente
                user_profile = request.user.userprofile
                decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                if not decrypted_private_key:
                    messages.error(request, 'Password della chiave privata errata.')
                    return render(request, 'Cripto1/view_personal_document.html', {'document': document})
                
                # Converti memoryview in bytes prima della decifratura
                encrypted_key_bytes = bytes(document.encrypted_symmetric_key) if document.encrypted_symmetric_key else None
                
                symmetric_key = decrypted_private_key.decrypt(
                    encrypted_key_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decifra il contenuto del file con la chiave simmetrica
                f = Fernet(symmetric_key)
                decrypted_content = f.decrypt(encrypted_file_content)
                
                # Debug: stampa i primi byte per verificare che sia un PDF valido
                print(f"DEBUG: Primi 20 bytes: {decrypted_content[:20]}")
                
                # Restituisci il contenuto esattamente come fa view_transaction_file
                response = HttpResponse(decrypted_content, content_type=content_type)
                response['Content-Disposition'] = f'inline; filename="{document.original_filename}"'
                return response
            
            except Exception as e:
                import traceback
                print(f"ERROR: Errore durante la decifratura: {str(e)}")
                print(traceback.format_exc())
                messages.error(request, f'Errore durante la decifratura del file: {str(e)}')
                return render(request, 'Cripto1/view_personal_document.html', {'document': document})
        else:
            return render(request, 'Cripto1/view_personal_document.html', {'document': document})
    else:
        # Se non è cifrato, procedi con la visualizzazione normale
        try:
            file_path = document.file.path
            
            # Verifica che il file esista fisicamente
            if not os.path.exists(file_path):
                messages.error(request, "File non trovato sul server.")
                return redirect('Cripto1:personal_documents')
            
            # Leggi il file esattamente come fa view_transaction_file
            with open(file_path, 'rb') as f:  # Assicurati che sia 'rb' per la lettura binaria
                file_content = f.read()
                
                # Debug: stampa i primi byte per verificare che sia un file valido
                print(f"DEBUG: Primi 20 bytes: {file_content[:20].hex()}")
                print(f"DEBUG: Content-type: {content_type}")
                print(f"DEBUG: Dimensione file: {len(file_content)} bytes")
                
                response = HttpResponse(file_content, content_type=content_type)
                response['Content-Disposition'] = f'inline; filename="{os.path.basename(file_path)}"'
                return response
                
        except Exception as e:
            import traceback
            print(f"ERROR: Errore durante la lettura del file: {str(e)}")
            print(traceback.format_exc())
            messages.error(request, f'Errore durante la lettura del file: {str(e)}')
            return redirect('Cripto1:personal_documents')


@login_required
def delete_personal_document(request, document_id):
    document = get_object_or_404(PersonalDocument, id=document_id, user=request.user)
    if request.method == 'POST':
        # Elimina il file dal filesystem
        if document.file:
            if os.path.isfile(document.file.path):
                os.remove(document.file.path)
        # Elimina il record dal database
        document.delete()
        messages.success(request, 'Documento eliminato con successo.')
    return redirect('Cripto1:personal_documents')

@login_required
@external_forbidden
@user_manager_forbidden
def send_document_as_transaction(request, document_id):
    document = get_object_or_404(PersonalDocument, id=document_id, user=request.user)
    
    if request.method == 'POST':
        # Ottieni i dati dal form
        receiver_key = request.POST.get('receiver_key')
        is_encrypted = request.POST.get('is_encrypted', 'false').lower() in ['true', 'on', '1']
        is_shareable = True  # Imposta come condivisibile di default
        private_key_password = request.POST.get('private_key_password')
        max_downloads_str = request.POST.get('max_downloads')
        max_downloads = int(max_downloads_str) if max_downloads_str and max_downloads_str.isdigit() else None
        
        if not receiver_key:
            messages.error(request, 'Seleziona un destinatario.')
            return redirect('Cripto1:personal_documents')
        
        user_profile = UserProfile.objects.get(user=request.user)
        user_org = user_profile.organization
        receiver_profile = UserProfile.objects.filter(
            user_key=receiver_key,
            organization=user_org
        ).first()
        
        if not receiver_profile:
            messages.error(request, 'Destinatario non trovato nella tua organizzazione.')
            return redirect('Cripto1:personal_documents')
        
        # Verifica se l'utente ha il ruolo "external"
        if user_profile.has_role('external'):
            messages.error(request, 'Gli utenti con ruolo "external" non possono inviare transazioni.')
            return redirect('Cripto1:personal_documents')
        
        try:
            # Leggi il file dal documento personale
            with default_storage.open(document.file.name, 'rb') as f:
                file_content = f.read()
            
            # Se il documento è cifrato, prima decifralo
            if document.is_encrypted:
                try:
                    # Decifra la chiave simmetrica con la chiave privata dell'utente
                    decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                    if not decrypted_private_key:
                        messages.error(request, 'Password della chiave privata errata.')
                        return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
                    
                    # Converti memoryview in bytes prima della decifratura
                    encrypted_symmetric_key_bytes = bytes(document.encrypted_symmetric_key) if isinstance(document.encrypted_symmetric_key, memoryview) else document.encrypted_symmetric_key
                    
                    symmetric_key = decrypted_private_key.decrypt(
                        encrypted_symmetric_key_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Decifra il contenuto del file
                    f = Fernet(symmetric_key)
                    file_content = f.decrypt(file_content)
                    
                    # Usa il nome originale del file
                    original_filename = document.original_filename
                except Exception as e:
                    messages.error(request, f'Errore durante la decifratura del documento: {str(e)}')
                    return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            else:
                original_filename = os.path.basename(document.file.name)

            # Salva la chiave pubblica del mittente
            sender_public_key = user_profile.public_key

            # Crea i dati della transazione
            transaction_data = {
                'type': 'file',
                'sender': request.user.id,
                'receiver': receiver_profile.user.id,
                'sender_public_key': sender_public_key,
                'content': '',  # Per i file, il contenuto è vuoto
                'timestamp': time.time(),
                'is_encrypted': is_encrypted,
                'is_shareable': is_shareable
            }
            
            # Gestione del file
            encrypted_symmetric_key_for_db = None

            if is_encrypted:
                try:
                    # Genera una chiave simmetrica per la cifratura del file
                    symmetric_key = Fernet.generate_key()
                    f = Fernet(symmetric_key)
                    encrypted_file_content = f.encrypt(file_content)

                    # Cifra la chiave simmetrica con la chiave pubblica RSA del destinatario
                    receiver_public_key = serialization.load_pem_public_key(
                        receiver_profile.public_key.encode(),
                        backend=default_backend()
                    )
                    encrypted_symmetric_key_for_db = receiver_public_key.encrypt(
                        symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Cifra la chiave simmetrica per il mittente
                    sender_public_key_obj = serialization.load_pem_public_key(
                        user_profile.public_key.encode(),
                        backend=default_backend()
                    )
                    sender_encrypted_symmetric_key = sender_public_key_obj.encrypt(
                        symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    filename = f"{uuid.uuid4().hex}.encrypted"
                    file_to_save = ContentFile(encrypted_file_content)
                    transaction_data['original_filename'] = original_filename
                    transaction_data['encrypted_symmetric_key'] = encrypted_symmetric_key_for_db.hex()
                    transaction_data['sender_encrypted_symmetric_key'] = sender_encrypted_symmetric_key.hex()
                    transaction_data['receiver_public_key_at_encryption'] = receiver_profile.public_key

                except Exception as e:
                    messages.error(request, f'Errore durante la cifratura del file: {str(e)}')
                    return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            else:
                filename = f"{time.time()}_{original_filename}"
                file_to_save = ContentFile(file_content)

            file_path = default_storage.save(f'transaction_files/{filename}', file_to_save)
            transaction_data['file'] = file_path

            # Calcola l'hash della transazione
            transaction_string_for_signing = json.dumps(transaction_data, sort_keys=True).encode()
            transaction_hash = hashlib.sha256(transaction_string_for_signing).hexdigest()
            
            # Firma la transazione
            private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
            if not private_key:
                messages.error(request, 'Errore durante il recupero della chiave privata.')
                return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            
            data_to_sign = transaction_hash.encode()
            signature = private_key.sign(
                data_to_sign,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Crea la transazione
            new_tx = Transaction.objects.create(
                type='file',
                sender=request.user,
                receiver=receiver_profile.user,
                sender_public_key=sender_public_key,
                content='',
                file=transaction_data.get('file'),
                timestamp=transaction_data['timestamp'],
                transaction_hash=transaction_hash,
                signature=signature.hex(),
                is_encrypted=is_encrypted,
                is_shareable=transaction_data.get('is_shareable', False),
                original_filename=transaction_data.get('original_filename', ''),
                encrypted_symmetric_key=bytes.fromhex(transaction_data['encrypted_symmetric_key']) if 'encrypted_symmetric_key' in transaction_data and transaction_data['encrypted_symmetric_key'] else None,
                sender_encrypted_symmetric_key=bytes.fromhex(transaction_data['sender_encrypted_symmetric_key']) if 'sender_encrypted_symmetric_key' in transaction_data and transaction_data['sender_encrypted_symmetric_key'] else None,
                receiver_public_key_at_encryption=transaction_data.get('receiver_public_key_at_encryption', ''),
                max_downloads=max_downloads
            )

            # Aggiungi alle transazioni in sospeso
            pending_transactions_ids = request.session.get('pending_transactions_ids', [])
            pending_transactions_ids.append(new_tx.id)
            request.session['pending_transactions_ids'] = pending_transactions_ids

            messages.success(request, 'Transazione creata e firmata. In attesa di mining.')
            return redirect('Cripto1:all_transactions')

        except Exception as e:
            messages.error(request, f'Errore durante la creazione della transazione: {str(e)}')
            return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
    
    return render(request, 'Cripto1/send_document_as_transaction.html', {'document': document})
@login_required
def add_transaction_file_to_personal_documents(request, transaction_id):
    tx = get_object_or_404(Transaction, id=transaction_id)
    
    # Verifica che l'utente sia il destinatario della transazione
    if request.user != tx.receiver:
        messages.error(request, 'Non sei autorizzato ad aggiungere questo file ai tuoi documenti.')
        return redirect('Cripto1:transaction_details', transaction_id=transaction_id)
    
    # Verifica che la transazione abbia un file e sia condivisibile
    if not tx.file or not tx.is_shareable:
        messages.error(request, 'Questo file non può essere aggiunto ai tuoi documenti personali.')
        return redirect('Cripto1:transaction_details', transaction_id=transaction_id)
    
    # Se il file è cifrato, dobbiamo gestire la decifratura
    if tx.is_encrypted:
        if request.method == 'POST':
            private_key_password = request.POST.get('private_key_password')
            if not private_key_password:
                messages.error(request, 'Inserisci la password della chiave privata.')
                return render(request, 'Cripto1/add_transaction_file_to_personal_documents.html', {'transaction': tx})
            
            try:
                # Leggi il contenuto cifrato del file
                with default_storage.open(tx.file.name, 'rb') as f:
                    encrypted_file_content = f.read()
                
                # Decifra la chiave simmetrica con la chiave privata dell'utente
                user_profile = request.user.userprofile
                decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                if not decrypted_private_key:
                    messages.error(request, 'Password della chiave privata errata.')
                    return render(request, 'Cripto1/add_transaction_file_to_personal_documents.html', {'transaction': tx})
                
                # Converti memoryview in bytes prima della decifratura RSA
                encrypted_symmetric_key_bytes = bytes(tx.encrypted_symmetric_key) if isinstance(tx.encrypted_symmetric_key, memoryview) else tx.encrypted_symmetric_key
                
                symmetric_key = decrypted_private_key.decrypt(
                    encrypted_symmetric_key_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decifra il contenuto del file con la chiave simmetrica
                f = Fernet(symmetric_key)
                decrypted_content = f.decrypt(encrypted_file_content)
                
                # Genera una nuova chiave simmetrica per cifrare il file per i documenti personali
                new_symmetric_key = Fernet.generate_key()
                new_f = Fernet(new_symmetric_key)
                new_encrypted_file_content = new_f.encrypt(decrypted_content)
                
                # Cifra la nuova chiave simmetrica con la chiave pubblica dell'utente
                user_public_key = serialization.load_pem_public_key(
                    user_profile.public_key.encode(),
                    backend=default_backend()
                )
                new_encrypted_symmetric_key = user_public_key.encrypt(
                    new_symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Salva il file cifrato
                filename = f"{uuid.uuid4().hex}.encrypted"
                file_to_save = ContentFile(new_encrypted_file_content)
                file_path = default_storage.save(f'personal_documents/{filename}', file_to_save)
                
                # Crea il documento personale
                PersonalDocument.objects.create(
                    user=request.user,
                    title=f"{tx.original_filename}",
                    description=f"Documento aggiunto dalla transazione {tx.id} ricevuta da {tx.sender.username}",
                    file=file_path,
                    is_encrypted=True,
                    original_filename=tx.original_filename,
                    encrypted_symmetric_key=new_encrypted_symmetric_key
                )
                
                messages.success(request, 'File aggiunto con successo ai tuoi documenti personali.')
                return redirect('Cripto1:personal_documents')
                
            except Exception as e:
                messages.error(request, f'Errore durante l\'aggiunta del file ai documenti personali: {str(e)}')
                return render(request, 'Cripto1/add_transaction_file_to_personal_documents.html', {'transaction': tx})
        else:
            return render(request, 'Cripto1/add_transaction_file_to_personal_documents.html', {'transaction': tx})
    else:
        # Se il file non è cifrato, copialo semplicemente
        try:
            # Leggi il contenuto del file
            with open(tx.file.path, 'rb') as f:
                file_content = f.read()
            
            # Salva il file nei documenti personali
            filename = os.path.basename(tx.file.path)
            file_to_save = ContentFile(file_content)
            file_path = default_storage.save(f'personal_documents/{filename}', file_to_save)
            
            # Crea il documento personale
            PersonalDocument.objects.create(
                user=request.user,
                title=f"{os.path.basename(tx.file.name)}",
                description=f"Documento aggiunto dalla transazione {tx.id} ricevuta da {tx.sender.username}",
                file=file_path,
                is_encrypted=False
            )
            
            messages.success(request, 'File aggiunto con successo ai tuoi documenti personali.')
            return redirect('Cripto1:personal_documents')
            
        except Exception as e:
            messages.error(request, f'Errore durante l\'aggiunta del file ai documenti personali: {str(e)}')
            return redirect('Cripto1:transaction_details', transaction_id=transaction_id)

@login_required
def setup_2fa(request):
    """Vista per la configurazione iniziale del 2FA"""
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Se l'utente ha già configurato 2FA, reindirizza alla pagina di gestione
    if user_profile.two_factor_verified:
        return redirect('Cripto1:manage_2fa')
    
    # Genera un nuovo segreto se non esiste
    if not user_profile.two_factor_secret:
        user_profile.generate_2fa_secret()
    
    # Genera il QR code
    totp_uri = user_profile.get_totp_uri()
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_img = base64.b64encode(buffered.getvalue()).decode()
    
    if request.method == 'POST':
        verification_code = request.POST.get('verification_code')
        if user_profile.enable_2fa(verification_code):
            messages.success(request, 'Autenticazione a due fattori abilitata con successo!')
            return redirect('Cripto1:dashboard')
        else:
            messages.error(request, 'Codice di verifica non valido. Riprova.')
    
    context = {
        'qr_code_img': qr_code_img,
        'secret_key': user_profile.two_factor_secret,
    }
    return render(request, 'Cripto1/setup_2fa.html', context)

@login_required
def manage_2fa(request):
    """Vista per gestire le impostazioni 2FA"""
    user_profile = UserProfile.objects.get(user=request.user)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'disable':
            user_profile.disable_2fa()
            messages.success(request, 'Autenticazione a due fattori disabilitata.')
        elif action == 'enable':
            return redirect('Cripto1:setup_2fa')
    
    context = {
        'two_factor_enabled': user_profile.two_factor_enabled,
    }
    return render(request, 'Cripto1/manage_2fa.html', context)

def verify_2fa(request):
    """Vista per verificare il codice 2FA durante il login"""
    if 'user_id' not in request.session:
        return redirect('Cripto1:login')
    
    user_id = request.session['user_id']
    try:
        user = User.objects.get(id=user_id)
        user_profile = UserProfile.objects.get(user=user)
    except (User.DoesNotExist, UserProfile.DoesNotExist):
        return redirect('Cripto1:login')
    
    if request.method == 'POST':
        verification_code = request.POST.get('verification_code')
        
        if user_profile.verify_2fa_code(verification_code):
            # Completa il login
            login(request, user)
            
            # Resetta i tentativi di login e aggiorna le informazioni
            user_profile.reset_login_attempts()
            user_profile.update_last_login(request.META.get('REMOTE_ADDR'))
            
            # Pulisci la sessione
            if 'user_id' in request.session:
                del request.session['user_id']
            
            messages.success(request, "Benvenuto! Hai effettuato l'accesso con successo.", extra_tags='welcome_toast')
            return redirect('Cripto1:dashboard')
        else:
            messages.error(request, 'Codice di verifica non valido. Riprova.')
    
    return render(request, 'Cripto1/verify_2fa.html')

def clean_file_path(file_path):
    """Pulisce e normalizza il percorso del file ricevuto dal frontend"""
    if not file_path:
        return None
    
    print(f"clean_file_path - input: {file_path}")
    print(f"clean_file_path - caratteri: {[ord(c) for c in file_path]}")
    
    # Decodifica le sequenze Unicode (come u005C -> \)
    try:
        # Gestisci le sequenze Unicode come u005C
        file_path = file_path.encode('utf-8').decode('unicode_escape')
        print(f"clean_file_path - dopo decodifica Unicode: {file_path}")
    except Exception as e:
        print(f"clean_file_path - errore nella decodifica Unicode: {e}")
    
    # Rimuovi caratteri non validi che potrebbero essere stati aggiunti durante la trasmissione
    # Rimuovi caratteri non ASCII che potrebbero essere stati aggiunti erroneamente
    original_path = file_path
    file_path = re.sub(r'[^\x00-\x7F]+', '', file_path)
    
    if original_path != file_path:
        print(f"clean_file_path - pulito: {original_path} -> {file_path}")
    
    # Normalizza i separatori di percorso
    file_path = file_path.replace('\\', '/').replace('//', '/')
    
    # Rimuovi slash iniziali e finali
    file_path = file_path.strip('/')
    
    print(f"clean_file_path - output: {file_path}")
    return file_path

@staff_member_required
def file_manager(request):
    """Vista per la gestione dei file di sistema"""
    # Definizione delle categorie di file
    categories = {
        'profile_pics': {
            'name': 'Foto Profilo',
            'path': 'profile_pics',
            'icon': 'fas fa-user-circle'
        },
        'personal_documents': {
            'name': 'Documenti Personali',
            'path': 'personal_documents',
            'icon': 'fas fa-file-alt'
        },
        'transaction_files': {
            'name': 'File Transazioni',
            'path': 'transaction_files',
            'icon': 'fas fa-exchange-alt'
        }
    }
    
    # Gestione del caricamento di nuovi file
    if request.method == 'POST' and 'upload_file' in request.POST:
        category = request.POST.get('category')
        if category in categories:
            files = request.FILES.getlist('files')
            for file in files:
                # Gestione della struttura delle cartelle
                subfolder = request.POST.get('subfolder', '')
                if subfolder:
                    upload_path = os.path.join(categories[category]['path'], subfolder)
                else:
                    upload_path = categories[category]['path']
                
                # Assicurati che la directory esista
                full_path = os.path.join(settings.MEDIA_ROOT, upload_path)
                os.makedirs(full_path, exist_ok=True)
                
                # Salva il file
                file_path = os.path.join(upload_path, file.name)
                with open(os.path.join(settings.MEDIA_ROOT, file_path), 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                
                messages.success(request, f'File {file.name} caricato con successo')
    
    # Gestione dell'eliminazione dei file
    if request.method == 'POST' and 'delete_file' in request.POST:
        file_path = request.POST.get('file_path')
        category = request.POST.get('category')
        
        if file_path:
            # Pulisci e normalizza il percorso
            file_path = clean_file_path(file_path)
            
            if not file_path:
                messages.error(request, 'Percorso del file non valido')
                return redirect('Cripto1:file_manager')
            
            # Assicurati che il percorso sia relativo a MEDIA_ROOT
            if file_path.startswith('/'):
                file_path = file_path[1:]
            
            # Normalizza il percorso per gestire correttamente i separatori
            file_path = os.path.normpath(file_path)
            full_path = os.path.join(settings.MEDIA_ROOT, file_path)
            
            # Log per debug
            print(f"Tentativo di eliminare il file: {full_path}")
            print(f"Il file esiste: {os.path.exists(full_path)}")
            print(f"È un file: {os.path.isfile(full_path) if os.path.exists(full_path) else 'N/A'}")
            print(f"È una directory: {os.path.isdir(full_path) if os.path.exists(full_path) else 'N/A'}")
            print(f"MEDIA_ROOT: {settings.MEDIA_ROOT}")
            print(f"Percorso ricevuto originale: {request.POST.get('file_path')}")
            print(f"Percorso pulito: {file_path}")
            
            try:
                if os.path.exists(full_path):
                    if os.path.isfile(full_path):
                        os.remove(full_path)
                        messages.success(request, f'File eliminato con successo')
                    elif os.path.isdir(full_path):
                        import shutil
                        shutil.rmtree(full_path)
                        messages.success(request, f'Cartella eliminata con successo')
                    else:
                        messages.error(request, 'Percorso non valido')
                else:
                    messages.error(request, f'File o cartella non trovata: {file_path}')
                    # Aggiungi più dettagli per il debug
                    print(f"Percorso completo non trovato: {full_path}")
                    # Prova a listare i file nella directory padre per debug
                    parent_dir = os.path.dirname(full_path)
                    if os.path.exists(parent_dir):
                        print(f"File nella directory padre {parent_dir}:")
                        try:
                            for item in os.listdir(parent_dir):
                                print(f"  - {item}")
                        except Exception as e:
                            print(f"Errore nel listare la directory: {e}")
            except Exception as e:
                messages.error(request, f'Errore durante l\'eliminazione: {str(e)}')
                print(f"Errore durante l'eliminazione: {e}")
        else:
            messages.error(request, 'Percorso del file non specificato')
    
    # Gestione della creazione di cartelle
    if request.method == 'POST' and 'create_folder' in request.POST:
        category = request.POST.get('category')
        folder_name = request.POST.get('folder_name')
        parent_folder = request.POST.get('parent_folder', '')
        
        if category in categories and folder_name:
            if parent_folder:
                new_folder_path = os.path.join(settings.MEDIA_ROOT, categories[category]['path'], parent_folder, folder_name)
            else:
                new_folder_path = os.path.join(settings.MEDIA_ROOT, categories[category]['path'], folder_name)
            
            os.makedirs(new_folder_path, exist_ok=True)
            messages.success(request, f'Cartella {folder_name} creata con successo')
    
    # Raccolta dei file per categoria
    category_files = {}
    search_query = request.GET.get('search', '')
    current_category = request.GET.get('category', '')
    
    if current_category and current_category in categories:
        # Visualizza solo la categoria selezionata
        categories_to_show = {current_category: categories[current_category]}
    else:
        # Visualizza tutte le categorie
        categories_to_show = categories
    
    for category_key, category_info in categories_to_show.items():
        category_path = os.path.join(settings.MEDIA_ROOT, category_info['path'])
        category_files[category_key] = {'name': category_info['name'], 'icon': category_info['icon'], 'files': []}
        
        # Verifica se la directory esiste
        if os.path.exists(category_path):
            # Raccolta ricorsiva di file e cartelle
            for root, dirs, files in os.walk(category_path):
                # Calcola il percorso relativo rispetto a MEDIA_ROOT
                rel_path = os.path.relpath(root, settings.MEDIA_ROOT)
                
                # Aggiungi le cartelle
                for dir_name in dirs:
                    dir_info = {
                        'name': dir_name,
                        'path': os.path.join(rel_path, dir_name),
                        'is_dir': True,
                        'size': '',
                        'modified': datetime.fromtimestamp(os.path.getmtime(os.path.join(root, dir_name))).strftime('%d/%m/%Y %H:%M')
                    }
                    
                    # Filtra in base alla ricerca
                    if not search_query or search_query.lower() in dir_name.lower():
                        category_files[category_key]['files'].append(dir_info)
                
                # Aggiungi i file
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    file_size = os.path.getsize(file_path)
                    
                    # Debug per capire il problema del carattere speciale
                    rel_path_debug = os.path.relpath(root, settings.MEDIA_ROOT)
                    
                    # Pulisci il nome del file se contiene caratteri non validi
                    clean_file_name = re.sub(r'[^\x00-\x7F]', '', file_name)
                    if clean_file_name != file_name:
                        print(f"WARNING - Nome file pulito: '{file_name}' -> '{clean_file_name}'")
                        file_name = clean_file_name
                    
                    file_path_debug = os.path.join(rel_path_debug, file_name)
                    
                    print(f"DEBUG - root: {root}")
                    print(f"DEBUG - file_name: {file_name}")
                    print(f"DEBUG - rel_path: {rel_path_debug}")
                    print(f"DEBUG - file_path costruito: {file_path_debug}")
                    print(f"DEBUG - caratteri nel file_path: {[ord(c) for c in file_path_debug]}")
                    
                    file_info = {
                        'name': file_name,
                        'path': file_path_debug,
                        'is_dir': False,
                        'size': format_file_size(file_size),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%d/%m/%Y %H:%M'),
                        'url': os.path.join(settings.MEDIA_URL, rel_path_debug, file_name)
                    }
                    
                    # Filtra in base alla ricerca
                    if not search_query or search_query.lower() in file_name.lower():
                        category_files[category_key]['files'].append(file_info)
    
    context = {
        'categories': categories,
        'category_files': category_files,
        'current_category': current_category,
        'search_query': search_query
    }
    
    return render(request, 'Cripto1/file_manager.html', context)

@login_required
@user_manager_forbidden
def create_transaction_from_document(request, document_id):
    # Recupera il documento personale
    document = get_object_or_404(PersonalDocument, id=document_id, user=request.user)
    user_profile = UserProfile.objects.get(user=request.user)
    
    # Verifica se l'utente ha il ruolo "external"
    if user_profile.has_role('external'):
        messages.error(request, 'Gli utenti con ruolo "external" non possono inviare transazioni.')
        return redirect('Cripto1:personal_documents')
    
    if request.method == 'POST':
        try:
            receiver_key = request.POST.get('receiver_key')
            is_encrypted = request.POST.get('is_encrypted', 'false').lower() in ['true', 'on', '1']
            is_shareable = request.POST.get('is_shareable', 'false').lower() in ['true', 'on', '1']
            private_key_password = request.POST.get('private_key_password')
            max_downloads_str = request.POST.get('max_downloads')
            max_downloads = int(max_downloads_str) if max_downloads_str and max_downloads_str.isdigit() else None
            
            user_org = request.user.userprofile.organization
            receiver_profile = UserProfile.objects.filter(
                user_key=receiver_key,
                organization=user_org
            ).first()
            if not receiver_profile:
                messages.error(request, 'Destinatario non trovato nella tua organizzazione.')
                return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            receiver = receiver_profile.user

            # Leggi il file dal documento personale
            with default_storage.open(document.file.name, 'rb') as f:
                file_content = f.read()
            
            # Se il documento è cifrato, prima decifralo
            if document.is_encrypted:
                try:
                    # Decifra la chiave simmetrica con la chiave privata dell'utente
                    decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                    if not decrypted_private_key:
                        messages.error(request, 'Password della chiave privata errata.')
                        return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
                    
                    symmetric_key = decrypted_private_key.decrypt(
                        document.encrypted_symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Decifra il contenuto del file
                    f = Fernet(symmetric_key)
                    file_content = f.decrypt(file_content)
                    
                    # Usa il nome originale del file
                    original_filename = document.original_filename
                except Exception as e:
                    messages.error(request, f'Errore durante la decifratura del documento: {str(e)}')
                    return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            else:
                original_filename = os.path.basename(document.file.name)

            # Salva la chiave pubblica del mittente
            sender_public_key = user_profile.public_key

            # Crea i dati della transazione
            transaction_data = {
                'type': 'file',
                'sender': request.user.id,
                'receiver': receiver.id,
                'sender_public_key': sender_public_key,
                'content': '',  # Per i file, il contenuto è vuoto
                'timestamp': time.time(),
                'is_encrypted': is_encrypted,
                'is_shareable': is_shareable
            }
            
            # Gestione del file
            encrypted_symmetric_key_for_db = None

            if is_encrypted:
                try:
                    # Genera una chiave simmetrica per la cifratura del file
                    symmetric_key = Fernet.generate_key()
                    f = Fernet(symmetric_key)
                    encrypted_file_content = f.encrypt(file_content)

                    # Cifra la chiave simmetrica con la chiave pubblica RSA del destinatario
                    receiver_public_key = serialization.load_pem_public_key(
                        receiver_profile.public_key.encode(),
                        backend=default_backend()
                    )
                    encrypted_symmetric_key_for_db = receiver_public_key.encrypt(
                        symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Cifra la chiave simmetrica per il mittente
                    sender_public_key_obj = serialization.load_pem_public_key(
                        user_profile.public_key.encode(),
                        backend=default_backend()
                    )
                    sender_encrypted_symmetric_key = sender_public_key_obj.encrypt(
                        symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    filename = f"{uuid.uuid4().hex}.encrypted"
                    file_to_save = ContentFile(encrypted_file_content)
                    transaction_data['original_filename'] = original_filename
                    transaction_data['encrypted_symmetric_key'] = encrypted_symmetric_key_for_db.hex()
                    transaction_data['sender_encrypted_symmetric_key'] = sender_encrypted_symmetric_key.hex()
                    transaction_data['receiver_public_key_at_encryption'] = receiver_profile.public_key

                except Exception as e:
                    messages.error(request, f'Errore durante la cifratura del file: {str(e)}')
                    return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            else:
                filename = f"{time.time()}_{original_filename}"
                file_to_save = ContentFile(file_content)

            file_path = default_storage.save(f'transaction_files/{filename}', file_to_save)
            transaction_data['file'] = file_path

            # Calcola l'hash della transazione
            transaction_string_for_signing = json.dumps(transaction_data, sort_keys=True).encode()
            transaction_hash = hashlib.sha256(transaction_string_for_signing).hexdigest()
            
            # Firma la transazione
            private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
            if not private_key:
                messages.error(request, 'Errore durante il recupero della chiave privata.')
                return redirect('Cripto1:send_document_as_transaction', document_id=document_id)
            
            data_to_sign = transaction_hash.encode()
            signature = private_key.sign(
                data_to_sign,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Crea la transazione
            new_tx = Transaction.objects.create(
                type='file',
                sender=request.user,
                receiver=receiver,
                sender_public_key=sender_public_key,
                content='',
                file=transaction_data.get('file'),
                timestamp=transaction_data['timestamp'],
                transaction_hash=transaction_hash,
                signature=signature.hex(),
                is_encrypted=is_encrypted,
                is_shareable=transaction_data.get('is_shareable', False),
                original_filename=transaction_data.get('original_filename', ''),
                encrypted_symmetric_key=bytes.fromhex(transaction_data['encrypted_symmetric_key']) if 'encrypted_symmetric_key' in transaction_data and transaction_data['encrypted_symmetric_key'] else None,
                sender_encrypted_symmetric_key=bytes.fromhex(transaction_data['sender_encrypted_symmetric_key']) if 'sender_encrypted_symmetric_key' in transaction_data and transaction_data['sender_encrypted_symmetric_key'] else None,
                receiver_public_key_at_encryption=transaction_data.get('receiver_public_key_at_encryption', ''),
                max_downloads=max_downloads
            )

            # Aggiungi alle transazioni in sospeso
            pending_transactions_ids = request.session.get('pending_transactions_ids', [])
            pending_transactions_ids.append(new_tx.id)
            request.session['pending_transactions_ids'] = pending_transactions_ids

            messages.success(request, 'Transazione creata e firmata. In attesa di mining.')
            return redirect('Cripto1:all_transactions')

        except Exception as e:
            messages.error(request, f'Errore durante la creazione della transazione: {str(e)}')
            return redirect('Cripto1:send_document_as_transaction', document_id=document_id)

    # Se GET, mostra il form di invio documento
    return render(request, 'Cripto1/send_document_as_transaction.html', {'document': document})

@login_required
def manage_user_storage(request, user_id):
    """Vista per gestire la quota storage di un utente (solo manager)"""
    user = get_object_or_404(User, id=user_id)
    user_profile = user.userprofile
    
    if request.method == 'POST':
        new_quota_gb = request.POST.get('storage_quota_gb')
        try:
            new_quota_bytes = int(float(new_quota_gb) * 1024 * 1024 * 1024)
            user_profile.storage_quota_bytes = new_quota_bytes
            user_profile.save()
            messages.success(request, f'Quota storage aggiornata a {new_quota_gb}GB per {user.username}')
            return redirect('Cripto1:user_detail', user_id=user_id)
        except ValueError:
            messages.error(request, 'Valore quota non valido')
    
    # Aggiorna l'utilizzo corrente
    user_profile.update_storage_usage()
    
    context = {
        'user': user,
        'user_profile': user_profile,
        'storage_quota_gb': user_profile.get_storage_quota_gb(),
        'storage_used_gb': user_profile.get_storage_used_gb(),
        'storage_percentage': user_profile.get_storage_percentage(),
    }
    
    return render(request, 'Cripto1/manage_user_storage.html', context)

def format_file_size(size_bytes):
    """Formatta la dimensione del file in un formato leggibile"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

@login_required
@user_passes_test(lambda u: u.is_staff)
def session_management(request):
    """Vista per gestire le sessioni attive"""
    session_cache = caches['sessions'] if 'sessions' in settings.CACHES else caches['default']
    
    # Ottieni tutte le sessioni attive
    active_sessions = []
    all_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    
    for session in all_sessions:
        session_data = session.get_decoded()
        user_id = session_data.get('_auth_user_id')
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                cache_key = f'user_sessions_{user_id}'
                user_sessions = session_cache.get(cache_key, [])
                
                active_sessions.append({
                    'session_key': session.session_key,
                    'user': user,
                    'expire_date': session.expire_date,
                    'last_activity': session_data.get('_last_activity'),
                    'ip_address': session_data.get('_session_ip'),
                    'concurrent_count': len(user_sessions)
                })
            except User.DoesNotExist:
                continue
                
    context = {
        'active_sessions': active_sessions,
        'total_sessions': len(active_sessions)
    }
    
    return render(request, 'Cripto1/session_management.html', context)

@login_required
def terminate_session(request):
    """Termina una sessione specifica"""
    if request.method == 'POST':
        # Gestisci sia i dati POST che JSON
        if request.content_type == 'application/json':
            import json
            try:
                data = json.loads(request.body)
                session_key = data.get('session_key')
            except json.JSONDecodeError:
                return JsonResponse({'success': False, 'message': 'Dati JSON non validi'})
        else:
            session_key = request.POST.get('session_key')
            
        if session_key and request.user.is_staff:
            try:
                session = Session.objects.get(session_key=session_key)
                session.delete()
                return JsonResponse({'success': True, 'message': 'Sessione terminata con successo'})
            except Session.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Sessione non trovata'})
        return JsonResponse({'success': False, 'message': 'Permessi insufficienti'})
    return JsonResponse({'success': False, 'message': 'Metodo non consentito'})

@external_forbidden
@login_required
def my_sessions(request):
    """Vista per l'utente per vedere le proprie sessioni"""
    session_cache = caches['sessions'] if 'sessions' in settings.CACHES else caches['default']
    cache_key = f'user_sessions_{request.user.id}'
    user_sessions = session_cache.get(cache_key, [])
    
    current_time = timezone.now().timestamp()
    active_sessions = []
    
    for session_data in user_sessions:
        if session_data['expires'] > current_time:
            active_sessions.append({
                'session_key': session_data['session_key'][:8] + '...',  # Mostra solo parte della chiave
                'last_activity': timezone.datetime.fromtimestamp(session_data['last_activity']),
                'ip_address': session_data['ip_address'],
                'user_agent': session_data['user_agent'],
                'is_current': session_data['session_key'] == request.session.session_key
            })
            
    context = {
        'active_sessions': active_sessions,
        'max_concurrent': getattr(settings, 'SESSION_MAX_CONCURRENT', 3)
    }
    
    return render(request, 'Cripto1/my_sessions.html', context)

@external_forbidden
@login_required
def smart_contracts_dashboard(request):
    """Dashboard principale per smart contracts"""
    user_contracts = SmartContract.objects.filter(creator=request.user)
    
    # Statistiche
    stats = {
        'total_contracts': user_contracts.count(),
        'deployed_contracts': user_contracts.filter(status='DEPLOYED').count(),
        'draft_contracts': user_contracts.filter(status='DRAFT').count(),
        'verified_contracts': user_contracts.filter(is_verified=True).count(),
    }
    
    # Contratti recenti
    recent_contracts = user_contracts.order_by('-created_at')[:5]
    
    # Esecuzioni recenti
    from .models import ContractExecution
    recent_executions = ContractExecution.objects.filter(
        contract__creator=request.user
    ).order_by('-timestamp')[:10]
    
    # Template popolari
    from .models import ContractTemplate
    popular_templates = ContractTemplate.objects.filter(
        is_public=True
    ).order_by('-usage_count')[:6]
    
    context = {
        'stats': stats,
        'recent_contracts': recent_contracts,
        'recent_executions': recent_executions,
        'popular_templates': popular_templates,
    }
    
    return render(request, 'Cripto1/smart_contracts/dashboard.html', context)

@external_forbidden
@login_required
def contract_list(request):
    """Lista di tutti i contratti dell'utente"""
    contracts = SmartContract.objects.filter(creator=request.user)
    
    # Filtri
    contract_type = request.GET.get('type')
    status = request.GET.get('status')
    search = request.GET.get('search')
    
    if contract_type:
        contracts = contracts.filter(contract_type=contract_type)
    if status:
        contracts = contracts.filter(status=status)
    if search:
        contracts = contracts.filter(
            Q(name__icontains=search) | 
            Q(description__icontains=search)
        )
    
    # Paginazione
    paginator = Paginator(contracts, 12)
    page = request.GET.get('page')
    contracts = paginator.get_page(page)
    
    context = {
        'contracts': contracts,
        'contract_types': SmartContract.CONTRACT_TYPES,
        'status_choices': SmartContract.STATUS_CHOICES,
        'current_filters': {
            'type': contract_type,
            'status': status,
            'search': search,
        }
    }
    
    return render(request, 'Cripto1/smart_contracts/contract_list.html', context)

@external_forbidden
@login_required
def contract_create(request):
    """Crea un nuovo smart contract"""
    if request.method == 'POST':
        from .forms import SmartContractForm
        form = SmartContractForm(request.POST)
        if form.is_valid():
            contract = form.save(commit=False)
            contract.creator = request.user
            contract.owner = request.user
            contract.save()
            
            messages.success(request, f'Smart Contract "{contract.name}" creato con successo!')
            return redirect('Cripto1:contract_detail', pk=contract.pk)
    else:
        from .forms import SmartContractForm
        form = SmartContractForm()
    
    # Template disponibili
    from .models import ContractTemplate
    templates = ContractTemplate.objects.filter(
        Q(is_public=True) | Q(created_by=request.user)
    ).order_by('-usage_count')
    
    context = {
        'form': form,
        'templates': templates,
    }
    
    return render(request, 'Cripto1/smart_contracts/contract_create.html', context)

@external_forbidden
@login_required
def contract_detail(request, pk):
    """Dettagli di un smart contract"""
    contract = get_object_or_404(SmartContract, pk=pk, creator=request.user)
    
    # Funzioni del contratto
    functions = contract.functions.all()
    
    # Eventi del contratto
    events = contract.events.all()
    
    # Esecuzioni recenti
    recent_executions = contract.executions.order_by('-timestamp')[:10]
    
    # Statistiche
    stats = {
        'total_executions': contract.executions.count(),
        'successful_executions': contract.executions.filter(status='SUCCESS').count(),
        'failed_executions': contract.executions.filter(status='FAILED').count(),
        'total_gas_used': contract.executions.aggregate(
            total=Sum('gas_used')
        )['total'] or 0,
    }
    
    context = {
        'contract': contract,
        'functions': functions,
        'events': events,
        'recent_executions': recent_executions,
        'stats': stats,
    }
    
    return render(request, 'Cripto1/smart_contracts/contract_detail.html', context)

@external_forbidden
@login_required
def contract_compile(request, pk):
    """Compila un smart contract"""
    contract = get_object_or_404(SmartContract, pk=pk, creator=request.user)
    
    if request.method == 'POST':
        try:
            # Simulazione compilazione (in produzione useresti solc)
            compilation_result = compile_contract(contract.source_code)
            
            contract.bytecode = compilation_result['bytecode']
            contract.abi = compilation_result['abi']
            contract.status = 'COMPILED'
            contract.save()
            
            # Crea funzioni ed eventi dal ABI
            create_functions_from_abi(contract, compilation_result['abi'])
            
            messages.success(request, 'Contratto compilato con successo!')
            
        except Exception as e:
            messages.error(request, f'Errore durante la compilazione: {str(e)}')
    
    return redirect('Cripto1:contract_detail', pk=pk)

@external_forbidden
@login_required
def contract_deploy(request, pk):
    """Deploy di un smart contract"""
    contract = get_object_or_404(SmartContract, pk=pk, creator=request.user)
    
    if contract.status != 'COMPILED':
        messages.error(request, 'Il contratto deve essere compilato prima del deploy.')
        return redirect('Cripto1:contract_detail', pk=pk)
    
    if request.method == 'POST':
        from .forms import ContractDeployForm
        form = ContractDeployForm(request.POST)
        if form.is_valid():
            try:
                # Simulazione deploy (in produzione useresti web3.py)
                deployment_result = deploy_contract(
                    contract.bytecode,
                    form.cleaned_data['constructor_params'],
                    form.cleaned_data['gas_limit'],
                    form.cleaned_data['gas_price']
                )
                
                contract.contract_address = deployment_result['address']
                contract.deployment_hash = deployment_result['tx_hash']
                contract.gas_used = deployment_result['gas_used']
                contract.gas_price = form.cleaned_data['gas_price']
                contract.status = 'DEPLOYED'
                contract.deployed_at = timezone.now()
                contract.save()
                
                messages.success(request, f'Contratto deployato all\'indirizzo: {contract.contract_address}')
                return redirect('Cripto1:contract_detail', pk=pk)
                
            except Exception as e:
                messages.error(request, f'Errore durante il deploy: {str(e)}')
    else:
        from .forms import ContractDeployForm
        form = ContractDeployForm()
    
    context = {
        'contract': contract,
        'form': form,
    }
    
    return render(request, 'Cripto1/smart_contracts/contract_deploy.html', context)

@external_forbidden
@login_required
def contract_interact(request, pk):
    """Interfaccia per interagire con un smart contract"""
    contract = get_object_or_404(SmartContract, pk=pk, creator=request.user)
    
    if contract.status != 'DEPLOYED':
        messages.error(request, 'Il contratto deve essere deployato per poter interagire.')
        return redirect('Cripto1:contract_detail', pk=pk)
    
    functions = contract.functions.all()
    
    context = {
        'contract': contract,
        'functions': functions,
    }
    
    return render(request, 'Cripto1/smart_contracts/contract_interact.html', context)

@external_forbidden
@login_required
def execute_function(request, contract_pk, function_pk):
    """Esegue una funzione del contratto"""
    contract = get_object_or_404(SmartContract, pk=contract_pk, creator=request.user)
    from .models import ContractFunction
    function = get_object_or_404(ContractFunction, pk=function_pk, contract=contract)
    
    if request.method == 'POST':
        try:
            input_data = {}
            for param in function.inputs:
                param_name = param['name']
                param_value = request.POST.get(param_name)
                input_data[param_name] = param_value
            
            # Simulazione esecuzione (in produzione useresti web3.py)
            execution_result = execute_contract_function(
                contract.contract_address,
                function.name,
                input_data
            )
            
            # Salva l'esecuzione
            from .models import ContractExecution
            execution = ContractExecution.objects.create(
                contract=contract,
                function=function,
                caller=request.user,
                input_data=input_data,
                output_data=execution_result['output'],
                transaction_hash=execution_result['tx_hash'],
                block_number=execution_result['block_number'],
                gas_used=execution_result['gas_used'],
                gas_price=execution_result['gas_price'],
                status='SUCCESS'
            )
            
            messages.success(request, f'Funzione "{function.name}" eseguita con successo!')
            return JsonResponse({
                'success': True,
                'result': execution_result['output'],
                'tx_hash': execution_result['tx_hash']
            })
            
        except Exception as e:
            messages.error(request, f'Errore durante l\'esecuzione: {str(e)}')
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Metodo non consentito'})


# Funzioni di utilità per la compilazione e deploy (simulazione)
@external_forbidden
def compile_contract(source_code):
    """Simula la compilazione di un contratto"""
    # In produzione useresti py-solc-x o solcx
    return {
        'bytecode': '0x608060405234801561001057600080fd5b50...',
        'abi': [
            {
                "inputs": [],
                "name": "totalSupply",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
    }

@external_forbidden
def deploy_contract(bytecode, constructor_params, gas_limit, gas_price):
    """Simula il deploy di un contratto"""
    import secrets
    return {
        'address': f"0x{secrets.token_hex(20)}",
        'tx_hash': f"0x{secrets.token_hex(32)}",
        'gas_used': gas_limit // 2,
        'block_number': 12345678
    }

@external_forbidden
def execute_contract_function(contract_address, function_name, input_data):
    """Simula l'esecuzione di una funzione del contratto"""
    import secrets
    return {
        'output': {'result': 'success', 'value': '1000000000000000000'},
        'tx_hash': f"0x{secrets.token_hex(32)}",
        'block_number': 12345679,
        'gas_used': 21000,
        'gas_price': 20000000000
    }

@external_forbidden
def create_functions_from_abi(contract, abi):
    """Crea le funzioni del contratto dall'ABI"""
    from .models import ContractFunction
    for item in abi:
        if item.get('type') == 'function':
            function, created = ContractFunction.objects.get_or_create(
                contract=contract,
                name=item['name'],
                defaults={
                    'function_type': item.get('stateMutability', 'nonpayable').upper(),
                    'inputs': item.get('inputs', []),
                    'outputs': item.get('outputs', []),
                }
            )

@external_forbidden
@login_required
def contract_create_from_template(request, template_id):
    """Crea un contratto da un template"""
    try:
        from .models import ContractTemplate
        template = ContractTemplate.objects.get(id=template_id)
    except ContractTemplate.DoesNotExist:
        messages.error(request, 'Template non trovato')
        return redirect('Cripto1:contract_templates')
    
    if request.method == 'POST':
        from .forms import SmartContractForm
        form = SmartContractForm(request.POST)
        if form.is_valid():
            contract = form.save(commit=False)
            contract.creator = request.user
            contract.owner = request.user
            contract.source_code = template.source_code
            contract.abi = template.abi
            contract.save()
            messages.success(request, 'Contratto creato con successo dal template!')
            return redirect('Cripto1:contract_detail', pk=contract.pk)
    else:
        # Pre-popola il form con i dati del template
        initial_data = {
            'name': template.name,
            'description': template.description,
            'source_code': template.source_code,
        }
        from .forms import SmartContractForm
        form = SmartContractForm(initial=initial_data)
    
    return render(request, 'Cripto1/smart_contracts/create_from_template.html', {
        'form': form,
        'template': template
    })

@external_forbidden
@login_required
def contract_edit(request, pk):
    """Modifica un contratto esistente"""
    try:
        contract = SmartContract.objects.get(pk=pk, owner=request.user)
    except SmartContract.DoesNotExist:
        messages.error(request, 'Contratto non trovato o non hai i permessi per modificarlo')
        return redirect('Cripto1:contract_list')
    
    if request.method == 'POST':
        from .forms import SmartContractForm
        form = SmartContractForm(request.POST, instance=contract)
        if form.is_valid():
            form.save()
            messages.success(request, 'Contratto aggiornato con successo!')
            return redirect('Cripto1:contract_detail', pk=contract.pk)
    else:
        from .forms import SmartContractForm
        form = SmartContractForm(instance=contract)
    
    return render(request, 'Cripto1/smart_contracts/edit.html', {
        'form': form,
        'contract': contract
    })

@external_forbidden
@login_required
def contract_templates(request):
    """Lista dei template di contratti disponibili"""
    from .models import ContractTemplate
    templates = ContractTemplate.objects.filter(is_public=True).order_by('-created_at')
    
    return render(request, 'Cripto1/smart_contracts/templates.html', {
        'templates': templates
    })

@external_forbidden
@login_required
def create_template(request):
    """Crea un nuovo template di contratto"""
    if request.method == 'POST':
        from .forms import ContractTemplateForm
        form = ContractTemplateForm(request.POST)
        if form.is_valid():
            template = form.save(commit=False)
            template.created_by = request.user
            template.save()
            messages.success(request, 'Template creato con successo!')
            return redirect('Cripto1:contract_templates')
    else:
        from .forms import ContractTemplateForm
        form = ContractTemplateForm()
    
    return render(request, 'Cripto1/smart_contracts/create_template.html', {
        'form': form
    })

@login_required
def search_transactions_ajax(request):
    """Vista AJAX per la ricerca delle transazioni"""
    try:
        if request.method == 'GET' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            search_query = request.GET.get('q', '').strip()
            page = request.GET.get('page', 1)
            
            # Base queryset filtrato per organizzazione
            user_org = request.user.userprofile.organization
            if request.user.is_superuser:
                transactions_list = Transaction.objects.filter(
                    sender__userprofile__organization=user_org,
                    receiver__userprofile__organization=user_org
                )
            else:
                transactions_list = Transaction.objects.filter(
                    models.Q(sender__userprofile__organization=user_org) & 
                    models.Q(receiver__userprofile__organization=user_org) &
                    (models.Q(sender=request.user) | models.Q(receiver=request.user))
                )
            
            # Applica filtri di ricerca SOLO per hash completo
            if search_query:
                transactions_list = transactions_list.filter(
                    transaction_hash__exact=search_query
                )
            
            transactions_list = transactions_list.order_by('-timestamp')
            
            # Processa le transazioni
            for tx in transactions_list:
                try:
                    tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
                    if tx.sender == request.user:
                        tx.direction = "Inviata"
                    elif tx.receiver == request.user:
                        tx.direction = "Ricevuta"
                    else:
                        tx.direction = "Tra altri utenti"
                except Exception as e:
                    # Se c'è un errore con una transazione specifica, salta
                    continue
            
            # Paginazione
            paginator = Paginator(transactions_list, 10)
            try:
                transactions = paginator.page(page)
            except PageNotAnInteger:
                transactions = paginator.page(1)
            except EmptyPage:
                transactions = paginator.page(paginator.num_pages)
            
            # Prova a renderizzare il template
            try:
                from django.template.loader import render_to_string
                html = render_to_string('Cripto1/partials/transactions_list.html', {
                    'all_transactions': transactions,
                    'request': request
                })
            except Exception as template_error:
                # Se il template fallisce, restituisci un HTML semplice
                html = f"<div class='alert alert-warning'>Template error: {str(template_error)}</div>"
            
            return JsonResponse({
                'html': html,
                'has_previous': transactions.has_previous(),
                'has_next': transactions.has_next(),
                'current_page': transactions.number,
                'total_pages': transactions.paginator.num_pages,
                'total_results': transactions.paginator.count,
                'debug': f'Query: {search_query}, Results: {transactions_list.count()}'
            })
        
        return JsonResponse({'error': 'Invalid request method or headers'}, status=400)
        
    except Exception as e:
        import traceback
        return JsonResponse({
            'error': 'Server error',
            'message': str(e),
            'traceback': traceback.format_exc() if hasattr(settings, 'DEBUG') and settings.DEBUG else None
        }, status=500)

@login_required
def personal_statistics(request):
    user_profile = UserProfile.objects.get(user=request.user)
    user_org = request.user.userprofile.organization
    
    # Statistiche delle transazioni filtrate per organizzazione
    total_transactions = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user))
    ).count()
    
    sent_transactions = Transaction.objects.filter(
        sender=request.user,
        receiver__userprofile__organization=user_org
    ).count()
    received_transactions = Transaction.objects.filter(
        receiver=request.user,
        sender__userprofile__organization=user_org
    ).count()
    
    # Statistiche per tipo filtrate per organizzazione
    text_transactions = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        type='text'
    ).count()
    
    file_transactions = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        type='file'
    ).count()
    
    # Transazioni crittografate filtrate per organizzazione
    encrypted_transactions = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        is_encrypted=True
    ).count()
    
    # Documenti personali
    personal_documents_count = PersonalDocument.objects.filter(user=request.user).count()
    
    # Statistiche temporali (ultimo mese)
    last_month = timezone.now() - timedelta(days=30)
    last_month_timestamp = last_month.timestamp()
    
    recent_transactions = Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        timestamp__gte=last_month_timestamp
    ).count()
    
    # Transazioni per mese (ultimi 6 mesi)
    monthly_stats = []
    for i in range(6):
        month_start = timezone.now() - timedelta(days=30 * (i + 1))
        month_end = timezone.now() - timedelta(days=30 * i)
        
        month_transactions = Transaction.objects.filter(
            models.Q(sender__userprofile__organization=user_org) & 
            models.Q(receiver__userprofile__organization=user_org) &
            (models.Q(sender=request.user) | models.Q(receiver=request.user)),
            timestamp__gte=month_start.timestamp(),
            timestamp__lt=month_end.timestamp()
        ).count()
        
        monthly_stats.append({
            'month': month_start.strftime('%B %Y'),
            'count': month_transactions
        })
    
    monthly_stats.reverse()  # Ordine cronologico
    
    # Aggiorna e calcola le statistiche dello storage
    user_profile.update_storage_usage()
    
    # Calcoli per le statistiche dello storage
    total_storage_mb = round(user_profile.storage_used_bytes / (1024 * 1024), 2)
    storage_limit_mb = round(user_profile.storage_quota_bytes / (1024 * 1024), 2)
    storage_percentage = round(user_profile.get_storage_percentage(), 1)
    remaining_storage_mb = round((user_profile.storage_quota_bytes - user_profile.storage_used_bytes) / (1024 * 1024), 2)
    
    # Calcoli dettagliati per categoria
    personal_docs_storage = 0
    transaction_files_storage = 0
    images_storage = 0
    pdf_storage = 0
    other_files_storage = 0
    
    # Calcola storage documenti personali
    for doc in user_profile.user.personal_documents.all():
        if doc.file and hasattr(doc.file, 'size'):
            size_mb = doc.file.size / (1024 * 1024)
            personal_docs_storage += size_mb
            
            # Categorizza per tipo
            if doc.file.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp')):
                images_storage += size_mb
            elif doc.file.name.lower().endswith('.pdf'):
                pdf_storage += size_mb
            else:
                other_files_storage += size_mb
    
    # Calcola storage file transazioni filtrati per organizzazione
    for tx in Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        type='file', file__isnull=False
    ):
        if tx.file and hasattr(tx.file, 'size'):
            size_mb = tx.file.size / (1024 * 1024)
            transaction_files_storage += size_mb
            
            # Categorizza per tipo
            if tx.file.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp')):
                images_storage += size_mb
            elif tx.file.name.lower().endswith('.pdf'):
                pdf_storage += size_mb
            else:
                other_files_storage += size_mb
    
    # File più grandi (top 5)
    all_files = []
    
    # Aggiungi documenti personali
    for doc in user_profile.user.personal_documents.all():
        if doc.file and hasattr(doc.file, 'size'):
            all_files.append({
                'name': doc.title or doc.file.name,
                'size_mb': round(doc.file.size / (1024 * 1024), 2),
                'upload_date': doc.uploaded_at
            })
    
    # Aggiungi file transazioni filtrati per organizzazione
    for tx in Transaction.objects.filter(
        models.Q(sender__userprofile__organization=user_org) & 
        models.Q(receiver__userprofile__organization=user_org) &
        (models.Q(sender=request.user) | models.Q(receiver=request.user)),
        type='file', file__isnull=False
    ):
        if tx.file and hasattr(tx.file, 'size'):
            # Converti timestamp in datetime timezone-aware
            upload_datetime = timezone.datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
            all_files.append({
                'name': tx.file.name,
                'size_mb': round(tx.file.size / (1024 * 1024), 2),
                'upload_date': upload_datetime  # Ora è timezone-aware
            })
    
    # Ordina per dimensione e prendi i primi 5
    largest_files = sorted(all_files, key=lambda x: x['size_mb'], reverse=True)[:5]
    
    # File più recenti (ultimi 5)
    recent_files = sorted(all_files, key=lambda x: x['upload_date'], reverse=True)[:5]
    
    # Timeline settimanale (ultimi 7 giorni)
    weekly_sent = [0] * 7
    weekly_received = [0] * 7
    
    for i in range(7):
        day_start = timezone.now() - timedelta(days=i+1)
        day_end = timezone.now() - timedelta(days=i)
        
        sent_count = Transaction.objects.filter(
            sender=request.user,
            receiver__userprofile__organization=user_org,
            timestamp__gte=day_start.timestamp(),
            timestamp__lt=day_end.timestamp()
        ).count()
        
        received_count = Transaction.objects.filter(
            receiver=request.user,
            sender__userprofile__organization=user_org,
            timestamp__gte=day_start.timestamp(),
            timestamp__lt=day_end.timestamp()
        ).count()
        
        weekly_sent[6-i] = sent_count  # Inverti l'ordine per avere lunedì-domenica
        weekly_received[6-i] = received_count
    
    # Sostituisci il vecchio calcolo di total_file_size_mb
    total_file_size_mb = total_storage_mb
    
    # Top 5 utenti con cui hai più transazioni
    from django.db.models import Count
    top_contacts = []
    
    # Utenti a cui hai inviato di più (filtrati per organizzazione)
    sent_to = Transaction.objects.filter(
        sender=request.user,
        receiver__userprofile__organization=user_org
    ).values('receiver__username').annotate(
        count=Count('receiver')
    ).order_by('-count')[:5]
    
    # Utenti da cui hai ricevuto di più (filtrati per organizzazione)
    received_from = Transaction.objects.filter(
        receiver=request.user,
        sender__userprofile__organization=user_org
    ).values('sender__username').annotate(
        count=Count('sender')
    ).order_by('-count')[:5]
    
    context = {
        'user_profile': user_profile,
        'total_transactions': total_transactions,
        'sent_transactions': sent_transactions,
        'received_transactions': received_transactions,
        'text_transactions': text_transactions,
        'file_transactions': file_transactions,
        'encrypted_transactions': encrypted_transactions,
        'personal_documents_count': personal_documents_count,
        'recent_transactions': recent_transactions,
        'monthly_stats': monthly_stats,
        'total_file_size_mb': total_file_size_mb,
        'sent_to': sent_to,
        'received_from': received_from,
        # Statistiche storage
        'total_storage_mb': total_storage_mb,
        'storage_limit_mb': storage_limit_mb,
        'storage_percentage': storage_percentage,
        'remaining_storage_mb': remaining_storage_mb,
        # Dettagli per categoria
        'personal_docs_storage_mb': round(personal_docs_storage, 2),
        'transaction_files_storage_mb': round(transaction_files_storage, 2),
        'images_storage_mb': round(images_storage, 2),
        'pdf_storage_mb': round(pdf_storage, 2),
        'other_files_storage_mb': round(other_files_storage, 2),
        # File più grandi e recenti
        'largest_files': largest_files,
        'recent_files': recent_files,
        # Timeline settimanale
        'weekly_sent': weekly_sent,
        'weekly_received': weekly_received,
    }
    
    return render(request, 'Cripto1/personal_statistics.html', context)

# Funzioni di utilità per le condivisioni
def can_share_document(user, document_type, document_id):
    """Verifica se l'utente può condividere il documento specificato"""
    try:
        if document_type == 'transaction':
            tx = Transaction.objects.get(id=document_id)
            return tx.sender == user or tx.receiver == user
        elif document_type == 'personal_document':
            doc = PersonalDocument.objects.get(id=document_id, user=user)
            return True
        elif document_type == 'created_document':
            from .models import CreatedDocument
            doc = CreatedDocument.objects.get(id=document_id, user=user)
            return True
        return False
    except (Transaction.DoesNotExist, PersonalDocument.DoesNotExist):
        return False
    except Exception:
        return False

def send_share_notification_email(shared_doc, action_type):
    """Invia email di notifica per le condivisioni"""
    try:
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        
        if action_type == 'created':
            if shared_doc.share_type == 'created_document':
                subject = f'Invito alla collaborazione da {shared_doc.owner.username}'
            else:
                subject = f'Nuovo documento condiviso da {shared_doc.owner.username}'
            template = 'emails/share_notification.html'
            recipient_email = shared_doc.shared_with.email
            recipient = shared_doc.shared_with
        elif action_type == 'accessed':
            subject = f'Il tuo documento è stato visualizzato'
            template = 'emails/share_accessed.html'
            recipient_email = shared_doc.owner.email
            recipient = shared_doc.owner
        elif action_type == 'downloaded':
            subject = f'Il tuo documento è stato scaricato'
            template = 'emails/share_downloaded.html'
            recipient_email = shared_doc.owner.email
            recipient = shared_doc.owner
        elif action_type == 'modified':
            subject = f'Il tuo documento condiviso è stato modificato'
            template = 'emails/share_modified.html'
            recipient_email = shared_doc.owner.email
            recipient = shared_doc.owner
        else:
            return  # Tipo di azione non riconosciuto
        
        context = {
            'shared_document': shared_doc,
            'recipient': recipient,
            'is_collaboration': shared_doc.share_type == 'created_document',
        }
        
        html_message = render_to_string(template, context)
        
        send_mail(
            subject=subject,
            message='',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            html_message=html_message,
            fail_silently=True
        )
        
    except Exception as e:
        print(f"Errore nell'invio email di condivisione: {e}")

@login_required
def create_share(request):
    """Crea una nuova condivisione"""
    if request.method == 'POST':
        document_type = request.POST.get('document_type')
        document_id = request.POST.get('document_id')
        shared_with_username = request.POST.get('shared_with')
        permission_level = request.POST.get('permission_level', 'read')
        expires_in_days = request.POST.get('expires_in_days')
        max_downloads = request.POST.get('max_downloads')
        share_message = request.POST.get('share_message', '')
        notify_on_access = request.POST.get('notify_on_access') == 'on'
        notify_on_download = request.POST.get('notify_on_download') == 'on'
        
        try:
            # Verifica che l'utente possa condividere il documento
            if not can_share_document(request.user, document_type, document_id):
                return JsonResponse({'success': False, 'message': 'Non hai i permessi per condividere questo documento'})
            
            # Trova l'utente destinatario
            try:
                shared_with_user = User.objects.get(username=shared_with_username)
            except User.DoesNotExist:
                return JsonResponse({'success': False, 'message': 'Utente destinatario non trovato'})
            
            # Calcola la data di scadenza
            expires_at = None
            if expires_in_days:
                expires_at = timezone.now() + timedelta(days=int(expires_in_days))
            
            # Crea la condivisione
            from .models import SharedDocument
            import uuid
            shared_doc = SharedDocument.objects.create(
                share_id=uuid.uuid4(),
                owner=request.user,
                shared_with=shared_with_user,
                share_type=document_type,
                object_id=document_id,
                permission_level=permission_level,
                expires_at=expires_at,
                max_downloads=int(max_downloads) if max_downloads else None,
                share_message=share_message,
                notify_on_access=notify_on_access,
                notify_on_download=notify_on_download
            )
            
            # Determina il messaggio in base al tipo di condivisione
            if document_type == 'created_document':
                notification_message = f'{request.user.username} ti ha invitato a collaborare su un documento: {share_message}'
            else:
                notification_message = f'{request.user.username} ha condiviso un {document_type} con te: {share_message}'
            
            # Crea notifica per il destinatario
            from .models import ShareNotification
            ShareNotification.objects.create(
                user=shared_with_user,
                shared_document=shared_doc,
                notification_type='share_created',
                message=notification_message
            )
            
            # Invia email di notifica
            send_share_notification_email(shared_doc, 'created')
            
            return JsonResponse({
                'success': True, 
                'message': 'Documento condiviso con successo',
                'share_id': str(shared_doc.share_id)
            })
            
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Errore nella condivisione: {str(e)}'})
    
    return render(request, 'Cripto1/create_share.html')

@login_required
def my_shares(request):
    """Visualizza le condivisioni create dall'utente"""
    from .models import SharedDocument
    # CORREZIONE: Aggiungi is_active=True per filtrare le condivisioni revocate
    shares_created = SharedDocument.objects.filter(owner=request.user, is_active=True).order_by('-created_at')
    shares_received = SharedDocument.objects.filter(shared_with=request.user, is_active=True).order_by('-created_at')
    
    # Filtra le condivisioni scadute
    active_shares_received = [share for share in shares_received if not share.is_expired()]
    
    # Separa le collaborazioni dai semplici share
    collaborations_created = [share for share in shares_created if share.share_type == 'created_document']
    collaborations_received = [share for share in active_shares_received if share.share_type == 'created_document']
    
    other_shares_created = [share for share in shares_created if share.share_type != 'created_document']
    other_shares_received = [share for share in active_shares_received if share.share_type != 'created_document']
    
    context = {
        'shares_created': shares_created,
        'shares_received': active_shares_received,
        'collaborations_created': collaborations_created,
        'collaborations_received': collaborations_received,
        'other_shares_created': other_shares_created,
        'other_shares_received': other_shares_received,
    }
    return render(request, 'Cripto1/my_shares.html', context)

@login_required
def view_shared_document(request, share_id):
    """Visualizza un documento condiviso"""
    from .models import SharedDocument, ShareNotification
    try:
        shared_doc = SharedDocument.objects.get(share_id=share_id, shared_with=request.user, is_active=True)
    except SharedDocument.DoesNotExist:
        messages.error(request, 'Documento condiviso non trovato o non hai i permessi per visualizzarlo')
        return redirect('Cripto1:my_shares')
    
    # Verifica se la condivisione è scaduta
    if shared_doc.is_expired():
        messages.error(request, 'La condivisione è scaduta')
        return redirect('Cripto1:my_shares')
    
    # Ottieni il documento originale
    if shared_doc.share_type == 'transaction':
        document = get_object_or_404(Transaction, id=shared_doc.object_id)
        template = 'Cripto1/shared_transaction.html'
    elif shared_doc.share_type == 'personal_document':
        document = get_object_or_404(PersonalDocument, id=shared_doc.object_id)
        template = 'Cripto1/shared_personal_document.html'
    elif shared_doc.share_type == 'created_document':
        from .models import CreatedDocument
        document = get_object_or_404(CreatedDocument, id=shared_doc.object_id)
        template = 'Cripto1/shared_created_document.html'
        
        # Per i documenti creati, decrittografa il contenuto se necessario
        if document.is_encrypted and document.encrypted_content:
            try:
                document.decrypted_content = decrypt_document_content(document)
            except Exception as e:
                document.decrypted_content = "[Contenuto crittografato - impossibile decrittografare]"
        else:
            document.decrypted_content = document.content
    
    # Invia notifica al proprietario se richiesto
    if shared_doc.notify_on_access:
        ShareNotification.objects.create(
            user=shared_doc.owner,
            shared_document=shared_doc,
            notification_type='share_accessed',
            message=f'{request.user.username} ha acceduto al documento condiviso'
        )
        send_share_notification_email(shared_doc, 'accessed')
    
    context = {
        'shared_document': shared_doc,
        'document': document,
        'can_download': shared_doc.can_download(),
        'can_write': shared_doc.can_write(),
        'is_collaboration': shared_doc.share_type == 'created_document',
    }
    return render(request, template, context)

@login_required
def download_shared_document(request, share_id):
    """Scarica un documento condiviso"""
    from .models import SharedDocument, ShareNotification
    try:
        shared_doc = SharedDocument.objects.get(share_id=share_id, shared_with=request.user, is_active=True)
    except SharedDocument.DoesNotExist:
        messages.error(request, 'Documento condiviso non trovato')
        return redirect('Cripto1:my_shares')
    
    if not shared_doc.record_download():
        messages.error(request, 'Limite di download raggiunto o permessi insufficienti')
        return redirect('Cripto1:view_shared_document', share_id=share_id)
    
    # Invia notifica al proprietario se richiesto
    if shared_doc.notify_on_download:
        ShareNotification.objects.create(
            user=shared_doc.owner,
            shared_document=shared_doc,
            notification_type='share_downloaded',
            message=f'{request.user.username} ha scaricato il documento condiviso'
        )
        send_share_notification_email(shared_doc, 'downloaded')
    
    # Reindirizza al download originale basato sul tipo
    if shared_doc.share_type == 'transaction':
        return redirect('Cripto1:download_file', transaction_id=shared_doc.object_id)
    elif shared_doc.share_type == 'personal_document':
        return redirect('Cripto1:download_personal_document', document_id=shared_doc.object_id)
    # Aggiungi altri tipi se necessario

@login_required
def revoke_share(request, share_id):
    """Revoca una condivisione"""
    from .models import SharedDocument, ShareNotification
    from django.http import JsonResponse
    
    try:
        shared_doc = SharedDocument.objects.get(share_id=share_id, owner=request.user)
        
        # Determina il tipo di messaggio in base al tipo di condivisione
        if shared_doc.share_type == 'created_document':
            message_text = f'{request.user.username} ha rimosso il tuo accesso di collaborazione al documento'
            success_message = 'Collaborazione revocata con successo'
        else:
            message_text = f'{request.user.username} ha revocato l\'accesso al documento condiviso'
            success_message = 'Condivisione revocata con successo'
        
        shared_doc.is_active = False
        shared_doc.save()
        
        # Crea notifica per il destinatario
        ShareNotification.objects.create(
            user=shared_doc.shared_with,
            shared_document=shared_doc,
            notification_type='share_revoked',
            message=message_text
        )
        
        # Se è una richiesta AJAX, restituisci JSON
        if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': success_message})
        
        messages.success(request, success_message)
        return redirect('Cripto1:my_shares')
        
    except SharedDocument.DoesNotExist:
        error_message = 'Condivisione non trovata'
        
        # Se è una richiesta AJAX, restituisci JSON
        if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'message': error_message})
        
        messages.error(request, error_message)
        return redirect('Cripto1:my_shares')

@login_required
def notifications(request):
    """Visualizza le notifiche dell'utente"""
    from .models import ShareNotification
    notifications = ShareNotification.objects.filter(user=request.user).order_by('-created_at')
    
    # Segna come lette le notifiche visualizzate
    unread_notifications = notifications.filter(is_read=False)
    unread_notifications.update(is_read=True)
    
    paginator = Paginator(notifications, 20)
    page = request.GET.get('page')
    try:
        notifications = paginator.page(page)
    except PageNotAnInteger:
        notifications = paginator.page(1)
    except EmptyPage:
        notifications = paginator.page(paginator.num_pages)
    
    context = {
        'notifications': notifications,
    }
    return render(request, 'Cripto1/notifications.html', context)

@login_required
def get_unread_notifications_count(request):
    """API per ottenere il numero di notifiche non lette"""
    from .models import ShareNotification
    count = ShareNotification.objects.filter(user=request.user, is_read=False).count()
    return JsonResponse({'count': count})

@login_required
def remove_collaborator(request, document_id, collaborator_id):
    """Rimuovi un collaboratore da un documento"""
    from .models import CreatedDocument, SharedDocument, ShareNotification
    
    document = get_object_or_404(CreatedDocument, id=document_id, user=request.user)
    
    try:
        shared_doc = SharedDocument.objects.get(
            owner=request.user,
            shared_with_id=collaborator_id,
            share_type='created_document',
            object_id=document.id,
            is_active=True
        )
        
        shared_doc.is_active = False
        shared_doc.save()
        
        # Crea notifica per il collaboratore rimosso
        ShareNotification.objects.create(
            user=shared_doc.shared_with,
            shared_document=shared_doc,
            notification_type='share_revoked',
            message=f'{request.user.username} ha rimosso il tuo accesso di collaborazione al documento "{document.title}"'
        )
        
        messages.success(request, f'Collaboratore {shared_doc.shared_with.username} rimosso con successo.')
        
    except SharedDocument.DoesNotExist:
        messages.error(request, 'Collaborazione non trovata.')
    
    return redirect('Cripto1:edit_document', document_id=document.id)
    
@external_forbidden
@login_required
def create_document(request):
    """Vista per creare un nuovo documento"""
    if request.method == 'POST':
        title = request.POST.get('title')
        document_type = request.POST.get('document_type', 'text')
        content = request.POST.get('content', '')
        
        # Crea il documento
        from .models import CreatedDocument
        document = CreatedDocument.objects.create(
            user=request.user,
            title=title,
            document_type=document_type,
            content=content,
            word_count=len(content.split())
        )
        
        # Crittografa il contenuto se necessario
        if content:
            encrypt_document_content(document, content)
        
        messages.success(request, f'Documento "{title}" creato con successo!')
        return redirect('Cripto1:edit_document', document_id=document.id)
    
    return render(request, 'Cripto1/create_document.html')

@external_forbidden
@login_required
def edit_document(request, document_id):
    """Vista per modificare un documento esistente"""
    from .models import CreatedDocument, SharedDocument
    document = get_object_or_404(CreatedDocument, id=document_id, user=request.user)
    
    if request.method == 'POST':
        if 'auto_save' in request.POST:
            # Auto-salvataggio AJAX
            content = request.POST.get('content', '')
            title = request.POST.get('title', document.title)
            document_type = request.POST.get('document_type', document.document_type)
            is_encrypted = 'is_encrypted' in request.POST
            is_shareable = 'is_shareable' in request.POST
            
            document.title = title
            document.content = content
            document.document_type = document_type
            document.is_encrypted = is_encrypted
            document.is_shareable = is_shareable
            document.word_count = len(content.split()) if content else 0
            document.save()
            
            # Ri-crittografa il contenuto se necessario
            if is_encrypted:
                encrypt_document_content(document, content)
            
            return JsonResponse({
                'success': True, 
                'status': 'saved', 
                'time': timezone.now().strftime('%H:%M')
            })
        else:
            # Salvataggio normale
            content = request.POST.get('content', '')
            title = request.POST.get('title', document.title)
            document_type = request.POST.get('document_type', document.document_type)
            is_encrypted = 'is_encrypted' in request.POST
            is_shareable = 'is_shareable' in request.POST
            
            document.title = title
            document.content = content
            document.document_type = document_type
            document.is_encrypted = is_encrypted
            document.is_shareable = is_shareable
            document.word_count = len(content.split()) if content else 0
            document.save()
            
            # Ri-crittografa il contenuto se necessario
            if is_encrypted:
                encrypt_document_content(document, content)
            
            messages.success(request, 'Documento salvato con successo!')
            return redirect('Cripto1:created_documents_list')
    
    # Decrittografa il contenuto se necessario
    if document.is_encrypted and document.encrypted_content:
        content = decrypt_document_content(document)
    else:
        content = document.content
    
    # Ottieni i collaboratori del documento
    collaborators = SharedDocument.objects.filter(
        owner=request.user,
        share_type='created_document',
        object_id=document.id,
        is_active=True
    ).select_related('shared_with')
    
    context = {
        'document': document,
        'content': content,
        'collaborators': collaborators,
    }
    return render(request, 'Cripto1/edit_document.html', context)

@external_forbidden
@login_required
def created_documents_list(request):
    """Lista dei documenti creati dall'utente"""
    from .models import CreatedDocument, SharedDocument
    documents = CreatedDocument.objects.filter(user=request.user)
    
    # Aggiungi informazioni sui collaboratori per ogni documento
    for document in documents:
        document.collaborators = SharedDocument.objects.filter(
            owner=request.user,
            share_type='created_document',
            object_id=document.id,
            is_active=True
        ).select_related('shared_with')
    
    context = {
        'documents': documents,
    }
    return render(request, 'Cripto1/created_documents_list.html', context)

def encrypt_document_content(document, content):
    """Crittografa il contenuto del documento"""
    try:
        user_profile = document.user.userprofile
        if user_profile.public_key:
            # Genera chiave simmetrica
            symmetric_key = Fernet.generate_key()
            f = Fernet(symmetric_key)
            
            # Crittografa il contenuto
            encrypted_content = f.encrypt(content.encode('utf-8'))
            
            # Crittografa la chiave simmetrica con la chiave pubblica
            public_key = serialization.load_pem_public_key(user_profile.public_key.encode())
            encrypted_symmetric_key = public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Salva i dati crittografati
            document.encrypted_content = encrypted_content
            document.encrypted_symmetric_key = encrypted_symmetric_key
            document.is_encrypted = True
            document.save()
            
    except Exception as e:
        print(f"Errore crittografia documento: {e}")

def decrypt_document_content(document):
    """Decrittografa il contenuto del documento"""
    try:
        user_profile = document.user.userprofile
        # Correzione: usare private_key invece di encrypted_private_key
        if user_profile.private_key and document.encrypted_symmetric_key:
            # Qui dovresti richiedere la password, per ora uso contenuto non crittografato
            return document.content
    except Exception as e:
        print(f"Errore decrittografia documento: {e}")
    
    return document.content

@external_forbidden
@login_required
def delete_created_document(request, document_id):
    """Elimina un documento creato dall'utente"""
    from .models import CreatedDocument
    document = get_object_or_404(CreatedDocument, id=document_id, user=request.user)
    
    if request.method == 'POST':
        document_title = document.title
        document.delete()
        messages.success(request, f'Documento "{document_title}" eliminato con successo.')
    
    return redirect('Cripto1:created_documents_list')

@external_forbidden
@login_required
@user_manager_forbidden
def create_transaction_from_created_document(request, document_id):
    # Recupera il documento creato
    from .models import CreatedDocument
    document = get_object_or_404(CreatedDocument, id=document_id, user=request.user)
    user_profile = UserProfile.objects.get(user=request.user)
    user_org = user_profile.organization
    
    # Verifica se l'utente ha il ruolo "external"
    if user_profile.has_role('external'):
        messages.error(request, 'Gli utenti con ruolo "external" non possono inviare transazioni.')
        return redirect('Cripto1:created_documents_list')
    
    if request.method == 'POST':
        try:
            receiver_key = request.POST.get('receiver_key')
            is_encrypted = request.POST.get('is_encrypted', 'false').lower() in ['true', 'on', '1']
            is_shareable = True  # I documenti creati condivisi sono sempre condivisibili
            private_key_password = request.POST.get('private_key_password')
            max_downloads_str = request.POST.get('max_downloads')
            max_downloads = int(max_downloads_str) if max_downloads_str and max_downloads_str.isdigit() else None
            
            receiver_profile = UserProfile.objects.filter(
                user_key=receiver_key,
                organization=user_org
            ).first()
            if not receiver_profile:
                messages.error(request, 'Destinatario non trovato nella tua organizzazione.')
                return render(request, 'Cripto1/share_created_document.html', {
                    'document': document,
                    'users': UserProfile.objects.filter(
                        organization=user_org
                    ).exclude(user=request.user)
                })
            receiver = receiver_profile.user

            # Ottieni il contenuto del documento
            if document.is_encrypted:
                try:
                    # Decifra il contenuto
                    decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                    if not decrypted_private_key:
                        messages.error(request, 'Password della chiave privata errata.')
                        return render(request, 'Cripto1/share_created_document.html', {
                            'document': document,
                            'users': UserProfile.objects.exclude(user=request.user)
                        })
                    
                    # Converti memoryview in bytes per encrypted_symmetric_key
                    encrypted_key_bytes = bytes(document.encrypted_symmetric_key)
                    symmetric_key = decrypted_private_key.decrypt(
                        encrypted_key_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    f = Fernet(symmetric_key)
                    # Converti memoryview in bytes per encrypted_content
                    encrypted_content_bytes = bytes(document.encrypted_content)
                    content = f.decrypt(encrypted_content_bytes).decode('utf-8')
                except Exception as e:
                    messages.error(request, f'Errore durante la decifratura del documento: {str(e)}')
                    return render(request, 'Cripto1/share_created_document.html', {
                        'document': document,
                        'users': UserProfile.objects.filter(
                            organization=user_org
                        ).exclude(user=request.user)
                    })
            else:
                content = document.content

            # Converti HTML in PDF usando reportlab
            from io import BytesIO
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER
            import re
            
            # Crea un buffer per il PDF
            pdf_buffer = BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Stile personalizzato per il titolo
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            # Aggiungi il titolo
            story.append(Paragraph(document.title, title_style))
            story.append(Spacer(1, 12))
            
            # Aggiungi le informazioni del documento
            info_text = f"""
            <b>Tipo:</b> {document.get_document_type_display()}<br/>
            <b>Creato il:</b> {document.created_at.strftime('%d/%m/%Y %H:%M')}<br/>
            <b>Parole:</b> {document.word_count}
            """
            story.append(Paragraph(info_text, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Pulisci il contenuto HTML per renderlo compatibile con reportlab
            clean_content = re.sub(r'<[^>]+>', '', content)  # Rimuovi tag HTML
            clean_content = clean_content.replace('&nbsp;', ' ')  # Sostituisci entità HTML
            
            # Aggiungi il contenuto
            for paragraph in clean_content.split('\n'):
                if paragraph.strip():
                    story.append(Paragraph(paragraph, styles['Normal']))
                    story.append(Spacer(1, 6))
            
            # Genera il PDF
            doc.build(story)
            pdf_content = pdf_buffer.getvalue()
            pdf_buffer.close()

            # Salva la chiave pubblica del mittente
            sender_public_key = user_profile.public_key

            # Crea i dati della transazione
            transaction_data = {
                'type': 'file',
                'sender': request.user.id,
                'receiver': receiver.id,
                'sender_public_key': sender_public_key,
                'content': f'Documento condiviso: {document.title}',
                'timestamp': time.time(),
                'is_encrypted': is_encrypted,
                'is_shareable': is_shareable
            }
            
            # Gestione del file PDF (invece di HTML)
            encrypted_symmetric_key_for_db = None

            if is_encrypted:
                try:
                    # Genera una chiave simmetrica per la cifratura del file
                    symmetric_key = Fernet.generate_key()
                    f = Fernet(symmetric_key)
                    encrypted_file_content = f.encrypt(pdf_content)

                    # Cifra la chiave simmetrica con la chiave pubblica RSA del destinatario
                    receiver_public_key = serialization.load_pem_public_key(
                        receiver_profile.public_key.encode(),
                        backend=default_backend()
                    )
                    encrypted_symmetric_key_for_db = receiver_public_key.encrypt(
                        symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Cifra la chiave simmetrica per il mittente
                    sender_public_key_obj = serialization.load_pem_public_key(
                        user_profile.public_key.encode(),
                        backend=default_backend()
                    )
                    sender_encrypted_symmetric_key = sender_public_key_obj.encrypt(
                        symmetric_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    filename = f"{uuid.uuid4().hex}.encrypted"
                    file_to_save = ContentFile(encrypted_file_content)
                    transaction_data['original_filename'] = f'{document.title}.pdf'
                    transaction_data['encrypted_symmetric_key'] = encrypted_symmetric_key_for_db.hex()
                    transaction_data['sender_encrypted_symmetric_key'] = sender_encrypted_symmetric_key.hex()
                    transaction_data['receiver_public_key_at_encryption'] = receiver_profile.public_key

                except Exception as e:
                    messages.error(request, f'Errore durante la cifratura del file: {str(e)}')
                    return render(request, 'Cripto1/share_created_document.html', {
                        'document': document,
                        'users': UserProfile.objects.filter(
                            organization=user_org
                        ).exclude(user=request.user)
                    })
            else:
                filename = f"{time.time()}_{document.title}.pdf"
                file_to_save = ContentFile(pdf_content)

            file_path = default_storage.save(f'transaction_files/{filename}', file_to_save)
            transaction_data['file'] = file_path

            # Calcola l'hash della transazione
            transaction_string_for_signing = json.dumps(transaction_data, sort_keys=True).encode()
            transaction_hash = hashlib.sha256(transaction_string_for_signing).hexdigest()
            
            # Firma la transazione
            private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
            if not private_key:
                messages.error(request, 'Errore durante il recupero della chiave privata.')
                return render(request, 'Cripto1/share_created_document.html', {
                    'document': document,
                    'users': UserProfile.objects.filter(
                        organization=user_org
                    ).exclude(user=request.user)
                })
            
            data_to_sign = transaction_hash.encode()
            signature = private_key.sign(
                data_to_sign,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Crea la transazione
            new_tx = Transaction.objects.create(
                type='file',
                sender=request.user,
                receiver=receiver,
                sender_public_key=sender_public_key,
                content=transaction_data['content'],
                file=transaction_data.get('file'),
                timestamp=transaction_data['timestamp'],
                transaction_hash=transaction_hash,
                signature=signature.hex(),
                is_encrypted=is_encrypted,
                is_shareable=transaction_data.get('is_shareable', False),
                original_filename=transaction_data.get('original_filename', ''),
                encrypted_symmetric_key=bytes.fromhex(transaction_data['encrypted_symmetric_key']) if 'encrypted_symmetric_key' in transaction_data and transaction_data['encrypted_symmetric_key'] else None,
                sender_encrypted_symmetric_key=bytes.fromhex(transaction_data['sender_encrypted_symmetric_key']) if 'sender_encrypted_symmetric_key' in transaction_data and transaction_data['sender_encrypted_symmetric_key'] else None,
                receiver_public_key_at_encryption=transaction_data.get('receiver_public_key_at_encryption', ''),
                max_downloads=max_downloads
            )

            # Aggiungi alle transazioni in sospeso
            pending_transactions_ids = request.session.get('pending_transactions_ids', [])
            pending_transactions_ids.append(new_tx.id)
            request.session['pending_transactions_ids'] = pending_transactions_ids

            messages.success(request, f'Documento "{document.title}" condiviso con successo!')
            return redirect('Cripto1:created_documents_list')
            
        except Exception as e:
            messages.error(request, f'Errore durante la condivisione: {str(e)}')
            return render(request, 'Cripto1/share_created_document.html', {
                'document': document,
                'users': UserProfile.objects.filter(
                    organization=user_org
                ).exclude(user=request.user)
            })
    
    # GET request - mostra il form di condivisione
    return render(request, 'Cripto1/share_created_document.html', {
        'document': document,
        'users': UserProfile.objects.filter(
            organization=user_org
        ).exclude(user=request.user)
    })

@login_required
def mark_notification_as_read(request, notification_id):
    """Segna una notifica specifica come letta"""
    from .models import ShareNotification
    try:
        notification = ShareNotification.objects.get(
            id=notification_id, 
            user=request.user
        )
        notification.is_read = True
        notification.save()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True, 'message': 'Notifica segnata come letta'})
        else:
            messages.success(request, 'Notifica segnata come letta')
            return redirect('Cripto1:notifications')
            
    except ShareNotification.DoesNotExist:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': False, 'error': 'Notifica non trovata'})
        else:
            messages.error(request, 'Notifica non trovata')
            return redirect('Cripto1:notifications')

@login_required
def add_collaborator(request, document_id):
    """Aggiungi un collaboratore a un documento creato"""
    from .models import CreatedDocument, SharedDocument, ShareNotification
    from django.contrib.auth.models import User
    from .email_utils import send_share_notification_email
    import uuid
    
    # Verifica che il documento esista e appartenga all'utente
    document = get_object_or_404(CreatedDocument, id=document_id, user=request.user)
    
    if request.method == 'POST':
        collaborator_username = request.POST.get('collaborator_username')
        permission_level = request.POST.get('permission_level', 'write')
        collaboration_message = request.POST.get('collaboration_message', '')
        
        try:
            # Trova l'utente collaboratore
            collaborator = User.objects.get(username=collaborator_username)
            
            # Verifica che non sia lo stesso proprietario
            if collaborator == request.user:
                messages.error(request, "Non puoi aggiungere te stesso come collaboratore.")
                return render(request, 'Cripto1/add_collaborator.html', {
                    'document': document,
                    'users': User.objects.exclude(id=request.user.id)
                })
            
            # Verifica che non sia già un collaboratore
            existing_share = SharedDocument.objects.filter(
                owner=request.user,
                shared_with=collaborator,
                share_type='created_document',
                object_id=document.id,
                is_active=True
            ).first()
            
            if existing_share:
                messages.warning(request, f"{collaborator.username} è già un collaboratore di questo documento.")
                return render(request, 'Cripto1/add_collaborator.html', {
                    'document': document,
                    'users': User.objects.exclude(id=request.user.id)
                })
            
            # Crea la condivisione per collaborazione
            shared_document = SharedDocument.objects.create(
                share_id=uuid.uuid4(),
                owner=request.user,
                shared_with=collaborator,
                share_type='created_document',
                object_id=document.id,
                permission_level=permission_level,
                share_message=collaboration_message,
                notify_on_access=True,
                notify_on_download=False  # Per collaborazione non serve
            )
            
            # Crea notifica
            ShareNotification.objects.create(
                user=collaborator,
                shared_document=shared_document,
                notification_type='share_created',
                message=f"{request.user.username} ti ha invitato a collaborare sul documento '{document.title}'"
            )
            
            # Invia email di notifica
            send_share_notification_email(shared_document, 'created')
            
            messages.success(request, f"Collaboratore {collaborator.username} aggiunto con successo!")
            return redirect('Cripto1:created_documents_list')
            
        except User.DoesNotExist:
            messages.error(request, "Utente non trovato.")
        except Exception as e:
            messages.error(request, f"Errore nell'aggiunta del collaboratore: {str(e)}")
    
    # GET request - mostra il form
    users = User.objects.exclude(id=request.user.id).order_by('username')
    
    return render(request, 'Cripto1/add_collaborator.html', {
        'document': document,
        'users': users
    })

@login_required
def edit_shared_document(request, share_id):
    """Modifica un documento condiviso con permessi di scrittura (co-working)"""
    from .models import SharedDocument, CreatedDocument, ShareNotification
    
    try:
        shared_doc = SharedDocument.objects.get(
            share_id=share_id, 
            shared_with=request.user, 
            is_active=True
        )
    except SharedDocument.DoesNotExist:
        messages.error(request, 'Documento condiviso non trovato')
        return redirect('Cripto1:my_shares')
    
    # Verifica permessi di scrittura
    if not shared_doc.can_write():
        messages.error(request, 'Non hai i permessi per modificare questo documento')
        return redirect('Cripto1:view_shared_document', share_id=share_id)
    
    # Solo documenti creati supportano la modifica collaborativa
    if shared_doc.share_type != 'created_document':
        messages.error(request, 'Questo tipo di documento non supporta la modifica collaborativa')
        return redirect('Cripto1:view_shared_document', share_id=share_id)
    
    document = get_object_or_404(CreatedDocument, id=shared_doc.object_id)
    
    if request.method == 'POST':
        if 'auto_save' in request.POST:
            # Auto-salvataggio AJAX
            content = request.POST.get('content', '')
            title = request.POST.get('title', document.title)
            
            document.title = title
            document.content = content
            document.word_count = len(content.split())
            document.last_modified = timezone.now()
            document.save()
            
            # Notifica al proprietario della modifica
            ShareNotification.objects.create(
                user=shared_doc.owner,
                shared_document=shared_doc,
                notification_type='share_modified',
                message=f'{request.user.username} ha modificato il documento condiviso: {document.title}'
            )
            
            # Invia email di notifica al proprietario
            send_share_notification_email(shared_doc, 'modified')
            
            return JsonResponse({
                'success': True,
                'message': 'Documento salvato automaticamente',
                'time': timezone.now().strftime('%H:%M:%S')
            })
        else:
            # Salvataggio normale
            document.title = request.POST.get('title', document.title)
            document.content = request.POST.get('content', document.content)
            document.document_type = request.POST.get('document_type', document.document_type)
            document.word_count = len(document.content.split())
            document.last_modified = timezone.now()
            document.save()
            
            # Notifica al proprietario
            ShareNotification.objects.create(
                user=shared_doc.owner,
                shared_document=shared_doc,
                notification_type='share_modified',
                message=f'{request.user.username} ha salvato le modifiche al documento: {document.title}'
            )
            
            # Invia email di notifica
            send_share_notification_email(shared_doc, 'modified')
            
            # Mostra pagina di successo invece del JSON
            messages.success(request, 'Documento salvato con successo!')
            context = {
                'success_message': 'Documento salvato con successo!',
                'document_title': document.title,
                'show_home_button': True
            }
            return render(request, 'Cripto1/success_page.html', context)
    
    # Decrittografa il contenuto se necessario
    content = document.content
    if document.is_encrypted and document.encrypted_content:
        try:
            content = decrypt_document_content(document)
        except Exception as e:
            content = "[Contenuto crittografato - impossibile decrittografare]"
    
    context = {
        'document': document,
        'shared_document': shared_doc,
        'content': content,
        'is_shared_edit': True,
        'share_id': share_id,
        'collaborator_name': shared_doc.owner.get_full_name() or shared_doc.owner.username
    }
    return render(request, 'Cripto1/edit_shared_document.html', context)