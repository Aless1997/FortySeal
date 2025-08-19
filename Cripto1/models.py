from django.db import models
from django.contrib.auth.models import User
import hashlib
import time
import json
import pyotp
import base64
from encrypted_model_fields.fields import EncryptedTextField
from django.core.validators import FileExtensionValidator
from django.utils import timezone
from datetime import timedelta

# Import for cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.exceptions import InvalidSignature

class Block(models.Model):
    index = models.IntegerField(unique=True)
    timestamp = models.FloatField()
    proof = models.CharField(max_length=255)
    previous_hash = models.CharField(max_length=255)
    hash = models.CharField(max_length=255)
    nonce = models.CharField(max_length=255)
    merkle_root = models.CharField(max_length=255)
    difficulty = models.FloatField(default=4.0, null=True, blank=True)

    def __str__(self):
        return f"Block #{self.index}"

    class Meta:
        ordering = ['index']

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('text', 'Text Message'),
        ('file', 'File Upload'),
    ]

    block = models.ForeignKey(Block, on_delete=models.CASCADE, related_name='transactions', null=True, blank=True)
    type = models.CharField(max_length=50, choices=TRANSACTION_TYPES)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_transactions')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_transactions')
    sender_public_key = models.TextField(null=True, blank=True)  # Nuovo campo
    content = models.TextField(blank=True)  # For text messages
    file = models.FileField(upload_to='transaction_files/', null=True, blank=True,
                          validators=[FileExtensionValidator(allowed_extensions=['pdf', 'csv', 'xlsx', 'xls', 'doc', 'docx', 'txt'])])
    timestamp = models.FloatField()
    transaction_hash = models.CharField(max_length=255, unique=True)
    signature = models.TextField(null=True, blank=True)
    is_encrypted = models.BooleanField(default=False)
    is_shareable = models.BooleanField(default=False)  # Aggiungi questo campo
    original_filename = models.CharField(max_length=255, blank=True, null=True) # Per salvare il nome originale del file cifrato
    encrypted_symmetric_key = models.BinaryField(null=True, blank=True) # Per la chiave simmetrica cifrata del file
    receiver_public_key_at_encryption = models.TextField(null=True, blank=True) # Public key of receiver at the time of encryption
    max_downloads = models.IntegerField(null=True, blank=True, default=None) # Numero massimo di download consentiti
    current_downloads = models.IntegerField(default=0) # Contatore dei download effettuati
    is_viewed = models.BooleanField(default=False) # Indica se la transazione è stata visualizzata dal destinatario
    
    # Aggiungi questi campi
    sender_encrypted_content = models.TextField(blank=True, null=True)  # Contenuto crittografato per il mittente (per messaggi di testo)
    sender_encrypted_symmetric_key = models.BinaryField(null=True, blank=True)  # Chiave simmetrica crittografata per il mittente (per file)
    
    def __str__(self):
        return f"Transaction {self.transaction_hash[:10]}..."

    def to_dict(self):
        """Returns a dictionary representation of the transaction for signing/hashing."""
        return {
            'type': self.type,
            'sender': self.sender.id,
            'receiver': self.receiver.id,
            'sender_public_key': self.sender_public_key or '',
            'content': self.content,
            'file': str(self.file) if self.file else '',
            'timestamp': self.timestamp,
            'is_encrypted': self.is_encrypted,
            'original_filename': self.original_filename or '', # Include original filename
            'encrypted_symmetric_key': self.encrypted_symmetric_key.hex() if self.encrypted_symmetric_key else '',
            'receiver_public_key_at_encryption': self.receiver_public_key_at_encryption or '',
            'sender_encrypted_content': self.sender_encrypted_content or '',
            'sender_encrypted_symmetric_key': self.sender_encrypted_symmetric_key.hex() if self.sender_encrypted_symmetric_key else '',
        }

    def calculate_hash(self):
        """Calculates the SHA-256 hash of the transaction data."""
        transaction_string = json.dumps(self.to_dict(), sort_keys=True).encode()
        print(f"[DEBUG VERIFYING] transaction_dict: {self.to_dict()}")
        print(f"[DEBUG VERIFYING] transaction_string: {transaction_string}")
        return hashlib.sha256(transaction_string).hexdigest()

    def verify_signature(self):
        """Verifies the digital signature of the transaction."""
        if not self.signature:
            print(f"[DEBUG] No signature for transaction {self.transaction_hash}")
            return False

        try:
            # Usa la chiave pubblica salvata nella transazione
            if not self.sender_public_key:
                print(f"[DEBUG] No sender_public_key saved in transaction {self.transaction_hash}")
                return False
            public_key = serialization.load_pem_public_key(
                self.sender_public_key.encode(),
                backend=default_backend()
            )
            
            # Calculate the hash of the transaction data
            tx_dict = self.to_dict()
            print(f"[DEBUG] Transaction dict for verification: {tx_dict}")
            data_to_verify = self.calculate_hash().encode()
            print(f"[DEBUG] Data to verify (hash): {self.calculate_hash()}")
            print(f"[DEBUG] Signature (hex): {self.signature}")
            
            # Verify the signature
            public_key.verify(
                bytes.fromhex(self.signature),
                data_to_verify,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"[DEBUG] Signature valid for transaction {self.transaction_hash}")
            return True
        except Exception as e:
            print(f"Error verifying signature for transaction {self.transaction_hash}: {type(e).__name__}: {e}")
            print(f"[DEBUG] Transaction dict: {self.to_dict()}")
            print(f"[DEBUG] Data to verify (hash): {self.calculate_hash()}")
            print(f"[DEBUG] Signature (hex): {self.signature}")
            return False

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_key = models.CharField(max_length=255, unique=True) # Keep as a unique identifier (can be hash of public key)
    public_key = models.TextField(null=True, blank=True) # Allow null for existing rows
    private_key = EncryptedTextField(null=True, blank=True) # Allow null for existing rows
    balance = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    
    # Nuovi campi per il sistema di ruoli
    is_active = models.BooleanField(default=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_login_date = models.DateTimeField(null=True, blank=True)
    login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    sso_provider = models.CharField(max_length=50, blank=True, null=True)  # Per SSO
    sso_id = models.CharField(max_length=255, blank=True, null=True)  # ID esterno per SSO
    department = models.CharField(max_length=100, blank=True, null=True)
    position = models.CharField(max_length=100, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    emergency_contact = models.CharField(max_length=255, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    
    # Campi per 2FA
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = EncryptedTextField(null=True, blank=True)  # Usiamo EncryptedTextField per maggiore sicurezza
    two_factor_verified = models.BooleanField(default=False)  # Per verificare se l'utente ha completato la configurazione
    
    # Nuovi campi per la gestione dello storage
    storage_quota_bytes = models.BigIntegerField(default=5368709120)  # 5GB in bytes
    storage_used_bytes = models.BigIntegerField(default=0)
    
    def get_storage_quota_gb(self):
        """Restituisce la quota in GB"""
        return self.storage_quota_bytes / (1024 * 1024 * 1024)
    
    def get_storage_used_gb(self):
        """Restituisce lo spazio utilizzato in GB"""
        return self.storage_used_bytes / (1024 * 1024 * 1024)
    
    def get_storage_percentage(self):
        """Restituisce la percentuale di storage utilizzata"""
        if self.storage_quota_bytes == 0:
            return 0
        return (self.storage_used_bytes / self.storage_quota_bytes) * 100
    
    def has_storage_available(self, file_size_bytes):
        """Verifica se c'è spazio disponibile per un file"""
        return (self.storage_used_bytes + file_size_bytes) <= self.storage_quota_bytes
    
    def update_storage_usage(self):
        """Ricalcola lo spazio utilizzato dall'utente"""
        from django.core.files.storage import default_storage
        import os
        
        total_size = 0
        
        # Calcola dimensione documenti personali
        for doc in self.user.personal_documents.all():
            if doc.file and default_storage.exists(doc.file.name):
                try:
                    total_size += doc.file.size
                except:
                    pass
        
        # Calcola dimensione file transazioni
        for tx in self.user.sent_transactions.all():
            if tx.file and default_storage.exists(tx.file.name):
                try:
                    total_size += tx.file.size
                except:
                    pass
        
        # Calcola dimensione immagine profilo
        if self.profile_picture and default_storage.exists(self.profile_picture.name):
            try:
                total_size += self.profile_picture.size
            except:
                pass
        
        self.storage_used_bytes = total_size
        self.save(update_fields=['storage_used_bytes'])
        return total_size
    
    def __str__(self):
        return f"{self.user.username}'s Profile"

    def generate_key_pair(self, password: bytes = b'securepassword'):
        """Genera una nuova coppia di chiavi RSA per l'utente, cifrando la privata con la password fornita."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = pem_public_key.decode()
        self.private_key = pem_private_key.decode()
        self.user_key = hashlib.sha256(self.public_key.encode()).hexdigest()
        self.save()

    def decrypt_private_key(self, password=b'securepassword'):
        """Decrypts and returns the user's private key."""
        try:
            private_key = serialization.load_pem_private_key(
                self.private_key.encode(),
                password=password, # Use the password for decryption
                backend=default_backend()
            )
            print(f"DEBUG: Private key decrypted successfully with provided password.")
            return private_key
        except Exception as e:
            print(f"DEBUG: Error decrypting private key with provided password: {e}")
            return None

    @property
    def private_key_hash(self):
        if self.private_key:
            return hashlib.sha256(self.private_key.encode()).hexdigest()
        return None

    def decrypt_message(self, encrypted_hex, password=b'securepassword'):
        """Decripta un messaggio cifrato in hex usando la chiave privata dell'utente."""
        try:
            if not encrypted_hex:
                return ''
            private_key = self.decrypt_private_key(password=password)
            if not private_key:
                return 'Errore: chiave privata non disponibile.'
            
            print(f"DEBUG: Encrypted hex received for decryption: {encrypted_hex}")
            print(f"DEBUG: Length of encrypted hex: {len(encrypted_hex)}")

            from cryptography.hazmat.primitives.asymmetric import padding
            decrypted = private_key.decrypt(
                bytes.fromhex(encrypted_hex),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            return f'Errore nella decriptazione: {str(e)}'

    def decrypt_file_content(self, encrypted_bytes: bytes, password: bytes):
        """Decripta il contenuto di un file (in bytes) usando la chiave privata dell'utente."""
        try:
            private_key = self.decrypt_private_key(password=password)
            if not private_key:
                return None # Or raise an exception

            from cryptography.hazmat.primitives.asymmetric import padding
            decrypted_content = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_content
        except Exception as e:
            print(f"Error decrypting file content: {e}")
            return None

    def get_roles(self):
        """Restituisce tutti i ruoli attivi dell'utente"""
        return Role.objects.filter(
            user_assignments__user=self.user,
            user_assignments__is_active=True
        ).exclude(
            user_assignments__expires_at__lt=timezone.now()
        )

    def has_role(self, role_name):
        """Verifica se l'utente ha un determinato ruolo"""
        return self.get_roles().filter(name=role_name).exists()

    def has_permission(self, permission_codename):
        """Verifica se l'utente ha un determinato permesso attraverso i suoi ruoli"""
        # Verifica se l'utente è superuser (bypass completo)
        if self.user.is_superuser:
            return True
        
        # Verifica i permessi attraverso i ruoli
        user_roles = self.get_roles()
        for role in user_roles:
            role_permissions = role.permissions.filter(is_active=True)
            if role_permissions.filter(codename=permission_codename).exists():
                return True
        
        return False

    def get_all_permissions(self):
        """Restituisce tutti i permessi dell'utente"""
        return Permission.objects.filter(
            role__user_assignments__user=self.user,
            role__user_assignments__is_active=True,
            is_active=True
        ).exclude(
            role__user_assignments__expires_at__lt=timezone.now()
        ).distinct()

    def assign_role(self, role, assigned_by=None, expires_at=None, notes=""):
        """Assegna un ruolo all'utente"""
        user_role, created = UserRole.objects.get_or_create(
            user=self.user,
            role=role,
            defaults={
                'assigned_by': assigned_by,
                'expires_at': expires_at,
                'notes': notes
            }
        )
        if not created:
            user_role.is_active = True
            user_role.expires_at = expires_at
            user_role.notes = notes
            user_role.save()
        
        # Aggiunta: se il ruolo è Super Admin, imposta anche is_superuser
        if role.name == 'Super Admin' and not self.user.is_superuser:
            self.user.is_superuser = True
            self.user.save()
        
        return user_role

    def remove_role(self, role):
        """Rimuove un ruolo dall'utente"""
        try:
            user_role = UserRole.objects.get(user=self.user, role=role)
            user_role.is_active = False
            user_role.save()
            
            # Aggiunta: se il ruolo è Super Admin, rimuovi anche is_superuser
            # ma solo se non ci sono altri ruoli Super Admin attivi
            if role.name == 'Super Admin' and self.user.is_superuser:
                # Verifica se l'utente ha ancora altri ruoli Super Admin attivi
                has_other_super_admin = UserRole.objects.filter(
                    user=self.user, 
                    role__name='Super Admin',
                    is_active=True
                ).exclude(id=user_role.id).exists()
                
                if not has_other_super_admin:
                    self.user.is_superuser = False
                    self.user.save()
            
            return True
        except UserRole.DoesNotExist:
            return False

    def get_active_roles_count(self):
        """Restituisce il numero di ruoli attivi"""
        return self.get_roles().count()

    def get_roles_summary(self):
        """Restituisce un riassunto dei ruoli attivi"""
        roles = self.get_roles()
        return [{
            'name': role.name,
            'description': role.description,
            'assigned_at': role.user_assignments.filter(user=self.user).first().assigned_at if role.user_assignments.filter(user=self.user).exists() else None,
            'expires_at': role.user_assignments.filter(user=self.user).first().expires_at if role.user_assignments.filter(user=self.user).exists() else None,
        } for role in roles]

    def refresh_roles_cache(self):
        """Aggiorna la cache dei ruoli (per compatibilità futura)"""
        # Questo metodo può essere usato per aggiornare cache o metadati
        pass

    def is_locked(self):
        """Verifica se l'account è bloccato"""
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        return False

    def increment_login_attempts(self):
        """Incrementa i tentativi di login"""
        self.login_attempts += 1
        if self.login_attempts >= 5:  # Blocca dopo 5 tentativi
            self.locked_until = timezone.now() + timedelta(minutes=30)
        self.save()

    def reset_login_attempts(self):
        """Resetta i tentativi di login"""
        self.login_attempts = 0
        self.locked_until = None
        self.save()

    def update_last_login(self, ip_address=None):
        """Aggiorna le informazioni dell'ultimo login"""
        self.last_login_date = timezone.now()
        if ip_address:
            self.last_login_ip = ip_address
        self.save()

    def test_permissions(self, permission_list=None):
        """Testa una lista di permessi e restituisce i risultati"""
        if permission_list is None:
            permission_list = ['view_users', 'add_users', 'edit_users', 'manage_roles']
        
        results = {}
        for perm in permission_list:
            results[perm] = self.has_permission(perm)
        
        return results
    
    def get_permissions_summary(self):
        """Restituisce un riassunto dei permessi dell'utente"""
        all_permissions = self.get_all_permissions()
        permissions_by_category = {}
        
        for perm in all_permissions:
            if perm.category not in permissions_by_category:
                permissions_by_category[perm.category] = []
            permissions_by_category[perm.category].append({
                'codename': perm.codename,
                'name': perm.name,
                'description': perm.description
            })
        
        return {
            'total_permissions': len(all_permissions),
            'permissions_by_category': permissions_by_category,
            'roles': [role.name for role in self.get_roles()]
        }
        
    def generate_2fa_secret(self):
        """Genera il segreto iniziale per l'autenticazione a due fattori"""
        import pyotp
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
            self.save()
        return self.two_factor_secret
    
    def regenerate_2fa_secret(self):
        """Rigenera il segreto per l'autenticazione a due fattori"""
        import pyotp
        self.two_factor_secret = pyotp.random_base32()
        self.two_factor_verified = False
        self.save()
        return self.two_factor_secret
    
    def get_totp_uri(self):
        """Genera l'URI per il QR code di Google Authenticator"""
        import pyotp
        if not self.two_factor_secret:
            self.generate_2fa_secret()
        
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.provisioning_uri(name=self.user.username, issuer_name="Cripto")
    
    def verify_2fa_code(self, code):
        """Verifica un codice 2FA"""
        import pyotp
        if not self.two_factor_secret or not self.two_factor_enabled:
            return False
        
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(code)
    
    def enable_2fa(self, verification_code):
        """Abilita l'autenticazione a due fattori dopo la verifica del codice"""
        import pyotp
        if not self.two_factor_secret:
            return False
        
        totp = pyotp.TOTP(self.two_factor_secret)
        if totp.verify(verification_code):
            self.two_factor_enabled = True
            self.two_factor_verified = True
            self.save()
            return True
        return False
    
    def disable_2fa(self):
        """Disabilita l'autenticazione a due fattori"""
        self.two_factor_enabled = False
        self.two_factor_verified = False
        self.save()
        return True

class SmartContract(models.Model):
    name = models.CharField(max_length=255, unique=True)
    code = models.TextField()
    deployer = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    block = models.ForeignKey(Block, on_delete=models.CASCADE, null=True, blank=True) # Allow null for pending contracts
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class BlockchainState(models.Model):
    current_supply = models.FloatField(default=0.0)
    max_supply = models.FloatField(default=21000000.0)
    current_reward = models.FloatField(default=0.05)
    halving_count = models.IntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)
    difficulty = models.FloatField(default=4.0)

    class Meta:
        verbose_name = "Blockchain State"
        verbose_name_plural = "Blockchain States"

    def __str__(self):
        return f"Blockchain State - Supply: {self.current_supply}"

class AuditLog(models.Model):
    ACTION_TYPES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('REGISTER', 'Registrazione'),
        ('CREATE_TRANSACTION', 'Creazione Transazione'),
        ('VIEW_TRANSACTION', 'Visualizzazione Transazione'),
        ('DOWNLOAD_FILE', 'Download File'),
        ('DECRYPT_MESSAGE', 'Decifratura Messaggio'),
        ('MINE_BLOCK', 'Mining Blocco'),
        ('EDIT_PROFILE', 'Modifica Profilo'),

        ('ADMIN_ACTION', 'Azione Amministrativa'),
        ('SECURITY_EVENT', 'Evento di Sicurezza'),
        ('EXPORT_DATA', 'Export Dati'),
        ('VERIFY_BLOCKCHAIN', 'Verifica Blockchain'),
        ('USER_MANAGEMENT', 'Gestione Utenti'),
        ('SYSTEM_EVENT', 'Evento di Sistema'),
        ('ROLE_ASSIGNMENT', 'Assegnazione Ruolo'),
        ('PERMISSION_CHANGE', 'Modifica Permessi'),
        ('USER_ACTIVATION', 'Attivazione Utente'),
        ('USER_DEACTIVATION', 'Disattivazione Utente'),
        ('SSO_LOGIN', 'Login SSO'),
    ]

    SEVERITY_LEVELS = [
        ('LOW', 'Basso'),
        ('MEDIUM', 'Medio'),
        ('HIGH', 'Alto'),
        ('CRITICAL', 'Critico'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='MEDIUM')
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    session_id = models.CharField(max_length=255, blank=True)
    related_object_type = models.CharField(max_length=100, blank=True)  # es: 'Transaction', 'Block', 'UserProfile'
    related_object_id = models.IntegerField(null=True, blank=True)
    additional_data = models.JSONField(default=dict, blank=True)  # Dati aggiuntivi in formato JSON
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=True)  # Se l'azione è stata completata con successo
    error_message = models.TextField(blank=True)  # Messaggio di errore se success=False

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        indexes = [
            models.Index(fields=['user', 'action_type', 'timestamp']),
            models.Index(fields=['action_type', 'severity', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.action_type} - {self.user} - {self.timestamp}"

    @classmethod
    def log_action(cls, user=None, action_type=None, description="", severity='MEDIUM', 
                   ip_address=None, user_agent="", session_id="", related_object_type="", 
                   related_object_id=None, additional_data=None, success=True, error_message=""):
        """Metodo di classe per creare facilmente log di audit"""
        try:
            return cls.objects.create(
                user=user,
                action_type=action_type,
                severity=severity,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                related_object_type=related_object_type,
                related_object_id=related_object_id,
                additional_data=additional_data or {},
                success=success,
                error_message=error_message
            )
        except Exception as e:
            print(f"Errore durante la creazione del log di audit: {e}")
            return None

    def get_related_object(self):
        """Restituisce l'oggetto correlato se esiste"""
        if not self.related_object_type or not self.related_object_id:
            return None
        
        try:
            model_class = globals().get(self.related_object_type)
            if model_class:
                return model_class.objects.get(id=self.related_object_id)
        except Exception:
            return None
        return None

# Sistema di Ruoli e Permessi
class Permission(models.Model):
    """Modello per i permessi granulari del sistema"""
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    category = models.CharField(max_length=50, choices=[
        ('USER_MANAGEMENT', 'Gestione Utenti'),
        ('TRANSACTION_MANAGEMENT', 'Gestione Transazioni'),
        ('BLOCKCHAIN_MANAGEMENT', 'Gestione Blockchain'),
        ('SYSTEM_ADMIN', 'Amministrazione Sistema'),
        ('AUDIT_LOGS', 'Log di Audit'),
        ('SECURITY', 'Sicurezza'),
        ('REPORTS', 'Report e Analytics'),
    ])
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['category', 'name']
        verbose_name = "Permesso"
        verbose_name_plural = "Permessi"

    def __str__(self):
        return f"{self.name} ({self.category})"

# --- AGGIUNTA CLASSE ROLE ---
class Role(models.Model):
    """Modello per i ruoli utente"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    permissions = models.ManyToManyField(Permission, blank=True)
    is_active = models.BooleanField(default=True)
    is_system_role = models.BooleanField(default=False)  # Ruoli di sistema non possono essere eliminati
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = "Ruolo"
        verbose_name_plural = "Ruoli"

    def __str__(self):
        return self.name

    def has_permission(self, permission_codename):
        """Verifica se il ruolo ha un determinato permesso"""
        return self.permissions.filter(codename=permission_codename, is_active=True).exists()

    def add_permission(self, permission_codename):
        """Aggiunge un permesso al ruolo"""
        try:
            permission = Permission.objects.get(codename=permission_codename, is_active=True)
            self.permissions.add(permission)
            return True
        except Permission.DoesNotExist:
            return False

    def remove_permission(self, permission_codename):
        """Rimuove un permesso dal ruolo"""
        try:
            permission = Permission.objects.get(codename=permission_codename)
            self.permissions.remove(permission)
            return True
        except Permission.DoesNotExist:
            return False
    
    def get_active_users_count(self):
        """Restituisce il numero di utenti attivi con questo ruolo"""
        return self.user_assignments.filter(is_active=True).count()
    
    def get_users(self):
        """Restituisce tutti gli utenti con questo ruolo (attivi e non scaduti)"""
        return User.objects.filter(
            user_roles__role=self,
            user_roles__is_active=True
        ).exclude(
            user_roles__expires_at__lt=timezone.now()
        ).distinct()

    def get_active_assignments_count(self):
        """Restituisce il numero di assegnazioni attive"""
        return UserRole.objects.filter(
            role=self,
            is_active=True
        ).count()

    def get_expired_assignments_count(self):
        """Restituisce il numero di assegnazioni scadute"""
        return UserRole.objects.filter(
            role=self,
            is_active=True,
            expires_at__lt=timezone.now()
        ).count()

    def get_total_assignments_count(self):
        """Restituisce il numero totale di assegnazioni"""
        return UserRole.objects.filter(role=self).count()


class UserRole(models.Model):
    """Modello per l'assegnazione di ruoli agli utenti"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey('Role', on_delete=models.CASCADE, related_name='user_assignments')  # Usa riferimento stringa
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='role_assignments_made')
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)  # Scadenza del ruolo
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)

    class Meta:
        unique_together = ['user', 'role']
        ordering = ['-assigned_at']
        verbose_name = "Ruolo Utente"
        verbose_name_plural = "Ruoli Utente"

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"

    def is_expired(self):
        """Verifica se il ruolo è scaduto"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    def is_valid(self):
        """Verifica se il ruolo è valido (attivo e non scaduto)"""
        return self.is_active and not self.is_expired()

class PersonalDocument(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='personal_documents')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    file = models.FileField(upload_to='personal_documents/', 
                          validators=[FileExtensionValidator(allowed_extensions=['pdf', 'csv', 'xlsx', 'xls', 'doc', 'docx', 'txt'])])
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_encrypted = models.BooleanField(default=False)
    original_filename = models.CharField(max_length=255, blank=True, null=True)
    encrypted_symmetric_key = models.BinaryField(null=True, blank=True)
    is_shareable = models.BooleanField(default=False)  # Nuovo campo per indicare se il file è condivisibile
    
    def __str__(self):
        return f"{self.title} - {self.user.username}"
