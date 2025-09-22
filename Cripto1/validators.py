from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import os

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available, skipping MIME type validation")

def validate_file_security(file, user=None):
    """Validatore per la sicurezza dei file caricati"""
    # 1. Controllo estensione
    allowed_extensions = [
        # Documenti
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv',
        # Immagini
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg',
        # Video
        'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv', '3gp', 'm4v',
        # File compressi
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz',
        # Disegni tecnici
        'dwg', 'dxf', 'dwf', 'step', 'stp', 'iges', 'igs',
        # ESEGUIBILI (ALTO RISCHIO)
        'exe'
    ]
    file_extension = file.name.split('.')[-1].lower()
    
    # Controllo speciale per file eseguibili
    if file_extension == 'exe':
        # Solo superadmin possono caricare .exe
        if not (user and (user.is_superuser or user.userprofile.has_role('Super Admin'))):
            raise ValidationError(
                _("Solo i Super Admin possono caricare file eseguibili per motivi di sicurezza.")
            )
        
        # Log di sicurezza per file .exe
        import logging
        logger = logging.getLogger('security')
        logger.warning(f"File .exe caricato da {user.username}: {file.name}")
    
    if file_extension not in allowed_extensions:
        raise ValidationError(
            _(f'Estensione file non consentita. Estensioni permesse: {", ".join(allowed_extensions)}')
        )
    
    # 1. Controllo magic bytes (solo se disponibile)
    if MAGIC_AVAILABLE:
        try:
            file_mime = magic.from_buffer(file.read(1024), mime=True)
            file.seek(0)
            
            allowed_mimes = [
                'application/pdf', 'image/jpeg', 'image/png',
                'application/msword', 'text/plain'
            ]
            
            if file_mime not in allowed_mimes:
                raise ValidationError(f'Tipo file non consentito: {file_mime}')
        except Exception as e:
            print(f"Warning: Magic validation failed: {e}")
    
    # 2. Controllo dimensione con limite dell'organizzazione
    max_size = 10 * 1024 * 1024  # Default 10 MB
    
    if user and hasattr(user, 'userprofile') and user.userprofile.organization:
        org_limit_mb = user.userprofile.organization.max_file_size_mb
        max_size = org_limit_mb * 1024 * 1024  # Converti MB in bytes
    
    if file.size > max_size:
        max_size_mb = max_size // (1024 * 1024)
        raise ValidationError(f'Il file è troppo grande. Dimensione massima consentita: {max_size_mb} MB')
    
    # 3. Scansione contenuto per pattern pericolosi
    content = file.read()
    file.seek(0)
    
    dangerous_patterns = [b'<script', b'javascript:', b'<?php']
    for pattern in dangerous_patterns:
        if pattern in content.lower():
            raise ValidationError('Contenuto file non sicuro')
    
    # 2. Controllo dimensione
    def validate_file_size(file, user=None):
        # Ottieni il limite dall'organizzazione dell'utente
        max_size = 10 * 1024 * 1024  # Default 10 MB
        
        if user and hasattr(user, 'userprofile') and user.userprofile.organization:
            org_limit_mb = user.userprofile.organization.max_file_size_mb
            max_size = org_limit_mb * 1024 * 1024  # Converti MB in bytes
        
        if file.size > max_size:
            max_size_mb = max_size // (1024 * 1024)
            raise ValidationError(f'Il file è troppo grande. Dimensione massima consentita: {max_size_mb} MB')
    
    # 3. Scansione antivirus
    try:
        from django_clamd import clamd
        from tempfile import NamedTemporaryFile
        
        with NamedTemporaryFile(delete=False) as temp_file:
            for chunk in file.chunks():
                temp_file.write(chunk)
            temp_file_path = temp_file.name
        
        try:
            scanner = clamd.ClamdUnixSocket()
            scan_result = scanner.scan_file(temp_file_path)
            
            if scan_result and temp_file_path in scan_result and scan_result[temp_file_path][0] == 'FOUND':
                virus_name = scan_result[temp_file_path][1]
                os.unlink(temp_file_path)
                raise ValidationError(_('Il file contiene codice malevolo e non può essere caricato.'))
            
            os.unlink(temp_file_path)
            
        except Exception as e:
            os.unlink(temp_file_path)
            # Gestisci l'errore di scansione
            pass  # Rimuovi il print di debug
    except ImportError:
        pass  # Rimuovi il print di debug
    
    # Riavvolgi il file per l'uso successivo
    file.seek(0)