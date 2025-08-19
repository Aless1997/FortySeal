from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import os

def validate_file_security(file):
    """Validatore per la sicurezza dei file caricati"""
    # 1. Controllo estensione
    allowed_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv', 'jpg', 'jpeg', 'png', 'gif']
    file_extension = file.name.split('.')[-1].lower()
    
    if file_extension not in allowed_extensions:
        raise ValidationError(
            _(f'Estensione file non consentita. Estensioni permesse: {", ".join(allowed_extensions)}')
        )
    
    # 2. Controllo dimensione
    if file.size > 10 * 1024 * 1024:  # 10MB
        raise ValidationError(_('Il file è troppo grande. Dimensione massima: 10MB'))
    
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
            print(f"Errore durante la scansione antivirus: {str(e)}")
    except ImportError:
        print("django-clamd non è installato. La scansione antivirus è disabilitata.")
    
    # Riavvolgi il file per l'uso successivo
    file.seek(0)