from django.utils import timezone
from django.core.cache import cache  # AGGIUNTO: import mancante
from datetime import timedelta
import os
import logging
from .models import Organization, Transaction

logger = logging.getLogger(__name__)

def cleanup_expired_files():  # RINOMINATO: da smart_cleanup_expired_files
    """Sistema MRP intelligente - controlla cache per evitare cleanup troppo frequenti"""
    
    # Controlla se è già stato fatto cleanup di recente
    last_cleanup = cache.get('last_cleanup_time')
    now = timezone.now()
    
    if last_cleanup:
        time_since_cleanup = now - last_cleanup
        if time_since_cleanup < timedelta(minutes=15):  # Minimo 15 minuti tra cleanup
            return 0
    
    deleted_count = 0
    
    try:
        for org in Organization.objects.filter(auto_delete_enabled=True):
            retention_delta = org.get_auto_delete_timedelta()
            if retention_delta:
                cutoff_time = now - retention_delta
                cutoff_timestamp = cutoff_time.timestamp()
                
                # Query ottimizzata
                expired_transactions = Transaction.objects.filter(
                    organization=org,
                    timestamp__lt=cutoff_timestamp
                ).select_related('organization')
                
                org_deleted = 0
                # Correggere le righe 38-47:
                for transaction in expired_transactions:
                    try:
                        file_deleted = False
                        if transaction.file and os.path.exists(transaction.file.path):
                            file_path = transaction.file.path  # Salva il path prima di rimuovere il riferimento
                            os.remove(file_path)  # Elimina il file fisico
                            file_deleted = True
                        
                        # Solo dopo aver eliminato il file, rimuovi il riferimento
                        if file_deleted:
                            transaction.file = None  # Rimuove il riferimento al file
                            transaction.save()       # Mantiene la transazione per lo storico
                            org_deleted += 1
                            deleted_count += 1
                    except Exception as e:
                        logger.error(f'Errore eliminando file transazione {transaction.id}: {e}')
                
                if org_deleted > 0:
                    logger.info(f'Org {org.name}: {org_deleted} file eliminati')
        
        # Aggiorna cache
        cache.set('last_cleanup_time', now, timeout=3600)  # Cache per 1 ora
        
        if deleted_count > 0:
            logger.info(f'Cleanup completato: {deleted_count} file totali eliminati')
            
    except Exception as e:
        logger.error(f'Errore durante cleanup: {e}')
    
    return deleted_count

# Funzione helper per trigger manuali
def trigger_cleanup_if_needed():
    """Trigger cleanup solo se necessario"""
    return cleanup_expired_files()