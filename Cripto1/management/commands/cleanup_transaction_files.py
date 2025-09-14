from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import os
import logging
from Cripto1.models import Transaction, Organization

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Elimina file scaduti usando le impostazioni delle organizzazioni'
    
    def handle(self, *args, **options):
        deleted_count = 0
        
        for org in Organization.objects.filter(auto_delete_enabled=True):
            retention_delta = org.get_auto_delete_timedelta()
            if retention_delta:
                cutoff_time = timezone.now() - retention_delta
                cutoff_timestamp = cutoff_time.timestamp()
                
                expired_transactions = Transaction.objects.filter(
                    organization=org,
                    timestamp__lt=cutoff_timestamp
                )
                
                org_deleted = 0
                # Sostituire le righe 28-35 con:
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
                            org_deleted += 1
                            deleted_count += 1
                    except Exception as e:
                        logger.error(f'Errore: {e}')
                
                if org_deleted > 0:
                    self.stdout.write(f'Org {org.name}: {org_deleted} file eliminati')
        
        self.stdout.write(
            self.style.SUCCESS(f'Totale: {deleted_count} transazioni eliminate')
        )