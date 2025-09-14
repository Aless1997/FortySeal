from django.core.management.base import BaseCommand
from django.core.cache import cache
from django.utils import timezone
from Cripto1.models import Organization, Transaction

class Command(BaseCommand):
    help = 'Mostra stato del sistema di auto-cleanup'
    
    def handle(self, *args, **options):
        last_cleanup = cache.get('last_cleanup_time')
        
        if last_cleanup:
            time_since = timezone.now() - last_cleanup
            self.stdout.write(f'Ultimo cleanup: {time_since.total_seconds()/60:.1f} minuti fa')
        else:
            self.stdout.write('Nessun cleanup registrato')
        
        # Statistiche organizzazioni
        orgs_enabled = Organization.objects.filter(auto_delete_enabled=True).count()
        total_transactions = Transaction.objects.count()
        
        self.stdout.write(f'Organizzazioni con auto-cleanup: {orgs_enabled}')
        self.stdout.write(f'Transazioni totali: {total_transactions}')