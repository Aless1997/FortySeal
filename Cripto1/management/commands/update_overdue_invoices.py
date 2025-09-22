from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import date
from Cripto1.models import Invoice, OrganizationBilling

class Command(BaseCommand):
    help = 'Aggiorna gli stati delle fatture e dei pagamenti scaduti'
    
    def handle(self, *args, **options):
        today = date.today()
        
        # Aggiorna fatture scadute
        overdue_invoices = Invoice.objects.filter(
            status='sent',
            due_date__lt=today
        )
        
        updated_invoices = overdue_invoices.update(status='overdue')
        
        # Aggiorna stati di pagamento delle organizzazioni
        overdue_billings = OrganizationBilling.objects.filter(
            payment_status='pending',
            next_payment_due__lt=today
        )
        
        updated_billings = overdue_billings.update(payment_status='overdue')
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Aggiornate {updated_invoices} fatture e {updated_billings} configurazioni di fatturazione scadute'
            )
        )