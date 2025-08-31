from django.core.management.base import BaseCommand
from Cripto1.models import Permission

class Command(BaseCommand):
    help = 'Crea i permessi mancanti per Organization Admin'

    def handle(self, *args, **options):
        permissions_data = [
            ('manage_organization_users', 'Gestisci Utenti Organizzazione', 'Gestire gli utenti della propria organizzazione', 'USER_MANAGEMENT'),
            ('manage_organization_roles', 'Gestisci Ruoli Organizzazione', 'Gestire i ruoli della propria organizzazione', 'USER_MANAGEMENT'),
            ('view_organization_sessions', 'Visualizza Sessioni Organizzazione', 'Visualizzare le sessioni attive della propria organizzazione', 'SECURITY'),
        ]
        
        for codename, name, description, category in permissions_data:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={
                    'name': name,
                    'description': description,
                    'category': category
                }
            )
            if created:
                self.stdout.write(f'Creato permesso: {name}')
            else:
                self.stdout.write(f'Permesso già esistente: {name}')
        
        self.stdout.write('Permessi Organization Admin creati con successo!')