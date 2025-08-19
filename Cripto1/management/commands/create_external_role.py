from django.core.management.base import BaseCommand
from Cripto1.models import Role, Permission

class Command(BaseCommand):
    help = 'Crea il ruolo "external" con permessi limitati'

    def handle(self, *args, **options):
        # Verifica se il ruolo esiste già
        if Role.objects.filter(name='external').exists():
            self.stdout.write(self.style.WARNING('Il ruolo "external" esiste già'))
            return

        # Crea il ruolo
        external_role = Role.objects.create(
            name='external',
            description='Ruolo per utenti esterni che possono solo ricevere e decriptare transazioni',
            is_active=True,
            is_system_role=True  # Ruolo di sistema, non può essere eliminato
        )

        # Aggiungi i permessi necessari
        # Nota: questi permessi devono esistere nel sistema
        permissions_to_add = [
            'view_transactions',  # Per vedere le proprie transazioni
            'decrypt_transactions',  # Per decriptare le transazioni
            'view_profile',  # Per vedere il proprio profilo
            'edit_profile',  # Per modificare il proprio profilo
            'view_personal_documents',  # Per vedere i propri documenti
            'manage_personal_documents',  # Per gestire i propri documenti
        ]

        for perm_code in permissions_to_add:
            external_role.add_permission(perm_code)

        self.stdout.write(self.style.SUCCESS(f'Ruolo "external" creato con successo con {len(permissions_to_add)} permessi'))