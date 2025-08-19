from django.core.management.base import BaseCommand
from Cripto1.models import Permission, Role

class Command(BaseCommand):
    help = 'Crea i permessi per la gestione utenti'

    def handle(self, *args, **options):
        # Permessi per la gestione utenti
        permissions_data = [
            {
                'name': 'user_management_view',
                'description': 'Visualizzare la dashboard di gestione utenti',
                'category': 'Gestione Utenti'
            },
            {
                'name': 'user_management_create',
                'description': 'Creare nuovi utenti',
                'category': 'Gestione Utenti'
            },
            {
                'name': 'user_management_edit',
                'description': 'Modificare utenti esistenti',
                'category': 'Gestione Utenti'
            },
            {
                'name': 'user_management_delete',
                'description': 'Eliminare utenti',
                'category': 'Gestione Utenti'
            },
            {
                'name': 'user_management_activate',
                'description': 'Attivare/disattivare utenti',
                'category': 'Gestione Utenti'
            },
            {
                'name': 'role_management_view',
                'description': 'Visualizzare i ruoli',
                'category': 'Gestione Ruoli'
            },
            {
                'name': 'role_management_create',
                'description': 'Creare nuovi ruoli',
                'category': 'Gestione Ruoli'
            },
            {
                'name': 'role_management_edit',
                'description': 'Modificare ruoli esistenti',
                'category': 'Gestione Ruoli'
            },
            {
                'name': 'role_management_delete',
                'description': 'Eliminare ruoli',
                'category': 'Gestione Ruoli'
            },
            {
                'name': 'role_management_assign',
                'description': 'Assegnare ruoli agli utenti',
                'category': 'Gestione Ruoli'
            },
            {
                'name': 'role_management_remove',
                'description': 'Rimuovere ruoli dagli utenti',
                'category': 'Gestione Ruoli'
            },
        ]

        created_count = 0
        for perm_data in permissions_data:
            permission, created = Permission.objects.get_or_create(
                name=perm_data['name'],
                defaults={
                    'description': perm_data['description'],
                    'category': perm_data['category']
                }
            )
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Permesso creato: {permission.name}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'Permesso già esistente: {permission.name}')
                )

        self.stdout.write(
            self.style.SUCCESS(f'Completato! {created_count} nuovi permessi creati.')
        )

        # Assegna i permessi al ruolo Super Admin se esiste
        try:
            super_admin_role = Role.objects.get(name='Super Admin')
            user_management_permissions = Permission.objects.filter(
                name__icontains='user_management'
            )
            role_management_permissions = Permission.objects.filter(
                name__icontains='role_management'
            )
            
            # Aggiungi tutti i permessi di gestione utenti e ruoli
            all_permissions = list(user_management_permissions) + list(role_management_permissions)
            super_admin_role.permissions.add(*all_permissions)
            
            self.stdout.write(
                self.style.SUCCESS(f'Permessi assegnati al ruolo Super Admin')
            )
        except Role.DoesNotExist:
            self.stdout.write(
                self.style.WARNING('Ruolo Super Admin non trovato. Esegui prima il comando initialize_roles_permissions.')
            ) 