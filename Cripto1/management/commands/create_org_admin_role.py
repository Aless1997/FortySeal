from django.core.management.base import BaseCommand
from Cripto1.models import Role, Permission

class Command(BaseCommand):
    help = 'Crea il ruolo Organization Admin con i permessi appropriati'
    
    def handle(self, *args, **options):
        # Crea il ruolo Organization Admin
        role, created = Role.objects.get_or_create(
            name='Organization Admin',
            defaults={
                'description': 'Amministratore dell\'organizzazione con privilegi limitati alla propria organizzazione',
                'is_active': True
            }
        )
        
        if created:
            self.stdout.write(self.style.SUCCESS(f'Ruolo "{role.name}" creato con successo'))
        else:
            self.stdout.write(self.style.WARNING(f'Ruolo "{role.name}" già esistente'))
        
        # Permessi per Organization Admin
        org_admin_permissions = [
            'view_admin_dashboard',
            'manage_organization_users',
            'view_audit_logs',
            'manage_organization_roles',
            'view_organization_sessions',
            'assign_roles'  # Aggiunto questo permesso
        ]
        
        for perm_code in org_admin_permissions:
            try:
                permission = Permission.objects.get(codename=perm_code)
                role.permissions.add(permission)
                self.stdout.write(f'Aggiunto permesso: {perm_code}')
            except Permission.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Permesso non trovato: {perm_code}'))
        
        self.stdout.write(self.style.SUCCESS('Configurazione completata!'))