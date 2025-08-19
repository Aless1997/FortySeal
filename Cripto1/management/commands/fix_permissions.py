from django.core.management.base import BaseCommand
from Cripto1.models import Permission, Role, UserRole, UserProfile

class Command(BaseCommand):
    help = 'Correggi l\'assegnazione dei permessi ai ruoli'

    def handle(self, *args, **options):
        self.stdout.write('=== CORREZIONE PERMESSI ===')
        
        # Definizione dei permessi per ruolo
        role_permissions = {
            'Super Admin': [
                'view_users', 'add_users', 'edit_users', 'delete_users', 'activate_users',
                'assign_roles', 'manage_roles', 'view_transactions', 'create_transactions',
                'delete_transactions', 'view_blockchain', 'mine_blocks', 'verify_blockchain',
                'view_admin_dashboard', 'export_data', 'view_audit_logs', 'manage_system'
            ],
            'User Manager': [
                'view_users', 'add_users', 'edit_users', 'activate_users', 'assign_roles', 'manage_roles'
            ],
            'Transaction Manager': [
                'view_transactions', 'create_transactions', 'view_blockchain', 'mine_blocks'
            ],
            'Auditor': [
                'view_audit_logs', 'view_admin_dashboard'
            ],
            'User': [
                'view_transactions', 'create_transactions'
            ]
        }
        
        # Assicurati che tutti i permessi esistano
        all_permissions = set()
        for perms in role_permissions.values():
            all_permissions.update(perms)
        
        self.stdout.write('Creazione permessi mancanti...')
        for perm_codename in all_permissions:
            perm, created = Permission.objects.get_or_create(
                codename=perm_codename,
                defaults={
                    'name': perm_codename.replace('_', ' ').title(),
                    'description': f'Permesso per {perm_codename}',
                    'category': 'USER_MANAGEMENT' if 'user' in perm_codename or 'role' in perm_codename else
                               'TRANSACTION_MANAGEMENT' if 'transaction' in perm_codename else
                               'BLOCKCHAIN_MANAGEMENT' if 'blockchain' in perm_codename or 'mine' in perm_codename else
                               'SYSTEM_ADMIN'
                }
            )
            if created:
                self.stdout.write(f'  Creato permesso: {perm_codename}')
        
        # Assegna i permessi ai ruoli
        self.stdout.write('\nAssegnazione permessi ai ruoli...')
        for role_name, permission_codenames in role_permissions.items():
            try:
                role = Role.objects.get(name=role_name)
                permissions = Permission.objects.filter(codename__in=permission_codenames)
                
                # Rimuovi tutti i permessi esistenti e riassegna
                role.permissions.clear()
                role.permissions.add(*permissions)
                
                self.stdout.write(f'  Ruolo {role_name}: {[p.codename for p in permissions]}')
                
            except Role.DoesNotExist:
                self.stdout.write(f'  Ruolo {role_name} non trovato')
        
        # Verifica che tutti gli utenti abbiano un profilo
        self.stdout.write('\nVerifica profili utente...')
        from django.contrib.auth.models import User
        for user in User.objects.all():
            profile, created = UserProfile.objects.get_or_create(user=user)
            if created:
                self.stdout.write(f'  Creato profilo per {user.username}')
        
        # Assegna ruolo Super Admin ai superuser se non ce l'hanno già
        super_admin_role = Role.objects.get(name='Super Admin')
        for user in User.objects.filter(is_superuser=True):
            if not UserRole.objects.filter(user=user, role=super_admin_role).exists():
                UserRole.objects.create(
                    user=user,
                    role=super_admin_role,
                    assigned_by=user,
                    notes='Assegnazione automatica al superuser'
                )
                self.stdout.write(f'  Assegnato ruolo Super Admin a {user.username}')
        
        self.stdout.write(self.style.SUCCESS('\n=== CORREZIONE COMPLETATA ===')) 