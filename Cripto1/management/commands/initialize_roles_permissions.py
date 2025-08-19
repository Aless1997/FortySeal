from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from Cripto1.models import Permission, Role, UserRole, UserProfile
from django.utils import timezone


class Command(BaseCommand):
    help = 'Inizializza i permessi e ruoli di base del sistema'

    def handle(self, *args, **options):
        self.stdout.write('Inizializzazione permessi e ruoli...')
        
        # Crea i permessi di base
        permissions_data = [
            # Gestione Utenti
            ('view_users', 'Visualizza Utenti', 'Visualizzare la lista degli utenti'),
            ('add_users', 'Aggiungi Utenti', 'Creare nuovi utenti'),
            ('edit_users', 'Modifica Utenti', 'Modificare i dati degli utenti'),
            ('delete_users', 'Elimina Utenti', 'Eliminare utenti'),
            ('activate_users', 'Attiva/Disattiva Utenti', 'Attivare o disattivare utenti'),
            ('assign_roles', 'Assegna Ruoli', 'Assegnare ruoli agli utenti'),
            ('manage_roles', 'Gestisci Ruoli', 'Creare e modificare ruoli'),
            
            # Gestione Transazioni
            ('view_transactions', 'Visualizza Transazioni', 'Visualizzare le transazioni'),
            ('create_transactions', 'Crea Transazioni', 'Creare nuove transazioni'),
            ('delete_transactions', 'Elimina Transazioni', 'Eliminare transazioni'),
            
            # Gestione Blockchain
            ('view_blockchain', 'Visualizza Blockchain', 'Visualizzare lo stato della blockchain'),
            ('mine_blocks', 'Mina Blocchi', 'Eseguire il mining di nuovi blocchi'),
            ('verify_blockchain', 'Verifica Blockchain', 'Verificare l\'integrità della blockchain'),
            
            # Amministrazione Sistema
            ('view_admin_dashboard', 'Dashboard Admin', 'Accedere alla dashboard amministrativa'),
            ('export_data', 'Export Dati', 'Esportare dati del sistema'),
            ('view_audit_logs', 'Visualizza Log Audit', 'Visualizzare i log di audit'),
            ('manage_system', 'Gestisci Sistema', 'Gestire le impostazioni del sistema'),
        ]
        
        created_permissions = []
        for codename, name, description in permissions_data:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={
                    'name': name,
                    'description': description,
                    'category': 'USER_MANAGEMENT' if 'user' in codename else 
                               'TRANSACTION_MANAGEMENT' if 'transaction' in codename else
                               'BLOCKCHAIN_MANAGEMENT' if 'blockchain' in codename or 'mine' in codename else
                               'SYSTEM_ADMIN'
                }
            )
            created_permissions.append(permission)
            if created:
                self.stdout.write(f'  Creato permesso: {name}')
        
        # Crea i ruoli di base
        roles_data = [
            {
                'name': 'Super Admin',
                'description': 'Amministratore completo del sistema con tutti i permessi',
                'is_system_role': True,
                'permissions': [p.codename for p in created_permissions]
            },
            {
                'name': 'User Manager',
                'description': 'Gestisce utenti e ruoli',
                'is_system_role': False,
                'permissions': ['view_users', 'add_users', 'edit_users', 'activate_users', 'assign_roles', 'manage_roles']
            },
            {
                'name': 'Transaction Manager',
                'description': 'Gestisce transazioni e blockchain',
                'is_system_role': False,
                'permissions': ['view_transactions', 'create_transactions', 'view_blockchain', 'mine_blocks']
            },
            {
                'name': 'Auditor',
                'description': 'Visualizza log e report',
                'is_system_role': False,
                'permissions': ['view_audit_logs', 'view_admin_dashboard']
            },
            {
                'name': 'User',
                'description': 'Utente standard del sistema',
                'is_system_role': False,
                'permissions': ['view_transactions', 'create_transactions']
            }
        ]
        
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={
                    'description': role_data['description'],
                    'is_system_role': role_data['is_system_role'],
                    'is_active': True
                }
            )
            
            if created:
                self.stdout.write(f'  Creato ruolo: {role.name}')
            
            # Assegna i permessi al ruolo
            for permission_codename in role_data['permissions']:
                try:
                    permission = Permission.objects.get(codename=permission_codename)
                    role.permissions.add(permission)
                except Permission.DoesNotExist:
                    self.stdout.write(f'    Permesso {permission_codename} non trovato per ruolo {role.name}')
        
        # Assegna il ruolo Super Admin al primo superuser
        superusers = User.objects.filter(is_superuser=True)
        if superusers.exists():
            super_admin_role = Role.objects.get(name='Super Admin')
            for superuser in superusers:
                user_profile, created = UserProfile.objects.get_or_create(user=superuser)
                if not UserRole.objects.filter(user=superuser, role=super_admin_role).exists():
                    UserRole.objects.create(
                        user=superuser,
                        role=super_admin_role,
                        assigned_by=superuser,
                        notes='Assegnazione automatica al superuser'
                    )
                    self.stdout.write(f'  Assegnato ruolo Super Admin a {superuser.username}')
        
        self.stdout.write(self.style.SUCCESS('Inizializzazione completata con successo!')) 