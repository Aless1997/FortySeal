from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from Cripto1.models import Permission, Role, UserRole, UserProfile

class Command(BaseCommand):
    help = 'Configura completamente il sistema di permessi'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Forza la ricreazione di tutti i permessi e ruoli',
        )

    def handle(self, *args, **options):
        self.stdout.write('=== CONFIGURAZIONE SISTEMA PERMESSI ===')
        
        # 1. Crea tutti i permessi necessari
        self.stdout.write('\n1. Creazione permessi...')
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
            if options['force']:
                # Rimuovi permesso esistente se force=True
                Permission.objects.filter(codename=codename).delete()
            
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={
                    'name': name,
                    'description': description,
                    'category': 'USER_MANAGEMENT' if 'user' in codename or 'role' in codename else
                               'TRANSACTION_MANAGEMENT' if 'transaction' in codename else
                               'BLOCKCHAIN_MANAGEMENT' if 'blockchain' in codename or 'mine' in codename else
                               'SYSTEM_ADMIN'
                }
            )
            created_permissions.append(permission)
            if created:
                self.stdout.write(f'  Creato permesso: {name}')
        
        # 2. Crea i ruoli di base
        self.stdout.write('\n2. Creazione ruoli...')
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
            },
            # Aggiungiamo il ruolo external
            {
                'name': 'external',
                'description': 'Utente esterno con accesso limitato',
                'is_system_role': False,
                'permissions': ['view_transactions']
            }
        ]
        
        for role_data in roles_data:
            if options['force']:
                # Rimuovi ruolo esistente se force=True
                Role.objects.filter(name=role_data['name']).delete()
            
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
            role.permissions.clear()  # Rimuovi permessi esistenti
            for permission_codename in role_data['permissions']:
                try:
                    permission = Permission.objects.get(codename=permission_codename)
                    role.permissions.add(permission)
                except Permission.DoesNotExist:
                    self.stdout.write(f'    ERRORE: Permesso {permission_codename} non trovato per ruolo {role.name}')
        
        # 3. Crea profili per tutti gli utenti
        self.stdout.write('\n3. Creazione profili utente...')
        for user in User.objects.all():
            profile, created = UserProfile.objects.get_or_create(user=user)
            if created:
                self.stdout.write(f'  Creato profilo per {user.username}')
        
        # 4. Assegna ruolo Super Admin ai superuser
        self.stdout.write('\n4. Assegnazione ruoli ai superuser...')
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
        
        # 5. Verifica finale
        self.stdout.write('\n5. Verifica finale...')
        total_permissions = Permission.objects.count()
        total_roles = Role.objects.count()
        total_user_profiles = UserProfile.objects.count()
        total_user_roles = UserRole.objects.count()
        
        self.stdout.write(f'  Permessi totali: {total_permissions}')
        self.stdout.write(f'  Ruoli totali: {total_roles}')
        self.stdout.write(f'  Profili utente: {total_user_profiles}')
        self.stdout.write(f'  Assegnazioni ruoli: {total_user_roles}')
        
        self.stdout.write(self.style.SUCCESS('\n=== CONFIGURAZIONE COMPLETATA ==='))
        self.stdout.write('\nPer testare i permessi, visita: /debug/permissions/')