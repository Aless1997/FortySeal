from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from Cripto1.models import Permission, Role, UserRole, UserProfile

class Command(BaseCommand):
    help = 'Verifica e correggi i permessi nel sistema'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Correggi automaticamente i problemi trovati',
        )
        parser.add_argument(
            '--user',
            type=str,
            help='Verifica un utente specifico',
        )

    def handle(self, *args, **options):
        self.stdout.write('=== VERIFICA PERMESSI SISTEMA ===')
        
        # 1. Verifica permessi esistenti
        self.stdout.write('\n1. Permessi nel sistema:')
        permissions = Permission.objects.all()
        for perm in permissions:
            self.stdout.write(f'  - {perm.codename}: {perm.name} ({perm.category})')
        
        # 2. Verifica ruoli
        self.stdout.write('\n2. Ruoli nel sistema:')
        roles = Role.objects.all()
        for role in roles:
            role_perms = role.permissions.all()
            self.stdout.write(f'  - {role.name}: {[p.codename for p in role_perms]}')
        
        # 3. Verifica utenti e loro ruoli
        self.stdout.write('\n3. Utenti e ruoli:')
        users = User.objects.all()
        for user in users:
            try:
                profile = UserProfile.objects.get(user=user)
                user_roles = UserRole.objects.filter(user=user, is_active=True)
                role_names = [ur.role.name for ur in user_roles]
                self.stdout.write(f'  - {user.username}: {role_names}')
                
                # Verifica permessi dell'utente
                if options['user'] and user.username == options['user']:
                    self.stdout.write(f'    Permessi di {user.username}:')
                    all_perms = profile.get_all_permissions()
                    for perm in all_perms:
                        self.stdout.write(f'      - {perm.codename}: {perm.name}')
                    
                    # Test specifici
                    test_permissions = ['view_users', 'add_users', 'edit_users', 'manage_roles']
                    for test_perm in test_permissions:
                        has_perm = profile.has_permission(test_perm)
                        self.stdout.write(f'      Test {test_perm}: {has_perm}')
                        
            except UserProfile.DoesNotExist:
                self.stdout.write(f'  - {user.username}: NO PROFILE')
        
        # 4. Verifica problemi comuni
        self.stdout.write('\n4. Problemi trovati:')
        
        # Utenti senza profilo
        users_without_profile = []
        for user in users:
            if not UserProfile.objects.filter(user=user).exists():
                users_without_profile.append(user.username)
        
        if users_without_profile:
            self.stdout.write(f'  - Utenti senza profilo: {users_without_profile}')
            if options['fix']:
                for username in users_without_profile:
                    user = User.objects.get(username=username)
                    UserProfile.objects.create(user=user)
                    self.stdout.write(f'    Creato profilo per {username}')
        
        # Ruoli senza permessi
        roles_without_permissions = []
        for role in roles:
            if role.permissions.count() == 0:
                roles_without_permissions.append(role.name)
        
        if roles_without_permissions:
            self.stdout.write(f'  - Ruoli senza permessi: {roles_without_permissions}')
        
        # Permessi non assegnati a nessun ruolo
        unassigned_permissions = []
        for perm in permissions:
            if perm.role_set.count() == 0:
                unassigned_permissions.append(perm.codename)
        
        if unassigned_permissions:
            self.stdout.write(f'  - Permessi non assegnati: {unassigned_permissions}')
        
        self.stdout.write('\n=== VERIFICA COMPLETATA ===') 