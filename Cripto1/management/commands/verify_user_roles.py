from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from Cripto1.models import UserProfile, UserRole, Role, Permission
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Verifica e correggi i dati dei ruoli utente nel database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Corregge automaticamente i problemi trovati',
        )
        parser.add_argument(
            '--user',
            type=str,
            help='Verifica solo per un utente specifico (username)',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Inizio verifica ruoli utente...'))
        
        # Ottieni tutti gli utenti o un utente specifico
        if options['user']:
            try:
                users = [User.objects.get(username=options['user'])]
                self.stdout.write(f'Verifica per utente: {options["user"]}')
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Utente {options["user"]} non trovato'))
                return
        else:
            users = User.objects.all()
            self.stdout.write(f'Verifica per {users.count()} utenti')

        total_issues = 0
        fixed_issues = 0

        for user in users:
            self.stdout.write(f'\n--- Verifica utente: {user.username} ---')
            
            # Verifica profilo utente
            try:
                profile = UserProfile.objects.get(user=user)
                self.stdout.write(f'✓ Profilo utente trovato')
            except UserProfile.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'✗ Profilo utente mancante per {user.username}'))
                total_issues += 1
                if options['fix']:
                    profile = UserProfile.objects.create(user=user)
                    self.stdout.write(self.style.SUCCESS(f'✓ Profilo utente creato per {user.username}'))
                    fixed_issues += 1
                continue

            # Verifica ruoli assegnati
            user_roles = UserRole.objects.filter(user=user)
            self.stdout.write(f'Ruoli assegnati: {user_roles.count()}')
            
            for user_role in user_roles:
                # Verifica se il ruolo esiste ancora
                if not Role.objects.filter(id=user_role.role.id).exists():
                    self.stdout.write(self.style.ERROR(f'✗ Ruolo {user_role.role.name} non esiste più'))
                    total_issues += 1
                    if options['fix']:
                        user_role.delete()
                        self.stdout.write(self.style.SUCCESS(f'✓ Assegnazione ruolo rimossa'))
                        fixed_issues += 1
                    continue

                # Verifica scadenza
                if user_role.expires_at and user_role.expires_at < timezone.now():
                    self.stdout.write(self.style.WARNING(f'⚠ Ruolo {user_role.role.name} scaduto il {user_role.expires_at}'))
                    if options['fix']:
                        user_role.is_active = False
                        user_role.save()
                        self.stdout.write(self.style.SUCCESS(f'✓ Ruolo {user_role.role.name} disattivato'))
                        fixed_issues += 1

                # Verifica stato attivo
                if user_role.is_active:
                    self.stdout.write(f'✓ Ruolo {user_role.role.name} attivo')
                else:
                    self.stdout.write(f'⚠ Ruolo {user_role.role.name} inattivo')

            # Verifica ruoli duplicati
            active_roles = user_roles.filter(is_active=True)
            role_ids = list(active_roles.values_list('role_id', flat=True))
            if len(role_ids) != len(set(role_ids)):
                self.stdout.write(self.style.ERROR(f'✗ Ruoli duplicati trovati'))
                total_issues += 1
                if options['fix']:
                    # Mantieni solo la prima assegnazione per ogni ruolo
                    seen_roles = set()
                    for user_role in active_roles:
                        if user_role.role_id in seen_roles:
                            user_role.is_active = False
                            user_role.save()
                            self.stdout.write(self.style.SUCCESS(f'✓ Rimossa assegnazione duplicata per {user_role.role.name}'))
                        else:
                            seen_roles.add(user_role.role_id)
                    fixed_issues += 1

        # Statistiche finali
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS(f'Verifica completata'))
        self.stdout.write(f'Problemi trovati: {total_issues}')
        if options['fix']:
            self.stdout.write(f'Problemi risolti: {fixed_issues}')
        else:
            self.stdout.write('Usa --fix per correggere automaticamente i problemi')

        # Verifica generale del sistema
        self.stdout.write('\n--- Verifica sistema ---')
        self.stdout.write(f'Ruoli totali: {Role.objects.count()}')
        self.stdout.write(f'Permessi totali: {Permission.objects.count()}')
        self.stdout.write(f'Assegnazioni ruoli totali: {UserRole.objects.count()}')
        self.stdout.write(f'Assegnazioni attive: {UserRole.objects.filter(is_active=True).count()}') 