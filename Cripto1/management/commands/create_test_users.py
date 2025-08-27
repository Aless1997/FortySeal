from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from Cripto1.models import UserProfile
from faker import Faker
import random
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class Command(BaseCommand):
    help = 'Crea utenti di test casuali per stress testing'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=10,
            help='Numero di utenti da creare (default: 10)'
        )
        parser.add_argument(
            '--prefix',
            type=str,
            default='testuser',
            help='Prefisso per gli username (default: testuser)'
        )
        parser.add_argument(
            '--delete-existing',
            action='store_true',
            help='Elimina gli utenti di test esistenti prima di crearne di nuovi'
        )

    def handle(self, *args, **options):
        fake = Faker('it_IT')  # Usa locale italiano
        count = options['count']
        prefix = options['prefix']
        
        # Elimina utenti esistenti se richiesto
        if options['delete_existing']:
            existing_users = User.objects.filter(username__startswith=prefix)
            deleted_count = existing_users.count()
            existing_users.delete()
            self.stdout.write(
                self.style.WARNING(f'Eliminati {deleted_count} utenti esistenti con prefisso "{prefix}"')
            )

        self.stdout.write(f'Creazione di {count} utenti di test...')
        
        created_users = []
        
        for i in range(count):
            try:
                # Genera dati casuali
                username = f"{prefix}_{i+1:04d}"
                email = fake.email()
                first_name = fake.first_name()
                last_name = fake.last_name()
                password = 'testpass123'  # Password fissa per facilità di test
                
                # Crea utente Django
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=password
                )
                
                # Genera chiavi RSA
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                
                public_key = private_key.public_key()
                
                # Serializza le chiavi
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                # Genera user_key (hash della chiave pubblica)
                user_key = hashlib.sha256(public_pem.encode()).hexdigest()[:32]
                
                # Crea UserProfile
                profile = UserProfile.objects.create(
                    user=user,
                    user_key=user_key,
                    public_key=public_pem,
                    private_key=private_pem,
                    balance=random.uniform(0, 1000),  # Balance casuale
                    department=fake.job(),
                    position=fake.job(),
                    phone=fake.phone_number(),
                    emergency_contact=f"{fake.name()} - {fake.phone_number()}",
                    notes=fake.text(max_nb_chars=200),
                    storage_quota_bytes=random.choice([1073741824, 5368709120, 10737418240]),  # 1GB, 5GB, 10GB
                    storage_used_bytes=random.randint(0, 1073741824),  # Uso casuale fino a 1GB
                    two_factor_enabled=random.choice([True, False]),
                    is_active=random.choice([True, True, True, False])  # 75% attivi
                )
                
                created_users.append(user)
                
                if (i + 1) % 10 == 0:
                    self.stdout.write(f'Creati {i + 1}/{count} utenti...')
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Errore nella creazione dell\'utente {i+1}: {str(e)}')
                )
                continue
        
        self.stdout.write(
            self.style.SUCCESS(f'Creati con successo {len(created_users)} utenti di test!')
        )
        
        # Mostra statistiche
        self.stdout.write('\n=== STATISTICHE ===')
        self.stdout.write(f'Username: {prefix}_0001 a {prefix}_{count:04d}')
        self.stdout.write(f'Password: testpass123 (uguale per tutti)')
        self.stdout.write(f'Email: casuali generate con Faker')
        self.stdout.write(f'Chiavi RSA: generate automaticamente')
        self.stdout.write(f'Profili: creati con dati casuali')
        
        # Mostra alcuni esempi
        if created_users:
            self.stdout.write('\n=== ESEMPI DI UTENTI CREATI ===')
            for user in created_users[:3]:
                profile = user.userprofile
                self.stdout.write(
                    f'• {user.username} ({user.first_name} {user.last_name}) - '
                    f'{user.email} - Balance: {profile.balance:.2f} - '
                    f'Storage: {profile.get_storage_used_gb():.2f}GB/{profile.get_storage_quota_gb():.0f}GB'
                )