import uuid
from django.core.management.base import BaseCommand
from django.db import transaction
from Cripto1.models import Organization, UserProfile, User
from django.contrib.auth.models import User as AuthUser

class Command(BaseCommand):
    help = 'Inizializza le organizzazioni multi-tenant del sistema'

    def add_arguments(self, parser):
        parser.add_argument(
            '--create-default',
            action='store_true',
            help='Crea un\'organizzazione di default',
        )

    def handle(self, *args, **options):
        self.stdout.write('=== SETUP ORGANIZZAZIONI MULTI-TENANT ===')
        
        if options['create_default']:
            self.create_default_organization()
        
        self.stdout.write('\n✅ Setup organizzazioni completato!')
    
    def create_default_organization(self):
        """Crea l'organizzazione di default"""
        self.stdout.write('\n1. Creazione organizzazione di default...')
        
        try:
            with transaction.atomic():
                # Crea organizzazione di default
                default_org, created = Organization.objects.get_or_create(
                    slug='default',
                    defaults={
                        'name': 'FortySeal Default',
                        'description': 'Organizzazione di default per FortySeal',
                        'domain': '',
                        'registration_code': f"ORG_{uuid.uuid4().hex[:8].upper()}",
                        'max_users': 1000,
                        'max_storage_gb': 1000,
                        'features_enabled': {
                            'blockchain': True,
                            '2fa': True,
                            'audit_logs': True,
                            'file_sharing': True,
                            'smart_contracts': True,
                        },
                        'require_2fa': True,
                        'password_policy': {
                            'min_length': 8,
                            'require_uppercase': True,
                            'require_lowercase': True,
                            'require_numbers': True,
                            'require_special': True,
                            'max_age_days': 90,
                        },
                        'session_timeout_hours': 24,
                    }
                )
                
                if created:
                    self.stdout.write(f'  ✅ Organizzazione "{default_org.name}" creata')
                else:
                    self.stdout.write(f'  ℹ️  Organizzazione "{default_org.name}" già esistente')
                
                # Assegna tutti gli utenti esistenti all'organizzazione di default
                self.stdout.write('\n2. Assegnazione utenti esistenti...')
                
                unassigned_profiles = UserProfile.objects.filter(organization__isnull=True)
                count = unassigned_profiles.count()
                
                if count > 0:
                    unassigned_profiles.update(organization=default_org)
                    self.stdout.write(f'  ✅ {count} utenti assegnati all\'organizzazione di default')
                else:
                    self.stdout.write('  ℹ️  Nessun utente da assegnare')
                
                # Crea organizzazioni di esempio
                self.create_sample_organizations()
                
        except Exception as e:
            self.stdout.write(f'  ❌ Errore: {str(e)}')
            raise
    
    def create_sample_organizations(self):
        """Crea organizzazioni di esempio per test"""
        self.stdout.write('\n3. Creazione organizzazioni di esempio...')
        
        sample_orgs = [
            {
                'name': 'TechCorp Solutions',
                'slug': 'techcorp',
                'description': 'Azienda tecnologica innovativa',
                'domain': 'techcorp.fortyseal.com',
                'max_users': 500,
                'max_storage_gb': 500,
                'primary_color': '#28a745',
                'secondary_color': '#17a2b8',
            },
            {
                'name': 'FinanceBank Ltd',
                'slug': 'financebank',
                'description': 'Banca di investimento internazionale',
                'domain': 'financebank.fortyseal.com',
                'max_users': 200,
                'max_storage_gb': 1000,
                'primary_color': '#dc3545',
                'secondary_color': '#fd7e14',
            },
            {
                'name': 'Healthcare Systems',
                'slug': 'healthcare',
                'description': 'Sistema sanitario regionale',
                'domain': 'healthcare.fortyseal.com',
                'max_users': 1000,
                'max_storage_gb': 2000,
                'primary_color': '#6f42c1',
                'secondary_color': '#e83e8c',
            }
        ]
        
        for org_data in sample_orgs:
            try:
                org, created = Organization.objects.get_or_create(
                    slug=org_data['slug'],
                    defaults={
                        **org_data,
                        'registration_code': f"ORG_{uuid.uuid4().hex[:8].upper()}",
                        'features_enabled': {
                            'blockchain': True,
                            '2fa': True,
                            'audit_logs': True,
                            'file_sharing': True,
                            'smart_contracts': False,
                        },
                        'require_2fa': True,
                        'password_policy': {
                            'min_length': 10,
                            'require_uppercase': True,
                            'require_lowercase': True,
                            'require_numbers': True,
                            'require_special': True,
                            'max_age_days': 60,
                        },
                        'session_timeout_hours': 8,
                    }
                )
                
                if created:
                    self.stdout.write(f'  ✅ Organizzazione "{org.name}" creata')
                else:
                    self.stdout.write(f'  ℹ️  Organizzazione "{org.name}" già esistente')
                    
            except Exception as e:
                self.stdout.write(f'  ❌ Errore creazione {org_data["name"]}: {str(e)}')
        
        self.stdout.write('\n4. Statistiche finali...')
        
        total_orgs = Organization.objects.count()
        total_users = UserProfile.objects.count()
        active_orgs = Organization.objects.filter(is_active=True).count()
        
        self.stdout.write(f'  📊 Organizzazioni totali: {total_orgs}')
        self.stdout.write(f'  📊 Organizzazioni attive: {active_orgs}')
        self.stdout.write(f'  📊 Utenti totali: {total_users}')
        
        # Mostra dettagli per organizzazione
        for org in Organization.objects.all():
            user_count = org.user_profiles.count()
            self.stdout.write(f'  🏢 {org.name}: {user_count} utenti')