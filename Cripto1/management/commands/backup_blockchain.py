from django.core.management.base import BaseCommand
from django.core import serializers
from django.utils import timezone
from django.db.models import Q
from Cripto1.models import Block, Transaction, BlockchainState, UserProfile, SmartContract
import os
import json
import shutil
import zipfile
import threading
import atexit

class Command(BaseCommand):
    help = 'Esegue un backup completo della blockchain e dei dati correlati'

    def add_arguments(self, parser):
        parser.add_argument(
            '--output-dir',
            default='blockchain_backups',
            help='Directory dove salvare il backup'
        )
        parser.add_argument(
            '--include-files',
            action='store_true',
            help='Includi i file allegati alle transazioni nel backup'
        )
        # NUOVO: Aggiungi parametro per organizzazione
        parser.add_argument(
            '--organization-id',
            type=int,
            help='ID dell\'organizzazione per backup specifico (opzionale)'
        )

    def __init__(self):
        super().__init__()
        self.active_threads = []
        atexit.register(self.cleanup_threads)
    
    def cleanup_threads(self):
        """Assicura che tutti i thread siano terminati"""
        for thread in self.active_threads:
            if thread.is_alive():
                thread.join(timeout=5)

    def handle(self, *args, **options):
        output_dir = options['output_dir']
        include_files = options.get('include_files', False)
        organization_id = options.get('organization_id')  # NUOVO
        
        # Se è specificata un'organizzazione, filtra i dati
        if organization_id:
            try:
                from Cripto1.models import Organization
                organization = Organization.objects.get(id=organization_id)
                self.stdout.write(self.style.SUCCESS(f'Backup per organizzazione: {organization.name}'))
            except Organization.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Organizzazione con ID {organization_id} non trovata'))
                return
        else:
            organization = None
            self.stdout.write(self.style.SUCCESS('Backup completo del sistema'))
        
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = os.path.join(output_dir, f'backup_{timestamp}')
        
        # Crea la directory di backup se non esiste
        os.makedirs(backup_dir, exist_ok=True)
        
        self.stdout.write(self.style.SUCCESS(f'Avvio backup nella directory {backup_dir}'))
        
        # Backup dei blocchi
        if organization:
            blocks = Block.objects.filter(organization=organization).order_by('index')
        else:
            blocks = Block.objects.all().order_by('index')
        
        with open(os.path.join(backup_dir, 'blocks.json'), 'w', encoding='utf-8') as f:
            data = serializers.serialize('json', blocks)
            f.write(data)
        self.stdout.write(self.style.SUCCESS(f'Salvati {blocks.count()} blocchi'))
        
        # Backup delle transazioni  
        if organization:
            transactions = Transaction.objects.filter(
                Q(sender__userprofile__organization=organization) |
                Q(receiver__userprofile__organization=organization)
            ).order_by('id')
        else:
            transactions = Transaction.objects.all().order_by('id')
        with open(os.path.join(backup_dir, 'transactions.json'), 'w', encoding='utf-8') as f:
            data = serializers.serialize('json', transactions)
            f.write(data)
        self.stdout.write(self.style.SUCCESS(f'Salvate {transactions.count()} transazioni'))
        
        # Backup dello stato della blockchain
        blockchain_state = BlockchainState.objects.all()
        with open(os.path.join(backup_dir, 'blockchain_state.json'), 'w', encoding='utf-8') as f:
            data = serializers.serialize('json', blockchain_state)
            f.write(data)
        self.stdout.write(self.style.SUCCESS('Salvato stato della blockchain'))
        
        # Backup degli smart contract
        smart_contracts = SmartContract.objects.all()
        with open(os.path.join(backup_dir, 'smart_contracts.json'), 'w', encoding='utf-8') as f:
            data = serializers.serialize('json', smart_contracts)
            f.write(data)
        self.stdout.write(self.style.SUCCESS(f'Salvati {smart_contracts.count()} smart contract'))
        
        # Backup dei profili utente (solo dati essenziali per la blockchain)
        if organization:
            user_profiles = UserProfile.objects.filter(organization=organization)
        else:
            user_profiles = UserProfile.objects.all()
        with open(os.path.join(backup_dir, 'user_profiles.json'), 'w', encoding='utf-8') as f:
            data = serializers.serialize('json', user_profiles, fields=[
                'user', 'user_key', 'public_key', 'balance'
            ])
            f.write(data)
        self.stdout.write(self.style.SUCCESS(f'Salvati {user_profiles.count()} profili utente'))
        
        # Backup dei file allegati alle transazioni
        if include_files:
            files_dir = os.path.join(backup_dir, 'transaction_files')
            os.makedirs(files_dir, exist_ok=True)
            
            if organization:
                file_transactions = Transaction.objects.filter(
                    Q(sender__userprofile__organization=organization) |
                    Q(receiver__userprofile__organization=organization),
                    file__isnull=False
                ).exclude(file='')
            else:
                file_transactions = Transaction.objects.filter(file__isnull=False).exclude(file='')
            for tx in file_transactions:
                if tx.file and os.path.exists(tx.file.path):
                    file_name = os.path.basename(tx.file.name)
                    dest_path = os.path.join(files_dir, f'{tx.id}_{file_name}')
                    shutil.copy2(tx.file.path, dest_path)
            
            self.stdout.write(self.style.SUCCESS(f'Salvati file allegati alle transazioni'))
        
        # Crea un file di metadati con informazioni sul backup
        metadata = {
            'timestamp': timestamp,
            'blocks_count': blocks.count(),
            'transactions_count': transactions.count(),
            'users_count': user_profiles.count(),
            'smart_contracts_count': smart_contracts.count(),
            'include_files': include_files,
            'organization_id': organization_id if organization else None,
            'organization_name': organization.name if organization else 'Sistema completo',
            'version': '1.0'
        }
        
        with open(os.path.join(backup_dir, 'metadata.json'), 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=4)
        
        # Sostituisci le righe 102-107 con questo codice:
        
        # Crea un archivio ZIP del backup
        zip_filename = os.path.join(output_dir, f'blockchain_backup_{timestamp}.zip')
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(backup_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Archivia i file direttamente nella radice del ZIP, non in sottodirectory
                    zipf.write(file_path, os.path.basename(file_path))
        
        self.stdout.write(self.style.SUCCESS(f'Backup completato e salvato in {zip_filename}'))
        
        # Opzionalmente, rimuovi la directory temporanea dopo la creazione del ZIP
        shutil.rmtree(backup_dir)
        self.stdout.write(self.style.SUCCESS('Directory temporanea rimossa'))