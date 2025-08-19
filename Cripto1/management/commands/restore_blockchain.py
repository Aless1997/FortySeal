from django.core.management.base import BaseCommand
from django.core import serializers
from django.db import transaction
from django.contrib.auth.models import User
from django.conf import settings  # Aggiunta importazione mancante
from Cripto1.models import Block, Transaction, BlockchainState, UserProfile, SmartContract
import os
import json
import zipfile
import tempfile
import shutil
import traceback  # Aggiunta importazione mancante
import datetime

class Command(BaseCommand):
    help = 'Ripristina un backup della blockchain'

    def add_arguments(self, parser):
        parser.add_argument(
            'backup_file',
            help='File ZIP di backup da ripristinare'
        )
        parser.add_argument(
            '--skip-confirmation',
            action='store_true',
            help='Salta la conferma prima del ripristino'
        )
        # Aggiunta opzione per creare backup automatico prima del ripristino
        parser.add_argument(
            '--auto-backup',
            action='store_true',
            help='Crea un backup automatico prima del ripristino'
        )

    def handle(self, *args, **options):
        backup_file = options['backup_file']
        skip_confirmation = options['skip_confirmation']
        auto_backup = options.get('auto_backup', True)  # Default a True per sicurezza
        
        if not os.path.exists(backup_file):
            self.stdout.write(self.style.ERROR(f'Il file di backup {backup_file} non esiste'))
            return
        
        # Crea un backup automatico prima del ripristino
        if auto_backup:
            try:
                self.stdout.write(self.style.WARNING('Creazione backup di sicurezza prima del ripristino...'))
                from django.core.management import call_command
                call_command('backup_blockchain', include_files=True)
                self.stdout.write(self.style.SUCCESS('Backup di sicurezza creato con successo'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Errore durante la creazione del backup di sicurezza: {str(e)}'))
                if not skip_confirmation:
                    confirm = input('Continuare comunque con il ripristino? (s/n): ')
                    if confirm.lower() != 's':
                        self.stdout.write(self.style.WARNING('Ripristino annullato dall\'utente'))
                        return
        
        # Estrai il backup in una directory temporanea
        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(backup_file, 'r') as zipf:
                zipf.extractall(temp_dir)
            
            # Leggi i metadati del backup
            metadata_files = [f for f in os.listdir(temp_dir) if f.endswith('metadata.json')]
            if not metadata_files:
                # Cerca il file di metadati in modo ricorsivo
                def find_metadata_file(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            if file == 'metadata.json':
                                return os.path.join(root, file)
                    return None
                
                metadata_file = find_metadata_file(temp_dir)
                if not metadata_file:
                    self.stdout.write(self.style.ERROR('File di metadati non trovato nel backup'))
                    return
                
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
            else:
                metadata_file = os.path.join(temp_dir, metadata_files[0])
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
            
            self.stdout.write(self.style.SUCCESS(f"Informazioni sul backup:"))
            self.stdout.write(f"Data: {metadata.get('timestamp')}")
            self.stdout.write(f"Blocchi: {metadata.get('blocks_count')}")
            self.stdout.write(f"Transazioni: {metadata.get('transactions_count')}")
            self.stdout.write(f"Utenti: {metadata.get('users_count')}")
            self.stdout.write(f"Smart Contract: {metadata.get('smart_contracts_count')}")
            self.stdout.write(f"Include file: {metadata.get('include_files')}")
            self.stdout.write(f"Versione: {metadata.get('version')}")
            
            if not skip_confirmation:
                confirm = input('\nATTENZIONE: Il ripristino sovrascriverà tutti i dati attuali della blockchain. Continuare? (s/n): ')
                if confirm.lower() != 's':
                    self.stdout.write(self.style.WARNING('Ripristino annullato dall\'utente'))
                    return
            
            # Trova i file di backup
            subdirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
            if subdirs:
                backup_dir = os.path.join(temp_dir, subdirs[0])
            else:
                # Se non ci sono sottodirectory, usa la directory temporanea stessa
                backup_dir = temp_dir
            
            # VERIFICA PRELIMINARE: controlla che tutti i file necessari esistano
            required_files = ['blocks.json', 'transactions.json', 'blockchain_state.json', 'smart_contracts.json']
            missing_files = []
            for file_name in required_files:
                file_path = os.path.join(backup_dir, file_name)
                if not os.path.exists(file_path):
                    missing_files.append(file_name)
            
            if missing_files:
                self.stdout.write(self.style.ERROR(f'File mancanti nel backup: {", ".join(missing_files)}'))
                self.stdout.write(self.style.ERROR('Ripristino annullato per evitare perdita di dati'))
                return
            
            # Verifica che i file siano deserializzabili prima di eliminare i dati esistenti
            try:
                # Verifica blocks.json
                with open(os.path.join(backup_dir, 'blocks.json'), 'r', encoding='utf-8') as f:
                    blocks_data = f.read()
                    blocks_count = 0
                    for obj in serializers.deserialize('json', blocks_data):
                        blocks_count += 1
                self.stdout.write(self.style.SUCCESS(f'Verifica preliminare: {blocks_count} blocchi validi'))
                
                # Verifica transactions.json
                with open(os.path.join(backup_dir, 'transactions.json'), 'r', encoding='utf-8') as f:
                    transactions_data = f.read()
                    tx_count = 0
                    for obj in serializers.deserialize('json', transactions_data):
                        tx_count += 1
                self.stdout.write(self.style.SUCCESS(f'Verifica preliminare: {tx_count} transazioni valide'))
                
                # Verifica blockchain_state.json
                with open(os.path.join(backup_dir, 'blockchain_state.json'), 'r', encoding='utf-8') as f:
                    blockchain_state_data = f.read()
                    state_count = 0
                    for obj in serializers.deserialize('json', blockchain_state_data):
                        state_count += 1
                self.stdout.write(self.style.SUCCESS(f'Verifica preliminare: {state_count} stati blockchain validi'))
                
                # Verifica smart_contracts.json
                with open(os.path.join(backup_dir, 'smart_contracts.json'), 'r', encoding='utf-8') as f:
                    smart_contracts_data = f.read()
                    sc_count = 0
                    for obj in serializers.deserialize('json', smart_contracts_data):
                        sc_count += 1
                self.stdout.write(self.style.SUCCESS(f'Verifica preliminare: {sc_count} smart contract validi'))
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Errore durante la verifica preliminare: {str(e)}'))
                self.stdout.write(self.style.ERROR('Ripristino annullato per evitare perdita di dati'))
                return
            
            # Esegui il ripristino in una transazione atomica
            with transaction.atomic():
                try:
                    # SOLO ORA eliminiamo i dati esistenti, dopo aver verificato che il backup è valido
                    self.stdout.write(self.style.WARNING('Eliminazione dei dati esistenti...'))
                    tx_count = Transaction.objects.count()
                    self.stdout.write(f"Eliminazione di {tx_count} transazioni...")
                    Transaction.objects.all().delete()
                    
                    block_count = Block.objects.count()
                    self.stdout.write(f"Eliminazione di {block_count} blocchi...")
                    Block.objects.all().delete()
                    
                    state_count = BlockchainState.objects.count()
                    self.stdout.write(f"Eliminazione di {state_count} stati della blockchain...")
                    BlockchainState.objects.all().delete()
                    
                    sc_count = SmartContract.objects.count()
                    self.stdout.write(f"Eliminazione di {sc_count} smart contract...")
                    SmartContract.objects.all().delete()
                    
                    # Ripristina i blocchi
                    blocks_file = os.path.join(backup_dir, 'blocks.json')
                    if os.path.exists(blocks_file):
                        self.stdout.write(f"Ripristino blocchi da {blocks_file}...")
                        with open(blocks_file, 'r', encoding='utf-8') as f:
                            blocks_data = f.read()
                            blocks_count = 0
                            for obj in serializers.deserialize('json', blocks_data):
                                try:
                                    obj.save()
                                    blocks_count += 1
                                except Exception as e:
                                    self.stdout.write(self.style.ERROR(f"Errore durante il ripristino del blocco: {str(e)}\nDati: {obj.object.__dict__}"))
                        self.stdout.write(self.style.SUCCESS(f'Blocchi ripristinati: {blocks_count}'))
                    
                    # Ripristina le transazioni
                    transactions_file = os.path.join(backup_dir, 'transactions.json')
                    if os.path.exists(transactions_file):
                        with open(transactions_file, 'r', encoding='utf-8') as f:
                            transactions_data = f.read()
                            tx_count = 0
                            for obj in serializers.deserialize('json', transactions_data):
                                try:
                                    obj.save()
                                    tx_count += 1
                                except Exception as e:
                                    self.stdout.write(self.style.ERROR(f"Errore durante il ripristino della transazione: {str(e)}"))
                                    raise  # Rilancia l'eccezione per attivare il rollback
                        self.stdout.write(self.style.SUCCESS(f'Transazioni ripristinate: {tx_count}'))
                    
                    # Ripristina lo stato della blockchain
                    blockchain_state_file = os.path.join(backup_dir, 'blockchain_state.json')
                    if os.path.exists(blockchain_state_file):
                        with open(blockchain_state_file, 'r', encoding='utf-8') as f:
                            blockchain_state_data = f.read()
                            state_count = 0
                            for obj in serializers.deserialize('json', blockchain_state_data):
                                try:
                                    obj.save()
                                    state_count += 1
                                except Exception as e:
                                    self.stdout.write(self.style.ERROR(f"Errore durante il ripristino dello stato: {str(e)}"))
                                    raise  # Rilancia l'eccezione per attivare il rollback
                        self.stdout.write(self.style.SUCCESS(f'Stati blockchain ripristinati: {state_count}'))
                    
                    # Ripristina gli smart contract
                    smart_contracts_file = os.path.join(backup_dir, 'smart_contracts.json')
                    if os.path.exists(smart_contracts_file):
                        with open(smart_contracts_file, 'r', encoding='utf-8') as f:
                            smart_contracts_data = f.read()
                            sc_count = 0
                            for obj in serializers.deserialize('json', smart_contracts_data):
                                try:
                                    obj.save()
                                    sc_count += 1
                                except Exception as e:
                                    self.stdout.write(self.style.ERROR(f"Errore durante il ripristino dello smart contract: {str(e)}"))
                                    raise  # Rilancia l'eccezione per attivare il rollback
                        self.stdout.write(self.style.SUCCESS(f'Smart contract ripristinati: {sc_count}'))
                    
                    # Aggiorna i saldi degli utenti
                    user_profiles_file = os.path.join(backup_dir, 'user_profiles.json')
                    if os.path.exists(user_profiles_file):
                        with open(user_profiles_file, 'r', encoding='utf-8') as f:
                            user_profiles_data = f.read()
                            profile_count = 0
                            for obj in serializers.deserialize('json', user_profiles_data):
                                try:
                                    # Aggiorna solo i campi specifici invece di sovrascrivere l'intero profilo
                                    profile = UserProfile.objects.get(user=obj.object.user)
                                    profile.balance = obj.object.balance
                                    profile.save(update_fields=['balance'])
                                    profile_count += 1
                                except UserProfile.DoesNotExist:
                                    self.stdout.write(self.style.WARNING(f"Profilo utente non trovato per l'utente {obj.object.user}"))
                                except Exception as e:
                                    self.stdout.write(self.style.ERROR(f"Errore durante l'aggiornamento del profilo: {str(e)}"))
                                    raise  # Rilancia l'eccezione per attivare il rollback
                        self.stdout.write(self.style.SUCCESS(f'Saldi utenti aggiornati: {profile_count}'))
                    
                    # Ripristina i file delle transazioni se presenti nel backup
                    files_dir = os.path.join(backup_dir, 'transaction_files')
                    if os.path.exists(files_dir) and metadata.get('include_files'):
                        media_root = settings.MEDIA_ROOT
                        transaction_files_dir = os.path.join(media_root, 'transaction_files')
                        os.makedirs(transaction_files_dir, exist_ok=True)
                        
                        file_count = 0
                        for file_name in os.listdir(files_dir):
                            try:
                                src_path = os.path.join(files_dir, file_name)
                                # Estrai l'ID della transazione dal nome del file
                                parts = file_name.split('_')
                                if len(parts) < 2:
                                    self.stdout.write(self.style.WARNING(f"Nome file non valido: {file_name}"))
                                    continue
                                    
                                tx_id = parts[0]
                                try:
                                    tx = Transaction.objects.get(id=tx_id)
                                    # Estrai il nome originale del file
                                    original_name = '_'.join(parts[1:])
                                    dest_path = os.path.join(transaction_files_dir, original_name)
                                    shutil.copy2(src_path, dest_path)
                                    # Aggiorna il percorso del file nella transazione
                                    tx.file = f'transaction_files/{original_name}'
                                    tx.save(update_fields=['file'])
                                    file_count += 1
                                except Transaction.DoesNotExist:
                                    self.stdout.write(self.style.WARNING(f'Transazione {tx_id} non trovata per il file {file_name}'))
                            except Exception as e:
                                self.stdout.write(self.style.ERROR(f"Errore durante il ripristino del file {file_name}: {str(e)}"))
                                # Non interrompiamo il ripristino per errori nei file
                        
                        self.stdout.write(self.style.SUCCESS(f'File delle transazioni ripristinati: {file_count}'))
                
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Errore durante il ripristino: {str(e)}\n{traceback.format_exc()}"))
                    # La transazione verrà automaticamente annullata grazie al context manager transaction.atomic()
                    raise  # Rilancia l'eccezione per assicurarsi che la transazione venga annullata
            
            self.stdout.write(self.style.SUCCESS('Ripristino completato con successo!'))
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Errore generale durante il ripristino: {str(e)}\n{traceback.format_exc()}"))
        finally:
            # Pulisci la directory temporanea
            try:
                shutil.rmtree(temp_dir)
                self.stdout.write(self.style.SUCCESS('Directory temporanea rimossa'))
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"Errore durante la rimozione della directory temporanea: {str(e)}"))