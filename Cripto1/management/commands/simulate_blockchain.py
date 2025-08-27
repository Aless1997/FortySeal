from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Q
from Cripto1.models import Transaction, Block, UserProfile
from faker import Faker
import random
import hashlib
import json
import time
from datetime import timedelta

class Command(BaseCommand):
    help = 'Simula transazioni e blocchi nel sistema blockchain'
    
    def __init__(self):
        super().__init__()
        self.fake = Faker('it_IT')
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--transactions',
            type=int,
            default=50,
            help='Numero di transazioni da simulare (default: 50)'
        )
        parser.add_argument(
            '--blocks',
            type=int,
            default=5,
            help='Numero di blocchi da creare (default: 5)'
        )
        parser.add_argument(
            '--users-min',
            type=int,
            default=10,
            help='Numero minimo di utenti richiesti (default: 10)'
        )
        parser.add_argument(
            '--realistic',
            action='store_true',
            help='Usa pattern di transazioni più realistici'
        )
        parser.add_argument(
            '--time-spread',
            type=int,
            default=24,
            help='Distribuisci le transazioni nelle ultime N ore (default: 24)'
        )
    
    def handle(self, *args, **options):
        num_transactions = options['transactions']
        num_blocks = options['blocks']
        users_min = options['users_min']
        realistic = options['realistic']
        time_spread = options['time_spread']
        
        self.stdout.write(self.style.SUCCESS('🚀 Avvio simulazione blockchain...'))
        
        # Verifica utenti disponibili
        users = list(User.objects.filter(is_active=True))
        if len(users) < users_min:
            self.stdout.write(
                self.style.ERROR(
                    f'❌ Servono almeno {users_min} utenti attivi. '
                    f'Trovati: {len(users)}. '
                    f'Usa prima: python manage.py create_test_users --count {users_min}'
                )
            )
            return
        
        self.stdout.write(f'👥 Utenti disponibili: {len(users)}')
        
        # Simula transazioni
        transactions_created = self.simulate_transactions(
            users, num_transactions, realistic, time_spread
        )
        
        # Crea blocchi
        blocks_created = self.create_blocks(num_blocks)
        
        # Statistiche finali
        self.print_statistics(transactions_created, blocks_created)
    
    def simulate_transactions(self, users, num_transactions, realistic, time_spread):
        """Simula transazioni tra utenti"""
        self.stdout.write('💸 Simulazione transazioni...')
        
        transactions_created = []
        transaction_types = ['text', 'file']  # Usa i tipi corretti dal modello
        
        # Pattern realistici se richiesto
        if realistic:
            # Alcuni utenti più attivi di altri
            active_users = random.sample(users, min(len(users) // 3, 10))
            weight_users = active_users + random.sample(users, len(users) // 2)
        else:
            weight_users = users
        
        for i in range(num_transactions):
            try:
                # Seleziona utenti
                sender = random.choice(weight_users)
                receiver = random.choice([u for u in users if u != sender])
                
                # Verifica/crea profili utente
                sender_profile, _ = UserProfile.objects.get_or_create(
                    user=sender,
                    defaults={
                        'user_key': self.fake.uuid4(),
                        'public_key': self.fake.sha256(),
                        'private_key': self.fake.sha256()
                    }
                )
                
                receiver_profile, _ = UserProfile.objects.get_or_create(
                    user=receiver,
                    defaults={
                        'user_key': self.fake.uuid4(),
                        'public_key': self.fake.sha256(),
                        'private_key': self.fake.sha256()
                    }
                )
                
                # Genera dati transazione
                transaction_type = random.choice(transaction_types)
                
                # Timestamp distribuito nel tempo
                if time_spread > 0:
                    hours_ago = random.uniform(0, time_spread)
                    timestamp_dt = timezone.now() - timedelta(hours=hours_ago)
                    timestamp = timestamp_dt.timestamp()
                else:
                    timestamp = time.time()
                
                # Genera contenuto basato sul tipo
                if transaction_type == 'text':
                    content = self.generate_text_content()
                else:
                    content = f"File condiviso: {self.fake.file_name()}"
                
                # Crea transazione con i campi corretti
                transaction = Transaction.objects.create(
                    type=transaction_type,  # Usa 'type' invece di 'transaction_type'
                    sender=sender,
                    receiver=receiver,
                    sender_public_key=sender_profile.public_key,
                    content=content,
                    timestamp=timestamp,
                    transaction_hash=self.generate_transaction_hash(
                        sender.username, receiver.username, content, timestamp
                    ),
                    is_encrypted=random.choice([True, False]),
                    is_shareable=random.choice([True, False]),
                    max_downloads=random.randint(1, 10) if transaction_type == 'file' else None,
                    current_downloads=0,
                    is_viewed=False
                )
                
                transactions_created.append(transaction)
                
                if (i + 1) % 10 == 0:
                    self.stdout.write(f'  📝 Transazioni create: {i + 1}/{num_transactions}')
                    
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(f'⚠️  Errore transazione {i + 1}: {str(e)}')
                )
                continue
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ Transazioni simulate: {len(transactions_created)}')
        )
        return transactions_created
    
    def create_blocks(self, num_blocks):
        """Crea blocchi con le transazioni non ancora incluse"""
        self.stdout.write('🧱 Creazione blocchi...')
        
        # Trova transazioni non ancora in blocchi
        unblocked_transactions = Transaction.objects.filter(
            block__isnull=True
        ).order_by('timestamp')
        
        if not unblocked_transactions.exists():
            self.stdout.write(
                self.style.WARNING('⚠️  Nessuna transazione disponibile per i blocchi')
            )
            return []
        
        blocks_created = []
        transactions_per_block = max(1, unblocked_transactions.count() // num_blocks)
        
        # Ottieni l'ultimo blocco per il previous_hash
        last_block = Block.objects.order_by('-index').first()
        previous_hash = last_block.hash if last_block else '0' * 64
        next_block_index = (last_block.index + 1) if last_block else 1
        
        for i in range(num_blocks):
            try:
                # Seleziona transazioni per questo blocco
                start_idx = i * transactions_per_block
                end_idx = start_idx + transactions_per_block
                
                if i == num_blocks - 1:  # Ultimo blocco prende tutte le rimanenti
                    block_transactions = list(unblocked_transactions[start_idx:])
                else:
                    block_transactions = list(unblocked_transactions[start_idx:end_idx])
                
                if not block_transactions:
                    break
                
                # Calcola merkle root
                merkle_root = self.calculate_merkle_root(block_transactions)
                
                # Genera proof of work
                nonce = str(random.randint(1000000, 9999999))
                proof = self.generate_proof_of_work(next_block_index + i, previous_hash, merkle_root)
                
                # Crea blocco
                block = Block.objects.create(
                    index=next_block_index + i,
                    timestamp=time.time(),
                    proof=proof,
                    previous_hash=previous_hash,
                    hash=self.generate_block_hash(
                        next_block_index + i, previous_hash, merkle_root, proof
                    ),
                    nonce=nonce,
                    merkle_root=merkle_root,
                    difficulty=4.0
                )
                
                # Associa transazioni al blocco
                for transaction in block_transactions:
                    transaction.block = block
                    transaction.save()
                
                blocks_created.append(block)
                previous_hash = block.hash
                
                self.stdout.write(
                    f'  🧱 Blocco #{block.index} creato con {len(block_transactions)} transazioni'
                )
                
            except Exception as e:
                self.stdout.write(
                    self.style.WARNING(f'⚠️  Errore blocco {i + 1}: {str(e)}')
                )
                continue
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ Blocchi creati: {len(blocks_created)}')
        )
        return blocks_created
    
    def generate_text_content(self):
        """Genera contenuti di testo realistici"""
        contents = [
            "Messaggio importante per il progetto",
            "Aggiornamento sullo stato dei lavori",
            "Condivisione informazioni riservate",
            "Documento contrattuale allegato",
            "Report mensile delle attività",
            "Comunicazione urgente",
            "Dati finanziari del trimestre",
            "Specifiche tecniche del prodotto",
            "Piano di sviluppo 2025",
            "Analisi di mercato dettagliata"
        ]
        return random.choice(contents)
    
    def generate_transaction_hash(self, sender, receiver, content, timestamp):
        """Genera hash per la transazione"""
        data = f"{sender}{receiver}{content}{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def calculate_merkle_root(self, transactions):
        """Calcola il Merkle Root delle transazioni"""
        if not transactions:
            return '0' * 64
        
        hashes = [t.transaction_hash for t in transactions]
        
        while len(hashes) > 1:
            new_hashes = []
            for i in range(0, len(hashes), 2):
                if i + 1 < len(hashes):
                    combined = hashes[i] + hashes[i + 1]
                else:
                    combined = hashes[i] + hashes[i]
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = new_hashes
        
        return hashes[0]
    
    def generate_proof_of_work(self, index, previous_hash, merkle_root):
        """Genera proof of work semplificato"""
        data = f"{index}{previous_hash}{merkle_root}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_block_hash(self, index, previous_hash, merkle_root, proof):
        """Genera hash per il blocco"""
        data = f"{index}{previous_hash}{merkle_root}{proof}{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def print_statistics(self, transactions, blocks):
        """Stampa statistiche della simulazione"""
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('📊 STATISTICHE SIMULAZIONE'))
        self.stdout.write('='*50)
        
        # Statistiche transazioni
        if transactions:
            transaction_types = {}
            encrypted_count = 0
            shareable_count = 0
            
            for t in transactions:
                transaction_types[t.type] = transaction_types.get(t.type, 0) + 1
                if t.is_encrypted:
                    encrypted_count += 1
                if t.is_shareable:
                    shareable_count += 1
            
            self.stdout.write(f'💸 Transazioni create: {len(transactions)}')
            self.stdout.write(f'🔐 Transazioni crittografate: {encrypted_count}')
            self.stdout.write(f'🔗 Transazioni condivisibili: {shareable_count}')
            self.stdout.write('📈 Tipi di transazione:')
            for t_type, count in transaction_types.items():
                self.stdout.write(f'   - {t_type}: {count}')
        
        # Statistiche blocchi
        if blocks:
            total_transactions_in_blocks = sum(
                Transaction.objects.filter(block=block).count() for block in blocks
            )
            avg_transactions_per_block = total_transactions_in_blocks / len(blocks)
            
            self.stdout.write(f'\n🧱 Blocchi creati: {len(blocks)}')
            self.stdout.write(f'📦 Transazioni nei blocchi: {total_transactions_in_blocks}')
            self.stdout.write(f'📊 Media transazioni/blocco: {avg_transactions_per_block:.1f}')
            
            # Mostra dettagli blocchi
            self.stdout.write('\n🔗 Dettagli blocchi:')
            for block in blocks:
                tx_count = Transaction.objects.filter(block=block).count()
                self.stdout.write(
                    f'   Blocco #{block.index}: {tx_count} transazioni, '
                    f'Hash: {block.hash[:16]}...'
                )
        
        # Statistiche utenti
        active_users = User.objects.filter(
            Q(sent_transactions__in=transactions) | 
            Q(received_transactions__in=transactions)
        ).distinct().count()
        
        self.stdout.write(f'\n👥 Utenti coinvolti: {active_users}')
        
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('✅ Simulazione completata con successo!'))
        self.stdout.write('='*50)