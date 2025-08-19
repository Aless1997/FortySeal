from django.test import TestCase
from django.contrib.auth.models import User
from Cripto1.models import Block, Transaction, UserProfile, BlockchainState
from django.utils import timezone
import hashlib
import json
import time

class BlockModelTest(TestCase):
    def setUp(self):
        self.block = Block.objects.create(
            index=1,
            timestamp=time.time(),
            proof="test_proof",
            previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
            hash="test_hash",
            nonce="test_nonce",
            merkle_root="test_merkle_root",
            difficulty=4.0
        )
    
    def test_block_creation(self):
        """Test che verifica la corretta creazione di un blocco"""
        self.assertEqual(self.block.index, 1)
        self.assertEqual(self.block.previous_hash, "0000000000000000000000000000000000000000000000000000000000000000")
        self.assertEqual(self.block.difficulty, 4.0)

class UserProfileModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        self.user_profile = UserProfile.objects.create(user=self.user)
        
    def test_user_profile_creation(self):
        """Test che verifica la corretta creazione di un profilo utente"""
        self.assertEqual(self.user_profile.user.username, 'testuser')
        self.assertEqual(self.user_profile.is_active, True)
        self.assertEqual(self.user_profile.login_attempts, 0)
    
    def test_key_generation(self):
        """Test che verifica la generazione delle chiavi"""
        self.user_profile.generate_key_pair(password=b'testpassword')
        self.assertIsNotNone(self.user_profile.public_key)
        self.assertIsNotNone(self.user_profile.private_key)
        self.assertIsNotNone(self.user_profile.user_key)

class TransactionModelTest(TestCase):
    def setUp(self):
        # Crea due utenti per le transazioni
        self.sender = User.objects.create_user(
            username='sender',
            email='sender@example.com',
            password='senderpassword'
        )
        self.sender_profile = UserProfile.objects.create(user=self.sender)
        self.sender_profile.generate_key_pair(password=b'testpassword')
        
        self.receiver = User.objects.create_user(
            username='receiver',
            email='receiver@example.com',
            password='receiverpassword'
        )
        self.receiver_profile = UserProfile.objects.create(user=self.receiver)
        self.receiver_profile.generate_key_pair(password=b'testpassword')
        
        # Crea una transazione di test
        self.transaction = Transaction.objects.create(
            type='text',
            sender=self.sender,
            receiver=self.receiver,
            sender_public_key=self.sender_profile.public_key,
            content='Test message',
            timestamp=time.time(),
            transaction_hash=hashlib.sha256('test'.encode()).hexdigest(),
            signature='test_signature',
            is_encrypted=False
        )
    
    def test_transaction_creation(self):
        """Test che verifica la corretta creazione di una transazione"""
        self.assertEqual(self.transaction.type, 'text')
        self.assertEqual(self.transaction.sender, self.sender)
        self.assertEqual(self.transaction.receiver, self.receiver)
        self.assertEqual(self.transaction.content, 'Test message')
        self.assertEqual(self.transaction.is_encrypted, False)