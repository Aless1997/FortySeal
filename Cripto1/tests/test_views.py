from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from Cripto1.models import UserProfile, Block, Transaction, Role, Permission, UserRole
import json
import time

class ViewsTestCase(TestCase):
    def setUp(self):
        # Crea un client per le richieste
        self.client = Client()
        
        # Crea un utente di test
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        self.user_profile = UserProfile.objects.create(user=self.user)
        self.user_profile.generate_key_pair(password=b'testpassword')
        
        # Crea un utente admin
        self.admin_user = User.objects.create_user(
            username='adminuser',
            email='admin@example.com',
            password='adminpassword',
            is_staff=True,
            is_superuser=True
        )
        self.admin_profile = UserProfile.objects.create(user=self.admin_user)
        
        # Crea ruoli e permessi di base
        self.permission = Permission.objects.create(
            name='Test Permission',
            codename='test_permission',
            description='Test permission description',
            category='TEST'
        )
        
        self.role = Role.objects.create(
            name='Test Role',
            description='Test role description',
            is_system_role=False
        )
        self.role.permissions.add(self.permission)
        
        # Assegna il ruolo all'utente
        UserRole.objects.create(
            user=self.user,
            role=self.role,
            assigned_by=self.admin_user
        )
    
    def test_homepage(self):
        """Test che verifica che la homepage sia accessibile"""
        response = self.client.get(reverse('Cripto1:home'))
        self.assertEqual(response.status_code, 200)
    
    def test_login_view(self):
        """Test che verifica il funzionamento della vista di login"""
        # Test login con credenziali errate
        response = self.client.post(reverse('Cripto1:login'), {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['user'].is_authenticated)
        
        # Test login con credenziali corrette
        response = self.client.post(reverse('Cripto1:login'), {
            'username': 'testuser',
            'password': 'testpassword'
        }, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['user'].is_authenticated)
    
    def test_dashboard_access(self):
        """Test che verifica l'accesso alla dashboard"""
        # Senza login, dovrebbe reindirizzare
        response = self.client.get(reverse('Cripto1:dashboard'))
        self.assertNotEqual(response.status_code, 200)
        
        # Con login, dovrebbe essere accessibile
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(reverse('Cripto1:dashboard'))
        self.assertEqual(response.status_code, 200)