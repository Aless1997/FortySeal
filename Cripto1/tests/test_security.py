from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from Cripto1.models import UserProfile
import re

class SecurityTestCase(TestCase):
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
    
    def test_csrf_protection(self):
        """Test che verifica la protezione CSRF"""
        # Login per ottenere una sessione
        self.client.login(username='testuser', password='testpassword')
        
        # Usa una vista diversa che non sia csrf_exempt, ad esempio dashboard
        response = self.client.get(reverse('Cripto1:dashboard'))
        csrf_token = response.context.get('csrf_token')
        
        # Crea un nuovo client con enforce_csrf_checks=True
        client_with_csrf = Client(enforce_csrf_checks=True)
        
        # Effettua il login con il nuovo client
        client_with_csrf.login(username='testuser', password='testpassword')
        
        # Prova a inviare una richiesta POST senza token CSRF a una vista protetta
        # Ad esempio, edit_profile o un'altra vista che accetta POST e non è csrf_exempt
        response = client_with_csrf.post(reverse('Cripto1:edit_profile'), {
            'field1': 'value1',
            'field2': 'value2'
        })
        
        # Dovrebbe fallire con 403 Forbidden
        self.assertEqual(response.status_code, 403)
    
    def test_login_attempts_limit(self):
        """Test che verifica il limite di tentativi di login"""
        # Configura il client per non sollevare eccezioni
        self.client = Client(raise_request_exception=False)
        
        # Prova a fare login con password errata più volte
        for i in range(6):  # Assumendo che il limite sia 5
            try:
                response = self.client.post(reverse('Cripto1:login'), {
                    'username': 'testuser',
                    'password': 'wrongpassword'
                })
            except:
                # Ignora eventuali eccezioni causate dai messaggi
                pass
        
        # Verifica che l'account sia bloccato
        user_profile = UserProfile.objects.get(user=self.user)
        self.assertTrue(user_profile.is_locked())
        
        # Verifica che non sia possibile accedere con le credenziali corrette
        # Usa il metodo post invece di client.login() per passare attraverso il middleware
        response = self.client.post(reverse('Cripto1:login'), {
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        # Verifica che l'utente non sia autenticato dopo il tentativo di login
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        
        # Verifica che non si possa accedere alla dashboard
        response = self.client.get(reverse('Cripto1:dashboard'))
        self.assertNotEqual(response.status_code, 200)  # Non dovrebbe essere accessibile
        
        # Prova a fare login con password corretta
        response = self.client.post(reverse('Cripto1:login'), {
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        # Dovrebbe essere ancora bloccato
        self.assertFalse(response.wsgi_request.user.is_authenticated)
    
    def test_password_strength(self):
        """Test che verifica la robustezza delle password durante la registrazione"""
        # Pulisci il database prima di questo test per evitare conflitti
        User.objects.all().delete()
        UserProfile.objects.all().delete()
        
        # Prova a registrare un utente con password debole (solo numeri, meno di 8 caratteri)
        response = self.client.post(reverse('Cripto1:register'), {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': '123456',
            'private_key_password': '123456'
        })
        
        # Verifica che la registrazione fallisca
        self.assertEqual(User.objects.filter(username='newuser').count(), 0)