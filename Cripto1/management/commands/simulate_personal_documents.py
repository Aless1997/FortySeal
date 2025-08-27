import os
import random
from datetime import datetime, timedelta
from faker import Faker
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db import transaction
from django.db import models
from Cripto1.models import PersonalDocument, CreatedDocument

class Command(BaseCommand):
    help = 'Genera documenti personali e creati random per testare il sistema'
    
    def __init__(self):
        super().__init__()
        self.fake = Faker('it_IT')
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--personal',
            type=int,
            default=30,
            help='Numero di documenti personali da creare (default: 30)'
        )
        parser.add_argument(
            '--created',
            type=int,
            default=20,
            help='Numero di documenti creati da creare (default: 20)'
        )
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Elimina tutti i documenti esistenti prima di creare i nuovi'
        )
        parser.add_argument(
            '--only-personal',
            action='store_true',
            help='Crea solo documenti personali'
        )
        parser.add_argument(
            '--only-created',
            action='store_true',
            help='Crea solo documenti creati'
        )
    
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=== SIMULATORE DOCUMENTI PERSONALI ==='))
        
        # Cleanup se richiesto
        if options['cleanup']:
            self.cleanup_documents()
        
        # Verifica utenti
        users = list(User.objects.all())
        if not users:
            self.stdout.write(self.style.ERROR('Nessun utente trovato. Crea prima alcuni utenti.'))
            return
        
        self.stdout.write(f'Trovati {len(users)} utenti nel sistema.')
        
        # Genera documenti
        if options['only_personal']:
            self.generate_personal_documents(options['personal'])
        elif options['only_created']:
            self.generate_created_documents(options['created'])
        else:
            self.generate_personal_documents(options['personal'])
            self.generate_created_documents(options['created'])
        
        # Statistiche finali
        self.show_final_stats()
    
    def cleanup_documents(self):
        """Pulisce tutti i documenti esistenti"""
        personal_count = PersonalDocument.objects.count()
        created_count = CreatedDocument.objects.count()
        
        if personal_count > 0 or created_count > 0:
            self.stdout.write(
                f'Eliminando {personal_count} documenti personali e {created_count} documenti creati...'
            )
            PersonalDocument.objects.all().delete()
            CreatedDocument.objects.all().delete()
            self.stdout.write(self.style.SUCCESS('Documenti eliminati.'))
    
    def create_fake_file_content(self, file_type):
        """Crea contenuto fake per diversi tipi di file"""
        if file_type == 'txt':
            return self.fake.text(max_nb_chars=2000)
        elif file_type == 'csv':
            content = "Nome,Cognome,Email,Telefono\n"
            for _ in range(random.randint(5, 20)):
                content += f"{self.fake.first_name()},{self.fake.last_name()},{self.fake.email()},{self.fake.phone_number()}\n"
            return content
        elif file_type == 'doc':
            return f"""DOCUMENTO UFFICIALE
            
Titolo: {self.fake.catch_phrase()}
Data: {self.fake.date()}
Autore: {self.fake.name()}

{self.fake.text(max_nb_chars=1500)}

Firma: {self.fake.name()}
            """
        else:
            return self.fake.text(max_nb_chars=1000)
    
    def generate_personal_documents(self, num_documents):
        """Genera documenti personali random"""
        
        # Tipi di file supportati
        file_extensions = ['pdf', 'csv', 'xlsx', 'xls', 'doc', 'docx', 'txt']
        
        # Categorie di documenti
        document_categories = [
            'Contratto di Lavoro', 'Fattura', 'Ricevuta', 'Certificato Medico',
            'Documento di Identità', 'Patente', 'Assicurazione', 'Bolletta',
            'Estratto Conto', 'Curriculum Vitae', 'Lettera Ufficiale', 'Report',
            'Preventivo', 'Ordine di Acquisto', 'Garanzia', 'Manuale Utente',
            'Contratto di Affitto', 'Atto Notarile', 'Certificato di Nascita',
            'Diploma', 'Attestato', 'Licenza Software', 'Polizza Assicurativa'
        ]
        
        users = list(User.objects.all())
        
        self.stdout.write(f'Generando {num_documents} documenti personali...')
        
        created_documents = []
        
        for i in range(num_documents):
            try:
                # Seleziona utente random
                user = random.choice(users)
                
                # Genera dati del documento
                category = random.choice(document_categories)
                file_ext = random.choice(file_extensions)
                
                # Crea titolo realistico
                title = f"{category} - {self.fake.date_between(start_date='-2y', end_date='today').strftime('%Y-%m-%d')}"
                
                # Genera descrizione
                description = self.fake.sentence(nb_words=random.randint(5, 15))
                
                # Crea contenuto del file
                file_content = self.create_fake_file_content(file_ext)
                
                # Nome file originale
                original_filename = f"{category.replace(' ', '_').lower()}_{self.fake.uuid4()[:8]}.{file_ext}"
                
                # Crea il file temporaneo
                file_obj = ContentFile(file_content.encode('utf-8'), name=original_filename)
                
                # Determina se crittografare (30% di probabilità)
                is_encrypted = random.choice([True, False, False, False])  # 25% encrypted
                
                # Determina se condivisibile (40% di probabilità)
                is_shareable = random.choice([True, False, False])  # 33% shareable
                
                # Crea il documento
                document = PersonalDocument.objects.create(
                    user=user,
                    title=title,
                    description=description,
                    file=file_obj,
                    is_encrypted=is_encrypted,
                    original_filename=original_filename,
                    is_shareable=is_shareable
                )
                
                created_documents.append(document)
                
                if (i + 1) % 10 == 0:
                    self.stdout.write(f'Creati {i + 1}/{num_documents} documenti personali...')
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Errore nella creazione del documento personale {i + 1}: {e}')
                )
                continue
        
        self.stdout.write(
            self.style.SUCCESS(f'Creazione completata! Generati {len(created_documents)} documenti personali.')
        )
        return created_documents
    
    def generate_created_documents(self, num_documents):
        """Genera documenti creati (testo) random"""
        
        document_types = ['text', 'note', 'letter', 'report']
        
        # Template per diversi tipi di documento
        templates = {
            'text': lambda: f"<h1>{self.fake.catch_phrase()}</h1><p>{self.fake.text(max_nb_chars=1500)}</p>",
            'note': lambda: f"<h2>Nota: {self.fake.sentence()}</h2><ul>" + "".join([f"<li>{self.fake.sentence()}</li>" for _ in range(random.randint(3, 8))]) + "</ul>",
            'letter': lambda: f"""<div>
                <p>Gentile {self.fake.name()},</p>
                <p>{self.fake.text(max_nb_chars=800)}</p>
                <p>Cordiali saluti,<br>{self.fake.name()}</p>
                <p>Data: {self.fake.date()}</p>
            </div>""",
            'report': lambda: f"""<h1>Report: {self.fake.catch_phrase()}</h1>
                <h2>Sommario Esecutivo</h2>
                <p>{self.fake.text(max_nb_chars=500)}</p>
                <h2>Dettagli</h2>
                <p>{self.fake.text(max_nb_chars=1000)}</p>
                <h2>Conclusioni</h2>
                <p>{self.fake.text(max_nb_chars=300)}</p>
            """
        }
        
        users = list(User.objects.all())
        
        self.stdout.write(f'Generando {num_documents} documenti creati...')
        
        created_docs = []
        
        for i in range(num_documents):
            try:
                user = random.choice(users)
                doc_type = random.choice(document_types)
                
                # Genera titolo basato sul tipo
                type_titles = {
                    'text': f"Documento {self.fake.word().title()}",
                    'note': f"Nota: {self.fake.sentence(nb_words=3)}",
                    'letter': f"Lettera a {self.fake.name()}",
                    'report': f"Report {self.fake.catch_phrase()}"
                }
                
                title = type_titles[doc_type]
                content = templates[doc_type]()
                
                # Calcola word count approssimativo
                word_count = len(content.split())
                
                # Determina se crittografare (70% di probabilità per documenti creati)
                is_encrypted = random.choice([True, True, True, False])  # 75% encrypted
                
                # Determina se condivisibile
                is_shareable = random.choice([True, False])  # 50% shareable
                
                document = CreatedDocument.objects.create(
                    user=user,
                    title=title,
                    document_type=doc_type,
                    content=content,
                    is_encrypted=is_encrypted,
                    is_shareable=is_shareable,
                    word_count=word_count
                )
                
                created_docs.append(document)
                
                if (i + 1) % 10 == 0:
                    self.stdout.write(f'Creati {i + 1}/{num_documents} documenti creati...')
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Errore nella creazione del documento creato {i + 1}: {e}')
                )
                continue
        
        self.stdout.write(
            self.style.SUCCESS(f'Creazione completata! Generati {len(created_docs)} documenti creati.')
        )
        return created_docs
    
    def show_final_stats(self):
        """Mostra statistiche finali"""
        personal_total = PersonalDocument.objects.count()
        created_total = CreatedDocument.objects.count()
        
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('STATISTICHE FINALI'))
        self.stdout.write('='*50)
        self.stdout.write(f'Documenti personali totali: {personal_total}')
        self.stdout.write(f'Documenti creati totali: {created_total}')
        self.stdout.write(f'Totale documenti: {personal_total + created_total}')
        
        # Statistiche per utente
        users_with_docs = User.objects.filter(
            models.Q(personal_documents__isnull=False) | 
            models.Q(created_documents__isnull=False)
        ).distinct()
        
        self.stdout.write(f'\nUtenti con documenti: {users_with_docs.count()}')
        for user in users_with_docs[:5]:  # Mostra primi 5
            personal_count = user.personal_documents.count()
            created_count = user.created_documents.count()
            self.stdout.write(f'  {user.username}: {personal_count} personali, {created_count} creati')
        
        if users_with_docs.count() > 5:
            self.stdout.write(f'  ... e altri {users_with_docs.count() - 5} utenti')