from django.utils.html import strip_tags
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Ottiene l'IP del client dalla richiesta"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def send_welcome_email(user, user_profile, request):
    """Invia email di benvenuto dopo la registrazione"""
    try:
        # Ottieni l'IP di registrazione
        registration_ip = get_client_ip(request)
        
        # Ottieni il ruolo dell'utente
        user_roles = user_profile.get_roles()
        user_role = user_roles[0].name if user_roles else 'Nessun ruolo'
        
        # Ottieni l'organizzazione dell'utente
        organization_name = user_profile.organization.name if user_profile.organization else 'Nessuna organizzazione'
        
        # Prepara il contesto per il template
        context = {
            'username': user.username,
            'email': user.email,
            'user_key': user_profile.user_key,
            'registration_ip': registration_ip,
            'registration_date': datetime.now().strftime('%d/%m/%Y alle %H:%M'),
            'user_role': user_role,
            'organization': organization_name,
        }
        
        # Renderizza il template HTML
        html_message = render_to_string('emails/welcome_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Invia l'email
        send_mail(
            subject='🎉 Benvenuto in FortySeal - Registrazione Completata!',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email di benvenuto inviata con successo a {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Errore nell'invio dell'email di benvenuto a {user.email}: {str(e)}")
        return False

def send_immediate_transaction_notification(transaction, user, request, direction='sent'):
    """
    Invia notifica email immediata per transazioni (SENZA info blocco)
    
    Args:
        transaction: Oggetto Transaction
        user: Utente che riceve la notifica
        request: Oggetto request per ottenere l'IP
        direction: 'sent' o 'received'
    """
    try:
        # Ottieni l'IP dell'utente
        user_ip = get_client_ip(request)
        
        # Determina l'altro utente (mittente o destinatario)
        if direction == 'sent':
            other_user = transaction.receiver.username
        else:
            other_user = transaction.sender.username
        
        # Prepara il contesto per il template (SENZA info blocco)
        context = {
            'transaction_id': transaction.id,
            'transaction_hash': transaction.transaction_hash,
            'transaction_type': transaction.type,
            'transaction_direction': direction,
            'other_user': other_user,
            'user_ip': user_ip,
            'timestamp': timezone.datetime.fromtimestamp(transaction.timestamp, tz=timezone.get_current_timezone()).strftime('%d/%m/%Y alle %H:%M:%S'),
            'is_encrypted': transaction.is_encrypted,
            'filename': transaction.original_filename if transaction.type == 'file' else None,
        }
        
        # Renderizza il template HTML
        html_message = render_to_string('emails/transaction_immediate_notification.html', context)
        plain_message = strip_tags(html_message)
        
        # Determina il soggetto dell'email
        if direction == 'sent':
            subject = f'📤 Transazione Creata - {transaction.type.title()} #{transaction.id}'
        else:
            subject = f'📥 Nuova Transazione Ricevuta - {transaction.type.title()} #{transaction.id}'
        
        # Invia l'email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Notifica transazione immediata inviata con successo a {user.email} (Direction: {direction})")
        return True
        
    except Exception as e:
        logger.error(f"Errore nell'invio della notifica transazione immediata a {user.email}: {str(e)}")
        return False

def send_block_confirmation_emails(block, transactions):
    """
    Invia email di conferma blocco a tutti gli utenti che hanno transazioni nel blocco
    
    Args:
        block: Oggetto Block
        transactions: QuerySet delle transazioni nel blocco
    """
    try:
        # Ottieni tutti gli utenti unici coinvolti nelle transazioni
        users_to_notify = set()
        transaction_data = {}
        
        for tx in transactions:
            # Aggiungi mittente e destinatario
            users_to_notify.add(tx.sender)
            users_to_notify.add(tx.receiver)
            
            # Salva i dati della transazione per ogni utente
            for user in [tx.sender, tx.receiver]:
                if user not in transaction_data:
                    transaction_data[user] = []
                
                direction = 'sent' if user == tx.sender else 'received'
                other_user = tx.receiver.username if user == tx.sender else tx.sender.username
                
                transaction_data[user].append({
                    'transaction_id': tx.id,
                    'transaction_hash': tx.transaction_hash,
                    'transaction_type': tx.type,
                    'transaction_direction': direction,
                    'other_user': other_user,
                })
        
        # Invia email a ogni utente
        for user in users_to_notify:
            if not user.email:
                continue
                
            # Prendi la prima transazione dell'utente per i dettagli principali
            main_transaction = transaction_data[user][0]
            
            # Prepara il contesto per il template
            context = {
                'username': user.username,
                'block_index': block.index,
                'block_hash': block.hash,
                'merkle_root': block.merkle_root,
                'block_timestamp': timezone.datetime.fromtimestamp(block.timestamp, tz=timezone.get_current_timezone()).strftime('%d/%m/%Y alle %H:%M:%S'),
                'nonce': block.nonce,
                'difficulty': int(block.difficulty),
                'total_transactions': transactions.count(),
                **main_transaction  # Include i dettagli della transazione principale
            }
            
            # Renderizza il template HTML
            html_message = render_to_string('emails/block_confirmation.html', context)
            plain_message = strip_tags(html_message)
            
            # Invia l'email
            send_mail(
                subject=f'✅ Transazione Confermata - Blocco #{block.index} Creato!',
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"Email conferma blocco #{block.index} inviata con successo a {user.email}")
        
        return True
        
    except Exception as e:
        logger.error(f"Errore nell'invio delle email di conferma blocco #{block.index}: {str(e)}")
        return False

# RIMUOVI queste righe (203-205):
def send_transaction_notification(transaction, user, request, direction='sent'):
    """DEPRECATA: Usa send_immediate_transaction_notification invece"""
    return send_immediate_transaction_notification(transaction, user, request, direction)


def send_share_notification_email(shared_document, action_type, modifier=None):
    """Invia email di notifica per azioni di condivisione"""
    try:
        # Ottieni il documento originale
        if shared_document.share_type == 'created_document':
            from .models import CreatedDocument
            document = CreatedDocument.objects.get(id=shared_document.object_id)
        else:
            return False  # Altri tipi non supportati per co-working
        
        base_url = settings.BASE_URL if hasattr(settings, 'BASE_URL') else 'http://localhost:8000'
        
        if action_type == 'created':
            subject = f'🤝 Invito alla Collaborazione: {document.title}'
            template = 'emails/share_created.html'
            recipient = shared_document.shared_with.email
        elif action_type == 'modified':
            subject = f'✏️ Documento Modificato: {document.title}'
            template = 'emails/share_modified.html'
            recipient = shared_document.owner.email
        elif action_type == 'accessed':
            subject = f'👁️ Documento condiviso acceduto da {shared_document.shared_with.username}'
            template = 'emails/share_accessed.html'
            recipient = shared_document.owner.email
        elif action_type == 'downloaded':
            subject = f'⬇️ Documento condiviso scaricato da {shared_document.shared_with.username}'
            template = 'emails/share_downloaded.html'
            recipient = shared_document.owner.email
        else:
            return False
        
        context = {
            'shared_document': shared_document,
            'document': document,
            'base_url': base_url,
            'modifier': modifier,
            'action_type': action_type,
        }
        
        html_message = render_to_string(template, context)
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email di notifica condivisione inviata a {recipient}")
        return True
        
    except Exception as e:
        logger.error(f"Errore nell'invio email notifica condivisione: {str(e)}")


def send_organization_welcome_email(organization, admin_email, request):
    """Invia email di benvenuto per registrazione organizzazione"""
    try:
        context = {
            'organization_name': organization.name,
            'registration_code': organization.registration_code,
            'max_users': organization.max_users,
            'registration_date': datetime.now().strftime('%d/%m/%Y alle %H:%M'),
        }
        
        html_message = render_to_string('emails/organization_welcome_email.html', context)
        plain_message = strip_tags(html_message)
        
        # Invia email all'admin dell'organizzazione
        if admin_email:
            send_mail(
                subject='🏢 Organizzazione Registrata con Successo - FortySeal Enterprise',
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[admin_email],
                html_message=html_message,
                fail_silently=False,
            )
        
        logger.info(f"Email di benvenuto organizzazione inviata per {organization.name}")
        return True
    except Exception as e:
        logger.error(f"Errore invio email organizzazione: {str(e)}")
        return False

def send_admin_welcome_email(user, user_profile, request):
    """Invia email di benvenuto per amministratore organizzazione"""
    try:
        context = {
            'username': user.username,
            'email': user.email,
            'organization': user_profile.organization.name if user_profile.organization else 'N/A',
            'registration_date': datetime.now().strftime('%d/%m/%Y alle %H:%M'),
        }
        
        html_message = render_to_string('emails/admin_welcome_email.html', context)
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject='👑 Privilegi Amministrativi Attivati - FortySeal Admin',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Email di benvenuto admin inviata a {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Errore nell'invio email admin a {user.email}: {str(e)}")
        return False


def send_meeting_invite(email, meeting_id, meeting_url, invited_by):
    """Invia email di invito per riunione video"""
    subject = f'Invito alla riunione video da {invited_by.get_full_name() or invited_by.username}'
    
    message = f"""
    Ciao,
    
    Sei stato invitato a partecipare a una riunione video.
    
    Organizzatore: {invited_by.get_full_name() or invited_by.username}
    ID Riunione: {meeting_id}
    
    Per partecipare, clicca sul seguente link:
    {meeting_url}
    
    Cordiali saluti,
    Il team di {settings.SITE_NAME if hasattr(settings, 'SITE_NAME') else 'Sistema'}
    """
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )