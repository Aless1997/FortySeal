# Nuovo comando per backup automatici
from django.core.management.base import BaseCommand
from django.core.cache import cache
from django.utils import timezone
from django.core.management import call_command
from datetime import timedelta
import os
import shutil
import logging
import json

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Esegue backup automatici incrementali'
    
    def handle(self, *args, **options):
        last_backup = cache.get('last_backup_time')
        
        if self.should_backup(last_backup):
            try:
                self.create_incremental_backup()
                cache.set('last_backup_time', timezone.now(), timeout=None)
                self.stdout.write(self.style.SUCCESS('Backup completato con successo'))
            except Exception as e:
                logger.error(f'Errore durante il backup: {e}')
                self.stdout.write(self.style.ERROR(f'Errore: {e}'))
    
    def should_backup(self, last_backup):
        if not last_backup:
            return True
        
        # Backup ogni 24 ore
        return timezone.now() - last_backup > timedelta(hours=24)
    
    def create_incremental_backup(self):
        # Implementa la logica di backup
        backup_dir = f'backups/{timezone.now().strftime("%Y%m%d_%H%M%S")}'
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup database e media files
        self.backup_database(backup_dir)
        self.backup_media_files(backup_dir)
    
    def backup_database(self, backup_dir):
        """Esegue il backup del database usando Django dumpdata"""
        try:
            # Usa Django dumpdata invece di comandi esterni
            backup_path = os.path.join(backup_dir, 'database_dump.json')
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                call_command('dumpdata', 
                           '--natural-foreign', 
                           '--natural-primary',
                           '--indent=2',
                           stdout=f)
            
            logger.info(f'Database esportato in {backup_path}')
            self.stdout.write(f'Database backup salvato in: {backup_path}')
            
        except Exception as e:
            logger.error(f'Errore durante il backup del database: {e}')
            raise
    
    def backup_media_files(self, backup_dir):
        """Esegue il backup dei file media"""
        try:
            from django.conf import settings
            
            # Backup file media
            if hasattr(settings, 'MEDIA_ROOT') and settings.MEDIA_ROOT and os.path.exists(settings.MEDIA_ROOT):
                media_backup_dir = os.path.join(backup_dir, 'media')
                if os.path.exists(settings.MEDIA_ROOT):
                    shutil.copytree(settings.MEDIA_ROOT, media_backup_dir, dirs_exist_ok=True)
                    logger.info(f'File media copiati in {media_backup_dir}')
                    self.stdout.write(f'Media files backup salvato in: {media_backup_dir}')
            
            # Backup file statici se esistono
            if hasattr(settings, 'STATIC_ROOT') and settings.STATIC_ROOT and os.path.exists(settings.STATIC_ROOT):
                static_backup_dir = os.path.join(backup_dir, 'static')
                shutil.copytree(settings.STATIC_ROOT, static_backup_dir, dirs_exist_ok=True)
                logger.info(f'File statici copiati in {static_backup_dir}')
                self.stdout.write(f'Static files backup salvato in: {static_backup_dir}')
            
            # Backup della cartella backups esistente (backup incrementale)
            existing_backups = os.path.join(os.path.dirname(backup_dir))
            if os.path.exists(existing_backups):
                backup_info = {
                    'timestamp': timezone.now().isoformat(),
                    'backup_type': 'incremental',
                    'database_included': True,
                    'media_included': hasattr(settings, 'MEDIA_ROOT') and os.path.exists(settings.MEDIA_ROOT),
                    'static_included': hasattr(settings, 'STATIC_ROOT') and os.path.exists(settings.STATIC_ROOT)
                }
                
                info_path = os.path.join(backup_dir, 'backup_info.json')
                with open(info_path, 'w', encoding='utf-8') as f:
                    json.dump(backup_info, f, indent=2, ensure_ascii=False)
                
                logger.info(f'Informazioni backup salvate in {info_path}')
                
        except Exception as e:
            logger.error(f'Errore durante il backup dei file: {e}')
            raise