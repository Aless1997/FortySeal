from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Aggiorna l\'utilizzo storage per tutti gli utenti'
    
    def handle(self, *args, **options):
        users = User.objects.all()
        updated_count = 0
        
        for user in users:
            try:
                user_profile = user.userprofile
                old_usage = user_profile.storage_used_bytes
                new_usage = user_profile.update_storage_usage()
                
                if old_usage != new_usage:
                    updated_count += 1
                    self.stdout.write(
                        f'Aggiornato {user.username}: {old_usage} -> {new_usage} bytes'
                    )
                    
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Errore per {user.username}: {e}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Aggiornati {updated_count} utenti')
        )