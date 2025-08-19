from django.core.management.base import BaseCommand
from Cripto1.models import UserProfile

class Command(BaseCommand):
    help = 'Generates new RSA key pairs for all existing users.'

    def handle(self, *args, **options):
        self.stdout.write('Generating new key pairs for all users...')

        user_profiles = UserProfile.objects.all()
        total_users = user_profiles.count()

        for i, profile in enumerate(user_profiles):
            try:
                profile.generate_key_pair()
                self.stdout.write(self.style.SUCCESS(f'Successfully generated key pair for user {profile.user.username} ({i + 1}/{total_users})'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Failed to generate key pair for user {profile.user.username} ({i + 1}/{total_users}): {e}'))

        self.stdout.write(self.style.SUCCESS('Finished generating key pairs.')) 