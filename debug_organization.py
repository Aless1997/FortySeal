import os
import django
import logging

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Cripto.settings')
django.setup()

from Cripto1.models import Organization

logger = logging.getLogger('Cripto1')

def test_organization_field():
    logger.info("=== TEST ORGANIZATION FIELD ===")
    
    # Test creazione
    try:
        org = Organization.objects.create(
            name="Test Org",
            max_file_size_mb=50
        )
        logger.info(f"Organization creata: ID={org.id}, max_file_size_mb={org.max_file_size_mb}")
        
        # Test lettura
        org_read = Organization.objects.get(id=org.id)
        logger.info(f"Organization letta: max_file_size_mb={org_read.max_file_size_mb} (tipo: {type(org_read.max_file_size_mb)})")
        
        # Test aggiornamento
        org_read.max_file_size_mb = 100
        org_read.save()
        logger.info(f"Organization aggiornata: max_file_size_mb={org_read.max_file_size_mb}")
        
    except Exception as e:
        logger.error(f"ERRORE nel test: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    test_organization_field()