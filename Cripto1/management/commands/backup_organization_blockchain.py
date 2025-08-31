def handle(self, *args, **options):
    organization_id = options['organization_id']
    organization = Organization.objects.get(id=organization_id)
    
    # Backup solo dei blocchi dell'organizzazione
    blocks = Block.objects.filter(organization=organization).order_by('index')
    
    # Backup solo delle transazioni dell'organizzazione
    transactions = Transaction.objects.filter(organization=organization).order_by('id')