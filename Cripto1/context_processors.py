def organization_context(request):
    """
    Context processor per fornire l'organizzazione ai template
    """
    organization = getattr(request, 'organization', None)
    
    if organization:
        return {
            'current_organization': organization,
            'org_name': organization.name,
            'org_logo': organization.logo,
            'org_primary_color': organization.primary_color,
            'org_secondary_color': organization.secondary_color,
            'org_slug': organization.slug,
        }
    
    return {
        'current_organization': None,
        'org_name': 'FortySeal',
        'org_logo': None,
        'org_primary_color': '#007bff',
        'org_secondary_color': '#6c757d',
        'org_slug': 'default',
    } 