def organization_context(request):
    """
    Context processor per fornire l'organizzazione ai template
    """
    organization = getattr(request, 'organization', None)
    
    # Controllo se il 2FA è obbligatorio ma non configurato
    require_2fa_setup = False
    if request.user.is_authenticated and hasattr(request.user, 'userprofile'):
        user_profile = request.user.userprofile
        if user_profile.organization and user_profile.organization.require_2fa:
            if not user_profile.two_factor_verified:
                require_2fa_setup = True
    
    if organization:
        return {
            'current_organization': organization,
            'org_name': organization.name,
            'org_logo': organization.logo,
            'org_primary_color': organization.primary_color,
            'org_secondary_color': organization.secondary_color,
            'org_slug': organization.slug,
            'require_2fa_setup': require_2fa_setup,
        }
    
    return {
        'current_organization': None,
        'org_name': 'FortySeal',
        'org_logo': None,
        'org_primary_color': '#007bff',
        'org_secondary_color': '#6c757d',
        'org_slug': 'default',
        'require_2fa_setup': require_2fa_setup,
    }