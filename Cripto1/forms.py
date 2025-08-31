from django import forms
from django.contrib.auth.models import User
from .models import UserProfile, Role, Permission, Organization

class UserProfileEditForm(forms.ModelForm):
    """Form per la modifica del profilo utente"""
    first_name = forms.CharField(max_length=30, required=False, label='Nome')
    last_name = forms.CharField(max_length=30, required=False, label='Cognome')
    email = forms.EmailField(required=True, label='Email')
    profile_picture = forms.ImageField(
        required=False,
        label='Foto Profilo',
        widget=forms.FileInput(attrs={'accept': 'image/*'})
    )
    organization = forms.ModelChoiceField(
        queryset=Organization.objects.all(),
        required=False,
        label='Organizzazione',
        empty_label='Nessuna organizzazione'
    )
    
    class Meta:
        model = UserProfile
        fields = [
            'organization', 'department', 'position', 'phone', 'emergency_contact', 
            'notes', 'profile_picture'
        ]
        labels = {
            'organization': 'Organizzazione',
            'department': 'Dipartimento',
            'position': 'Posizione',
            'phone': 'Telefono',
            'emergency_contact': 'Contatto di Emergenza',
            'notes': 'Note',
            'profile_picture': 'Foto Profilo'
        }
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)  # Utente che sta facendo la modifica
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.user:
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
            self.fields['email'].initial = self.instance.user.email
        
        # Solo i superuser possono modificare l'organizzazione
        if not (user and user.is_superuser):
            self.fields['organization'].widget = forms.HiddenInput()
            self.fields['organization'].required = False
        else:
            # Per i superuser, assicuriamoci che il campo sia visibile
            self.fields['organization'].widget.attrs.update({
                'class': 'form-control'
            })
    
    def save(self, commit=True):
        user_profile = super().save(commit=False)
        if commit:
            # Aggiorna anche i campi dell'utente
            user_profile.user.first_name = self.cleaned_data['first_name']
            user_profile.user.last_name = self.cleaned_data['last_name']
            user_profile.user.email = self.cleaned_data['email']
            user_profile.user.save()
            user_profile.save()
        return user_profile


class UserCreateForm(forms.Form):
    """Form per la creazione di nuovi utenti"""
    username = forms.CharField(max_length=150, label='Username')
    email = forms.EmailField(label='Email')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    confirm_password = forms.CharField(widget=forms.PasswordInput, label='Conferma Password')
    first_name = forms.CharField(max_length=30, required=False, label='Nome')
    last_name = forms.CharField(max_length=30, required=False, label='Cognome')
    department = forms.CharField(max_length=100, required=False, label='Dipartimento')
    position = forms.CharField(max_length=100, required=False, label='Posizione')
    phone = forms.CharField(max_length=20, required=False, label='Telefono')
    default_role = forms.ModelChoiceField(
        queryset=Role.objects.filter(is_active=True),
        required=False,
        label='Ruolo di Default'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError('Le password non coincidono')
        
        return cleaned_data


class RoleForm(forms.ModelForm):
    """Form per la creazione/modifica di ruoli"""
    class Meta:
        model = Role
        fields = ['name', 'description']
        labels = {
            'name': 'Nome Ruolo',
            'description': 'Descrizione'
        }


class RolePermissionForm(forms.Form):
    """Form per la gestione dei permessi di un ruolo"""
    permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.filter(is_active=True),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label='Permessi'
    )
    
    def __init__(self, *args, **kwargs):
        role = kwargs.pop('role', None)
        super().__init__(*args, **kwargs)
        if role:
            self.fields['permissions'].initial = role.permissions.all()


class UserRoleAssignmentForm(forms.Form):
    """Form per l'assegnazione di ruoli agli utenti"""
    role = forms.ModelChoiceField(
        queryset=Role.objects.filter(is_active=True),
        label='Ruolo'
    )
    expires_at = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date'}),
        label='Data di Scadenza'
    )
    notes = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3}),
        required=False,
        label='Note'
    )


class UserSearchForm(forms.Form):
    """Form per la ricerca di utenti"""
    search = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'Cerca per username, email, nome...'}),
        label='Ricerca'
    )
    status = forms.ChoiceField(
        choices=[
            ('', 'Tutti'),
            ('active', 'Attivi'),
            ('inactive', 'Inattivi'),
            ('locked', 'Bloccati')
        ],
        required=False,
        label='Stato'
    )
    role = forms.ModelChoiceField(
        queryset=Role.objects.filter(is_active=True),
        required=False,
        label='Ruolo'
    )


class OrganizationRegistrationForm(forms.Form):
    """Form per la registrazione di una nuova organizzazione"""
    
    # Dati Organizzazione
    organization_name = forms.CharField(
        max_length=200, 
        label='Nome Organizzazione',
        help_text='Nome completo della tua organizzazione'
    )
    organization_slug = forms.SlugField(
        max_length=50,
        label='Codice Organizzazione',
        help_text='Codice univoco (es: azienda-abc). Solo lettere, numeri e trattini.'
    )
    organization_domain = forms.CharField(
        max_length=100,
        required=False,
        label='Dominio Email',
        help_text='Dominio email aziendale (es: azienda.com) - opzionale'
    )
    organization_description = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3}),  # ← CORREZIONE QUI
        required=False,
        label='Descrizione',
        help_text='Breve descrizione della tua organizzazione'
    )
    
    # Dati Amministratore
    admin_username = forms.CharField(
        max_length=150, 
        label='Username Amministratore'
    )
    admin_email = forms.EmailField(
        label='Email Amministratore'
    )
    admin_password = forms.CharField(
        widget=forms.PasswordInput, 
        label='Password'
    )
    admin_confirm_password = forms.CharField(
        widget=forms.PasswordInput, 
        label='Conferma Password'
    )
    admin_first_name = forms.CharField(
        max_length=30, 
        label='Nome'
    )
    admin_last_name = forms.CharField(
        max_length=30, 
        label='Cognome'
    )
    
    # Termini e Condizioni
    accept_terms = forms.BooleanField(
        required=True,
        label='Accetto i termini e condizioni di servizio'
    )
    
    def clean_organization_slug(self):
        slug = self.cleaned_data['organization_slug']
        if Organization.objects.filter(slug=slug).exists():
            raise forms.ValidationError('Questo codice organizzazione è già in uso')
        return slug
    
    def clean_organization_domain(self):
        domain = self.cleaned_data.get('organization_domain')
        if domain and Organization.objects.filter(domain=domain).exists():
            raise forms.ValidationError('Questo dominio è già registrato')
        return domain
    
    def clean_admin_username(self):
        username = self.cleaned_data['admin_username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('Username già esistente')
        return username
    
    def clean_admin_email(self):
        email = self.cleaned_data['admin_email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email già registrata')
        return email
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('admin_password')
        confirm_password = cleaned_data.get('admin_confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError('Le password non coincidono')
        
        # Validazione robustezza password
        if password and len(password) < 8:
            raise forms.ValidationError('La password deve essere di almeno 8 caratteri')
        
        if password and not (any(c.isdigit() for c in password) and any(c.isalpha() for c in password)):
            raise forms.ValidationError('La password deve contenere almeno un numero e una lettera')
        
        return cleaned_data