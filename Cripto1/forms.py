from django import forms
from django.contrib.auth.models import User
from .models import UserProfile, Role, Permission

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
    
    class Meta:
        model = UserProfile
        fields = [
            'department', 'position', 'phone', 'emergency_contact', 
            'notes', 'profile_picture'
        ]
        labels = {
            'department': 'Dipartimento',
            'position': 'Posizione',
            'phone': 'Telefono',
            'emergency_contact': 'Contatto di Emergenza',
            'notes': 'Note',
            'profile_picture': 'Foto Profilo'
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.user:
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
            self.fields['email'].initial = self.instance.user.email
    
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