from django.contrib import admin
from django.contrib import messages  # Aggiungi questa importazione
from django.http import HttpResponse
import csv
from Cripto1.models import BlockchainState, CreatedDocument, Transaction, UserProfile, Block, SmartContract, AuditLog, Role, Permission, UserRole, Organization

class ExportCsvMixin:
    def export_as_csv(self, request, queryset):
        meta = self.model._meta
        field_names = [field.name for field in meta.fields]

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename={}.csv'.format(meta)
        writer = csv.writer(response)

        writer.writerow(field_names)
        for obj in queryset:
            writer.writerow([getattr(obj, field) for field in field_names])

        return response

    export_as_csv.short_description = "Export Selected to CSV"

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in AuditLog._meta.fields]
    list_filter = ['action_type', 'severity', 'success', 'timestamp', 'user']
    search_fields = ['user__username', 'description', 'ip_address', 'user_agent']
    readonly_fields = ['timestamp', 'user', 'action_type', 'severity', 'description', 'ip_address', 
                      'user_agent', 'session_id', 'related_object_type', 'related_object_id', 
                      'additional_data', 'success', 'error_message']
    date_hierarchy = 'timestamp'
    list_per_page = 100
    
    actions = ["export_as_csv", "mark_as_critical", "mark_as_high"]
    
    fieldsets = (
        ('Informazioni Base', {
            'fields': ('timestamp', 'user', 'action_type', 'severity', 'success')
        }),
        ('Dettagli Azione', {
            'fields': ('description', 'error_message')
        }),
        ('Informazioni Tecniche', {
            'fields': ('ip_address', 'user_agent', 'session_id')
        }),
        ('Oggetti Correlati', {
            'fields': ('related_object_type', 'related_object_id')
        }),
        ('Dati Aggiuntivi', {
            'fields': ('additional_data',),
            'classes': ('collapse',)
        }),
    )
    
    def mark_as_critical(self, request, queryset):
        queryset.update(severity='CRITICAL')
    mark_as_critical.short_description = "Segna come critico"
    
    def mark_as_high(self, request, queryset):
        queryset.update(severity='HIGH')
    mark_as_high.short_description = "Segna come alto"

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in Role._meta.fields]
    list_filter = ['is_active', 'is_system_role', 'created_at', 'updated_at']
    search_fields = ['name', 'description']
    # Rimuovi questa riga:
    # filter_horizontal = ['permissions']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Informazioni Base', {
            'fields': ('name', 'description', 'is_active', 'is_system_role')
        }),
        # Rimuovi questa sezione:
        # ('Permessi', {
        #     'fields': ('permissions',)
        # }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ["export_as_csv", "activate_roles", "deactivate_roles"]
    
    def activate_roles(self, request, queryset):
        queryset.update(is_active=True)
    activate_roles.short_description = "Attiva ruoli selezionati"
    
    def deactivate_roles(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_roles.short_description = "Disattiva ruoli selezionati"

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ['name', 'slug', 'domain', 'max_users', 'max_storage_gb', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at', 'require_2fa']
    search_fields = ['name', 'slug', 'domain', 'description']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Informazioni Base', {
            'fields': ('name', 'slug', 'description', 'domain')
        }),
        ('Configurazioni', {
            'fields': ('max_users', 'max_storage_gb', 'logo', 'primary_color', 'secondary_color')
        }),
        ('Sicurezza', {
            'fields': ('require_2fa', 'password_policy', 'session_timeout_hours')
        }),
        ('Funzionalità', {
            'fields': ('features_enabled',)
        }),
        ('Stato', {
            'fields': ('is_active',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ["export_as_csv", "activate_organizations", "deactivate_organizations"]
    
    def activate_organizations(self, request, queryset):
        queryset.update(is_active=True)
    activate_organizations.short_description = "Attiva organizzazioni selezionate"
    
    def deactivate_organizations(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_organizations.short_description = "Disattiva organizzazioni selezionate"

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in Permission._meta.fields]
    list_filter = ['category', 'is_active', 'created_at']
    search_fields = ['name', 'codename', 'description']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Informazioni Base', {
            'fields': ('name', 'codename', 'description', 'category', 'is_active')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ["export_as_csv", "activate_permissions", "deactivate_permissions"]
    
    def activate_permissions(self, request, queryset):
        queryset.update(is_active=True)
    activate_permissions.short_description = "Attiva permessi selezionati"
    
    def deactivate_permissions(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_permissions.short_description = "Disattiva permessi selezionati"

@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in UserRole._meta.fields]
    list_filter = ['role', 'is_active', 'assigned_at', 'expires_at']
    search_fields = ['user__username', 'role__name', 'assigned_by__username', 'notes']
    readonly_fields = ['assigned_at']
    
    fieldsets = (
        ('Assegnazione', {
            'fields': ('user', 'role', 'assigned_by', 'assigned_at')
        }),
        ('Configurazione', {
            'fields': ('expires_at', 'is_active', 'notes')
        }),
    )
    
    actions = ["export_as_csv", "activate_assignments", "deactivate_assignments"]
    
    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = "Scaduto"
    
    def activate_assignments(self, request, queryset):
        queryset.update(is_active=True)
    activate_assignments.short_description = "Attiva assegnazioni selezionate"
    
    def deactivate_assignments(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_assignments.short_description = "Disattiva assegnazioni selezionate"

@admin.register(BlockchainState)
class BlockchainStateAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in BlockchainState._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in Transaction._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in UserProfile._meta.fields]
    list_filter = ['is_active', 'department', 'created_at', 'last_login_date']
    search_fields = ['user__username', 'user__email', 'user__first_name', 'user__last_name', 'department', 'position']
    readonly_fields = ['created_at', 'last_login_date', 'last_login_ip']
    
    fieldsets = (
        ('Informazioni Utente', {
            'fields': ('user', 'is_active', 'department', 'position', 'phone', 'emergency_contact')
        }),
        ('Sicurezza', {
            'fields': ('login_attempts', 'locked_until', 'last_login_ip', 'last_login_date')
        }),
        ('SSO', {
            'fields': ('sso_provider', 'sso_id'),
            'classes': ('collapse',)
        }),
        ('Altro', {
            'fields': ('profile_picture', 'notes', 'created_at'),
            'classes': ('collapse',)
        }),
        ('Chiavi', {
            'fields': ('user_key', 'public_key', 'private_key'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ["export_as_csv", "activate_users", "deactivate_users", "reset_login_attempts", "regenerate_2fa_qrcode", "enable_2fa"]
    
    def activate_users(self, request, queryset):
        queryset.update(is_active=True)
    activate_users.short_description = "Attiva utenti selezionati"
    
    def deactivate_users(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_users.short_description = "Disattiva utenti selezionati"
    
    def reset_login_attempts(self, request, queryset):
        queryset.update(login_attempts=0, locked_until=None)
    reset_login_attempts.short_description = "Resetta tentativi di login"
    
    def reset_2fa_qrcode(self, request, queryset):
        reset_count = 0
        for profile in queryset:
            if profile.reset_2fa_secret():
                reset_count += 1
        
        if reset_count > 0:
            self.message_user(
                request, 
                f"QR code 2FA resettato per {reset_count} utenti. Gli utenti dovranno riconfigurare l'autenticazione a due fattori.",
                messages.SUCCESS
            )
        else:
            self.message_user(
                request,
                "Nessun QR code 2FA è stato resettato. Verifica che gli utenti selezionati abbiano l'autenticazione a due fattori abilitata.",
                messages.WARNING
            )
    reset_2fa_qrcode.short_description = "Resetta QR code 2FA per gli utenti selezionati"
    
    def regenerate_2fa_qrcode(self, request, queryset):
        regenerated_count = 0
        for profile in queryset:
            if profile.two_factor_enabled:
                profile.regenerate_2fa_secret()
                regenerated_count += 1
        
        if regenerated_count > 0:
            self.message_user(
                request, 
                f"QR code 2FA rigenerato per {regenerated_count} utenti. Gli utenti dovranno verificare nuovamente l'autenticazione a due fattori al prossimo accesso.",
                messages.SUCCESS
            )
        else:
            self.message_user(
                request,
                "Nessun QR code 2FA è stato rigenerato. Verifica che gli utenti selezionati abbiano l'autenticazione a due fattori abilitata.",
                messages.WARNING
            )
    regenerate_2fa_qrcode.short_description = "Rigenera QR code 2FA per gli utenti selezionati"
    
    def enable_2fa(self, request, queryset):
        enabled_count = 0
        for profile in queryset:
            if not profile.two_factor_enabled:
                # Genera il segreto 2FA se non esiste
                profile.generate_2fa_secret()
                # Abilita il 2FA ma richiedi verifica da parte dell'utente
                profile.two_factor_enabled = True
                profile.two_factor_verified = False
                profile.save()
                enabled_count += 1
        
        if enabled_count > 0:
            self.message_user(
                request, 
                f"2FA abilitato per {enabled_count} utenti. Gli utenti possono ora visualizzare il QR code.",
                messages.SUCCESS
            )
        else:
            self.message_user(
                request,
                "Nessun utente è stato modificato. Verifica che gli utenti selezionati non abbiano già il 2FA abilitato.",
                messages.WARNING
            )
    enable_2fa.short_description = "Abilita 2FA per gli utenti selezionati"

@admin.register(Block)
class BlockAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in Block._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(SmartContract)
class SmartContractAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in SmartContract._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True
    fields = [field.name for field in SmartContract._meta.fields]

admin.site.register(CreatedDocument)


