from django.contrib import admin
from django.urls import path, include
from . import views
from . import user_management_views  # Aggiungi questa riga
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy
from django.urls import path
from .decorators import external_forbidden

app_name = 'Cripto1'

urlpatterns = [
    path('', views.homepage, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # User dashboard and profile
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.personal_profile, name='personal_profile'),
    path('profile/statistics/', views.personal_statistics, name='personal_statistics'),  # NUOVA RIGA
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('users/', external_forbidden(views.users_feed), name='users_feed'),  # Spostato qui
    path('all-transactions/', views.all_transactions_view, name='all_transactions'),
    path('unviewed-transactions/', views.unviewed_transactions_list, name='unviewed_transactions_list'),


    # Transaction URLs
    path('transaction/create/', external_forbidden(views.create_transaction), name='create_transaction'),  # Spostato qui
    path('transaction/<int:transaction_id>/', views.transaction_details, name='transaction_details'),
    path('transaction/<int:transaction_id>/download/', views.download_file, name='download_file'),
    path('transaction/decrypt/', views.decrypt_transaction, name='decrypt_transaction'),
    path('search-transactions-ajax/', views.search_transactions_ajax, name='search_transactions_ajax'),

    # Custom Admin URLs (NON devono iniziare solo con 'admin/', per evitare conflitti)
    path('admdashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admdashboard/verify-blockchain/', views.verify_blockchain, name='verify_blockchain'),
    path('admdashboard/export/<str:model>/', views.export_csv, name='export_csv'),
    path('admdashboard/user/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),


    # Audit Log URLs
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),
    path('audit-logs/<int:log_id>/', views.audit_log_detail, name='audit_log_detail'),
    path('audit-logs/export/', views.export_audit_logs, name='export_audit_logs'),
    path('audit-logs/analytics/', views.audit_logs_analytics, name='audit_logs_analytics'),
    path('security-alerts/', views.security_alerts, name='security_alerts'),

    # User Management URLs
    path('user-management/', views.user_management_dashboard, name='user_management_dashboard'),
    
    path('user-management/users/', views.user_list, name='user_list'),
    path('user-management/users/create/', views.create_user, name='create_user'),
    path('user-management/users/<int:user_id>/', views.user_detail, name='user_detail'),
    path('user-management/users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
    path('user-management/users/<int:user_id>/toggle-status/', views.toggle_user_status, name='toggle_user_status'),
    path('user-management/users/<int:user_id>/assign-role/', user_management_views.assign_role, name='assign_role'),
    path('user-management/users/<int:user_id>/assign-role-form/', user_management_views.assign_role_form, name='assign_role_form'),
    path('user-management/users/<int:user_id>/remove-role/<int:role_id>/', views.remove_role, name='remove_role'),

    
    # Role Management URLs
    path('user-management/roles/', views.role_list, name='role_list'),
    path('user-management/roles/create/', views.create_role, name='create_role'),
    path('user-management/roles/<int:role_id>/', views.role_detail, name='role_detail'),
    path('users/<int:user_id>/storage/', views.manage_user_storage, name='manage_user_storage'),

    # Debug URLs
    path('debug/permissions/', views.debug_permissions, name='debug_permissions'),

    # Blockchain mining
    path('mine-block/', views.mine_block, name='mine_block'),

    # Password change
    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='registration/password_change_form.html', success_url=reverse_lazy('Cripto1:password_change_done')), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_change_done.html'), name='password_change_done'),
    
    # Personal Documents URLs
    path('documents/', views.personal_documents, name='personal_documents'),
    path('documents/upload/', views.upload_personal_document, name='upload_personal_document'),
    path('documents/<int:document_id>/download/', views.download_personal_document, name='download_personal_document'),
    path('documents/<int:document_id>/view/', views.view_personal_document, name='view_personal_document'),  # Nuova URL
    path('documents/<int:document_id>/delete/', views.delete_personal_document, name='delete_personal_document'),
    path('documents/<int:document_id>/send/', views.send_document_as_transaction, name='send_document_as_transaction'),
    path('documents/<int:document_id>/create-transaction/', views.create_transaction_from_document, name='create_transaction_from_document'),  # Spostato qui
    path('created-documents/<int:document_id>/share/', views.create_transaction_from_created_document, name='create_transaction_from_created_document'),
    path('transactions/<int:transaction_id>/add-to-personal-documents/', views.add_transaction_file_to_personal_documents, name='add_transaction_file_to_personal_documents'),
    # Django admin (deve essere l'ULTIMA e fuori dal blocco app)
    path('admin/', admin.site.urls),
    # Aggiungi questa riga per il pattern backup_management
    path('admdashboard/backup/', views.backup_management, name='backup_management'),
    # Aggiungi questa riga alle URL patterns esistenti
    path('transactions/<int:transaction_id>/view-file/', views.view_transaction_file, name='view_transaction_file'),
    path('admdashboard/backup/upload/', views.upload_backup, name='upload_backup'),
    path('admdashboard/backup/download/<str:filename>/', views.download_backup, name='download_backup'),
    # Aggiungi questi URL al tuo urlpatterns
    path('setup-2fa/', views.setup_2fa, name='setup_2fa'),
    path('manage-2fa/', views.manage_2fa, name='manage_2fa'),
    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
    # Nelle URL patterns
    path('user-management/user/<int:user_id>/2fa-qrcode/', user_management_views.view_user_2fa_qrcode, name='view_user_2fa_qrcode'),
    # File Manager URLs
    path('admdashboard/file-manager/', views.file_manager, name='file_manager'),
    # Aggiungi questi URL
    path('documents/create/', views.create_document, name='create_document'),
    path('documents/created/', views.created_documents_list, name='created_documents_list'),
    path('documents/edit/<int:document_id>/', views.edit_document, name='edit_document'),
    # Aggiungi questa riga dopo le altre URL dei documenti
    path('documents/delete/<int:document_id>/', views.delete_created_document, name='delete_created_document'),
    # Aggiungi queste righe nelle URL patterns esistenti, prima della chiusura della lista
    # Sostituisci la riga esistente con queste due righe complete
    path('admdashboard/sessions/', views.session_management, name='session_management'),
    path('admdashboard/my-sessions/', views.my_sessions, name='my_sessions'),
    path('admdashboard/terminate-session/', views.terminate_session, name='terminate_session'),
    # Sharing URLs
    path('share/create/', views.create_share, name='create_share'),
    path('share/my-shares/', views.my_shares, name='my_shares'),
    path('share/<uuid:share_id>/', views.view_shared_document, name='view_shared_document'),
    path('share/<uuid:share_id>/download/', views.download_shared_document, name='download_shared_document'),
    path('share/<uuid:share_id>/edit/', views.edit_shared_document, name='edit_shared_document'),
    path('share/<uuid:share_id>/revoke/', views.revoke_share, name='revoke_share'),
    path('documents/created/<int:document_id>/add-collaborator/', views.add_collaborator, name='add_collaborator'),
    # Notification URLs
    path('notifications/', views.notifications, name='notifications'),
    path('notifications/<int:notification_id>/mark-read/', views.mark_notification_as_read, name='mark_notification_as_read')
    ]