from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404, render
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.db import transaction, models
from django.utils import timezone
from datetime import date, timedelta
from dateutil.relativedelta import relativedelta
import json

from .models import Organization, OrganizationBilling, BillingPlan, Invoice, AuditLog
from .decorators import superuser_required

@superuser_required()
def finance_dashboard(request):
    """Dashboard finanziario principale"""
    organizations = Organization.objects.filter(is_active=True).prefetch_related('billing_config', 'user_profiles')
    
    # Statistiche generali
    total_organizations = organizations.count()
    paid_organizations = OrganizationBilling.objects.filter(payment_status='paid').count()
    pending_organizations = OrganizationBilling.objects.filter(payment_status='pending').count()
    overdue_organizations = OrganizationBilling.objects.filter(payment_status='overdue').count()
    
    # Calcolo fatturato mensile CORRETTO - somma solo le fatture pagate
    current_month = date.today().replace(day=1)
    
    monthly_revenue = Invoice.objects.filter(
        status='paid',
        created_at__gte=current_month
    ).aggregate(total=models.Sum('total_amount'))['total'] or 0
    
    context = {
        'organizations': organizations,
        'total_organizations': total_organizations,
        'paid_organizations': paid_organizations,
        'pending_organizations': pending_organizations,
        'overdue_organizations': overdue_organizations,
        'monthly_revenue': monthly_revenue,
        'billing_plans': BillingPlan.objects.filter(is_active=True),
    }
    
    return render(request, 'Cripto1/finance/dashboard.html', context)

@superuser_required()  # AGGIUNGI LE PARENTESI
@superuser_required()
def organization_billing_detail(request, org_id):
    """Dettaglio fatturazione organizzazione"""
    organization = get_object_or_404(Organization, id=org_id)
    
    # Trova un admin dell'organizzazione per l'email di billing
    admin_profile = None
    for profile in organization.user_profiles.all():
        if profile.has_role('admin'):
            admin_profile = profile
            break
    
    # Crea configurazione billing se non esiste
    billing_config, created = OrganizationBilling.objects.get_or_create(
        organization=organization,
        defaults={
            'billing_email': admin_profile.user.email if admin_profile else '',
        }
    )
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Aggiorna configurazione billing
                billing_config.billing_plan_id = request.POST.get('billing_plan') or None
                billing_config.custom_monthly_cost = request.POST.get('custom_monthly_cost') or None
                billing_config.custom_cost_per_user = request.POST.get('custom_cost_per_user') or None
                billing_config.billing_email = request.POST.get('billing_email', '')
                billing_config.billing_contact_name = request.POST.get('billing_contact_name', '')
                billing_config.admin_notes = request.POST.get('admin_notes', '')
                
                # Gestione costi aggiuntivi
                additional_costs = {}
                for key, value in request.POST.items():
                    if key.startswith('additional_cost_'):
                        cost_name = key.replace('additional_cost_', '')
                        if value:
                            additional_costs[cost_name] = float(value)
                
                billing_config.additional_costs = additional_costs
                billing_config.save()
                
                # Log dell'azione
                AuditLog.log_action(
                    user=request.user,
                    action_type='ADMIN_ACTION',
                    description=f'Configurazione fatturazione aggiornata per {organization.name}',
                    related_object_type='OrganizationBilling',
                    related_object_id=billing_config.id
                )
                
                messages.success(request, 'Configurazione fatturazione aggiornata con successo')
                
        except Exception as e:
            messages.error(request, f'Errore durante l\'aggiornamento: {str(e)}')
    
    context = {
        'organization': organization,
        'billing_config': billing_config,
        'billing_plans': BillingPlan.objects.filter(is_active=True),
        'user_count': organization.user_profiles.filter(is_active=True).count(),
        'monthly_cost': billing_config.get_monthly_cost(),
        'invoices': billing_config.invoices.all()[:10],
    }
    
    return render(request, 'Cripto1/finance/organization_billing.html', context)

@superuser_required()
def mark_payment_received(request, org_id):
    """Segna pagamento come ricevuto"""
    if request.method == 'POST':
        organization = get_object_or_404(Organization, id=org_id)
        billing_config = get_object_or_404(OrganizationBilling, organization=organization)
        
        billing_config.mark_as_paid()
        
        # Log dell'azione
        AuditLog.log_action(
            user=request.user,
            action_type='ADMIN_ACTION',
            description=f'Pagamento ricevuto per {organization.name}. Prossima scadenza: {billing_config.next_payment_due}',
            related_object_type='OrganizationBilling',
            related_object_id=billing_config.id
        )
        
        messages.success(request, f'Pagamento registrato. Prossima scadenza: {billing_config.next_payment_due}')
    
    return redirect('Cripto1:finance_dashboard')

@superuser_required()
def send_payment_request(request, org_id):
    """Invia richiesta di pagamento via email"""
    organization = get_object_or_404(Organization, id=org_id)
    billing_config = get_object_or_404(OrganizationBilling, organization=organization)
    
    if not billing_config.billing_email:
        messages.error(request, 'Email di fatturazione non configurata per questa organizzazione')
        return redirect('Cripto1:organization_billing_detail', org_id=org_id)
    
    try:
        # Genera fattura se non esiste
        today = date.today()
        period_start = today.replace(day=1)
        period_end = (period_start + relativedelta(months=1)) - timedelta(days=1)
        
        invoice, created = Invoice.objects.get_or_create(
            organization_billing=billing_config,
            billing_period_start=period_start,
            billing_period_end=period_end,
            defaults={
                'base_amount': billing_config.custom_monthly_cost or (billing_config.billing_plan.monthly_base_cost if billing_config.billing_plan else 0),
                'user_amount': 0,  # Calcolato dopo
                'additional_amount': sum(float(cost) for cost in billing_config.additional_costs.values() if isinstance(cost, (int, float, str)) and str(cost).replace('.', '').isdigit()),
                'total_amount': billing_config.get_monthly_cost(),
                'user_count': organization.user_profiles.filter(is_active=True).count(),
                'due_date': today + timedelta(days=30),
            }
        )
        
        # Prepara email
        context = {
            'organization': organization,
            'billing_config': billing_config,
            'invoice': invoice,
            'monthly_cost': billing_config.get_monthly_cost(),
            'user_count': organization.user_profiles.filter(is_active=True).count(),
        }
        
        subject = f'Richiesta Pagamento - {organization.name} - {invoice.invoice_number}'
        html_message = render_to_string('Cripto1/finance/payment_request_email.html', context)
        
        send_mail(
            subject=subject,
            message='',  # Testo semplice vuoto
            html_message=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[billing_config.billing_email],
            fail_silently=False,
        )
        
        # Aggiorna stato fattura
        invoice.status = 'sent'
        invoice.sent_date = timezone.now()
        invoice.save()
        
        # Log dell'azione
        AuditLog.log_action(
            user=request.user,
            action_type='ADMIN_ACTION',
            description=f'Richiesta pagamento inviata a {billing_config.billing_email} per {organization.name}',
            related_object_type='Invoice',
            related_object_id=invoice.id
        )
        
        messages.success(request, f'Richiesta pagamento inviata a {billing_config.billing_email}')
        
    except Exception as e:
        messages.error(request, f'Errore durante l\'invio: {str(e)}')
    
    return redirect('Cripto1:organization_billing_detail', org_id=org_id)

@login_required
def billing_analytics(request):
    """Analytics finanziarie"""
    # Calcola il fatturato mensile CORRETTO - usa le fatture pagate come nella dashboard
    current_month = date.today().replace(day=1)
    
    monthly_revenue = Invoice.objects.filter(
        status='paid',
        created_at__gte=current_month
    ).aggregate(total=models.Sum('total_amount'))['total'] or 0
    
    # Trova la prima fattura per determinare il punto di partenza
    first_invoice = Invoice.objects.filter(
        organization_billing__organization__is_active=True
    ).order_by('issue_date').first()
    
    revenue_data = []
    months_labels = []
    
    if first_invoice:
        # Calcola i dati storici basandosi sulle fatture pagate per ogni mese
        start_date = first_invoice.issue_date.replace(day=1)
        current_date = timezone.now().date().replace(day=1)
        
        temp_date = start_date
        
        while temp_date <= current_date:
            # Calcola il fatturato effettivo per questo mese dalle fatture pagate
            next_month = temp_date.replace(day=28) + timedelta(days=4)
            next_month = next_month.replace(day=1)
            
            month_revenue = Invoice.objects.filter(
                status='paid',
                created_at__gte=temp_date,
                created_at__lt=next_month
            ).aggregate(total=models.Sum('total_amount'))['total'] or 0
            
            revenue_data.append(float(month_revenue))
            months_labels.append(temp_date.strftime('%b %Y'))
            
            # Passa al mese successivo
            if temp_date.month == 12:
                temp_date = temp_date.replace(year=temp_date.year + 1, month=1)
            else:
                temp_date = temp_date.replace(month=temp_date.month + 1)
    else:
        # Se non ci sono fatture, mostra dati vuoti per gli ultimi 12 mesi
        for i in range(12):
            revenue_data.append(0.0)
            
            month_date = timezone.now().date().replace(day=1)
            months_back = 11 - i
            
            for _ in range(months_back):
                if month_date.month == 1:
                    month_date = month_date.replace(year=month_date.year - 1, month=12)
                else:
                    month_date = month_date.replace(month=month_date.month - 1)
            
            months_labels.append(month_date.strftime('%b %Y'))
    
    # Status distribution - usa OrganizationBilling direttamente
    billing_configs = OrganizationBilling.objects.filter(
        organization__is_active=True
    )
    
    status_stats = {
        'paid': billing_configs.filter(payment_status='paid').count(),
        'pending': billing_configs.filter(payment_status='pending').count(),
        'overdue': billing_configs.filter(payment_status='overdue').count(),
        'suspended': billing_configs.filter(payment_status='suspended').count(),
    }
    
    # Top organizations by revenue - passa OrganizationBilling objects
    top_organizations = sorted(
        billing_configs.select_related('organization'),
        key=lambda x: x.get_monthly_cost(),
        reverse=True
    )[:10]
    
    context = {
        'monthly_revenue': monthly_revenue,
        'revenue_data': revenue_data,
        'months_labels': months_labels,
        'status_stats': status_stats,
        'top_organizations': top_organizations,
        'first_invoice_date': first_invoice.issue_date if first_invoice else None,
    }
    
    return render(request, 'Cripto1/finance/analytics.html', context)


@login_required
def payment_history(request):
    """Storico di tutti i pagamenti ricevuti"""
    # Mostra tutte le fatture (non solo quelle pagate)
    all_invoices = Invoice.objects.filter(
        organization_billing__organization__is_active=True
    ).select_related(
        'organization_billing__organization'
    ).order_by('-issue_date')
    
    # Separa le fatture pagate dalle altre
    paid_invoices = all_invoices.filter(status='paid')
    
    # Calcola statistiche generali
    total_revenue = sum(invoice.total_amount for invoice in paid_invoices)
    total_invoices = paid_invoices.count()
    all_invoices_count = all_invoices.count()
    
    # Raggruppa per mese per statistiche aggiuntive
    monthly_stats = {}
    for invoice in paid_invoices:
        month_key = invoice.issue_date.strftime('%Y-%m')
        if month_key not in monthly_stats:
            monthly_stats[month_key] = {
                'count': 0,
                'total': 0,
                'month_name': invoice.issue_date.strftime('%B %Y')
            }
        monthly_stats[month_key]['count'] += 1
        monthly_stats[month_key]['total'] += float(invoice.total_amount)
    
    # Statistiche per status
    status_breakdown = {
        'draft': all_invoices.filter(status='draft').count(),
        'sent': all_invoices.filter(status='sent').count(),
        'paid': all_invoices.filter(status='paid').count(),
        'overdue': all_invoices.filter(status='overdue').count(),
        'cancelled': all_invoices.filter(status='cancelled').count(),
    }
    
    context = {
        'all_invoices': all_invoices,  # Mostra tutte le fatture
        'paid_invoices': paid_invoices,
        'total_revenue': total_revenue,
        'total_invoices': total_invoices,
        'all_invoices_count': all_invoices_count,
        'monthly_stats': monthly_stats,
        'status_breakdown': status_breakdown,
    }
    
    return render(request, 'Cripto1/finance/payment_history.html', context)


@login_required
@require_http_methods(["POST"])
def register_organization_payment(request, organization_id):
    """Registra il pagamento per un'organizzazione creando o aggiornando la fattura più recente"""
    try:
        organization = get_object_or_404(Organization, id=organization_id)
        
        # Verifica che l'utente abbia i permessi
        if not request.user.is_staff:
            return JsonResponse({'success': False, 'error': 'Permessi insufficienti'})
        
        # Ottieni o crea l'OrganizationBilling
        org_billing, created = OrganizationBilling.objects.get_or_create(
            organization=organization,
            defaults={
                'billing_plan': BillingPlan.objects.first(),  # Piano di default
                'payment_status': 'paid'
            }
        )
        
        if not created:
            org_billing.payment_status = 'paid'
            org_billing.save()
        
        # Cerca la fattura più recente per questa organizzazione
        latest_invoice = Invoice.objects.filter(
            organization_billing=org_billing
        ).order_by('-created_at').first()
        
        if latest_invoice and latest_invoice.status != 'paid':
            # Aggiorna la fattura esistente
            latest_invoice.status = 'paid'
            latest_invoice.save()
            message = f'Pagamento registrato per la fattura {latest_invoice.invoice_number} di {organization.name}'
        else:
            # Crea una nuova fattura se non esiste o se l'ultima è già pagata
            from datetime import date
            today = date.today()
            
            new_invoice = Invoice.objects.create(
                organization_billing=org_billing,
                billing_period_start=today.replace(day=1),
                billing_period_end=today,
                base_amount=org_billing.get_monthly_cost(),
                user_amount=0,
                total_amount=org_billing.get_monthly_cost(),
                user_count=organization.user_profiles.count(),
                due_date=today,
                status='paid'
            )
            message = f'Nuovo pagamento registrato per {organization.name} - Fattura {new_invoice.invoice_number}'
        
        return JsonResponse({
            'success': True, 
            'message': message
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
def invoice_detail(request, invoice_id):
    """Dettaglio di una singola fattura"""
    invoice = get_object_or_404(Invoice, id=invoice_id)
    
    # Verifica che l'utente abbia i permessi
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permessi insufficienti'}, status=403)
    
    context = {
        'invoice': invoice,
        'organization': invoice.organization_billing.organization,
        'billing_config': invoice.organization_billing,
    }
    
    return render(request, 'Cripto1/finance/invoice_detail.html', context)