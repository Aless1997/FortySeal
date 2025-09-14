import os
from pathlib import Path
import dj_database_url
import django
from django.core.management import call_command
import sys

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-your-secret-key-here'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'block-lxlw.onrender.com', 'fortyseal-1.onrender.com']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'encrypted_model_fields',
    'Cripto1' #Installed 25/05/2025
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'Cripto1.middleware.MultiTenantMiddleware',
    'Cripto1.middleware.AuditLogMiddleware',
    'Cripto1.middleware.SecurityMiddleware',
    'Cripto1.middleware.SmartAutoCleanupMiddleware',  # RIATTIVATO
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'Cripto1.middleware.RoleExpirationMiddleware',
]

ROOT_URLCONF = 'Cripto.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'Cripto' / 'Cripto1' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'Cripto1.context_processors.organization_context',  # Context processor per multi-tenancy
            ],
        },
    },
]

WSGI_APPLICATION = 'Cripto.wsgi.application'

if os.getenv("DATABASE_URL"):
    # 🔹 Produzione (Render) → prende tutto da DATABASE_URL
    DATABASES = {
        "default": dj_database_url.config(
            default=os.getenv("DATABASE_URL"),
            conn_max_age=600,
            ssl_require=True,
        )
    }
else:
    # 🔹 Locale (sviluppo) → usa i parametri fissi
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": "forty_seal",
            "USER": "forty_admin",
            "PASSWORD": "123",
            "HOST": "localhost",
            "PORT": "5432",
            "OPTIONS": {
                "sslmode": "prefer",
            },
        }
    }

# Configurazione per ambiente di produzione (Heroku, etc.)
import os
if os.environ.get('DATABASE_URL'):
    import dj_database_url
    DATABASES['default'] = dj_database_url.parse(os.environ.get('DATABASE_URL'))


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'it-it'

TIME_ZONE = 'Europe/Rome'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login URL
LOGIN_URL = 'Cripto1:login'
LOGIN_REDIRECT_URL = 'Cripto1:dashboard'
LOGOUT_REDIRECT_URL = 'Cripto1:login'
FERNET_KEY = b'JelaY1G0OlEEPMOnb-q9jVuxr88GAUiyzWD4u4fgEUs='

# Encryption key for encrypted model fields
FIELD_ENCRYPTION_KEY = b'JelaY1G0OlEEPMOnb-q9jVuxr88GAUiyzWD4u4fgEUs='
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Error pages
HANDLER403 = 'Cripto1.views.permission_denied'

import sentry_sdk

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'sealforty@gmail.com'  # Sostituisci con la tua email
EMAIL_HOST_PASSWORD = 'sssw jaei ppqg tbuy'  # Usa una App Password di Google
DEFAULT_FROM_EMAIL = 'FortySeal <sealforty@gmail.com>'
SERVER_EMAIL = 'sealforty@gmail.com'

# URL del sito per le email
#SITE_URL = 'http://127.0.0.1:8000'  # Per sviluppo locale
SITE_URL = 'https://fortyseal-1.onrender.com'  # Per produzione


# Ottimizzazioni PostgreSQL per applicazioni blockchain
if 'postgresql' in DATABASES['default']['ENGINE']:
    # Parametri di connessione corretti
    DATABASES['default'].update({
        'CONN_MAX_AGE': 600,  # Riutilizzo connessioni per 10 minuti
        'OPTIONS': {
            'sslmode': 'prefer',
            'options': '-c default_transaction_isolation=serializable'  # Per integrità blockchain
        },
    })
    
# Configurazione cache per PostgreSQL
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'cache_table',
    }
}
# Configurazione cache alternativa (in memoria)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Mantieni solo:
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
