import os
from pathlib import Path  # AGGIUNGERE QUESTA RIGA
# from django.core.checks import Debug
from dotenv import load_dotenv
import dj_database_url

# Carica le variabili d'ambiente dal file .env
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# Configurazioni di sicurezza da variabili d'ambiente
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
FERNET_KEY = os.getenv('FERNET_KEY').encode() if os.getenv('FERNET_KEY') else None
FIELD_ENCRYPTION_KEY = os.getenv('FIELD_ENCRYPTION_KEY').encode() if os.getenv('FIELD_ENCRYPTION_KEY') else None

# Validazione chiavi obbligatorie
if not SECRET_KEY:
    raise ValueError("SECRET_KEY deve essere definita nel file .env")
if not FERNET_KEY:
    raise ValueError("FERNET_KEY deve essere definita nel file .env")
if not FIELD_ENCRYPTION_KEY:
    raise ValueError("FIELD_ENCRYPTION_KEY deve essere definita nel file .env")

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'encrypted_model_fields',
    'Cripto1'
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
    'Cripto1.middleware.FileSizeMiddleware',
    'Cripto1.middleware.SmartAutoCleanupMiddleware',
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
                'Cripto1.context_processors.organization_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'Cripto.wsgi.application'

# Database configuration
if os.getenv("DATABASE_URL"):
    # Produzione (Render)
    DATABASES = {
        "default": dj_database_url.config(
            default=os.getenv("DATABASE_URL"),
            conn_max_age=600,
            ssl_require=True,
        )
    }
else:
    # Sviluppo locale
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv('DB_NAME'),
            "USER": os.getenv('DB_USER'),
            "PASSWORD": os.getenv('DB_PASSWORD'),
            "HOST": os.getenv('DB_HOST', 'localhost'),
            "PORT": os.getenv('DB_PORT', '5432'),
            "OPTIONS": {
                "sslmode": "prefer",
                "options": "-c default_transaction_isolation=serializable"
            },
        }
    }

# Header di sicurezza
SECURE_SSL_REDIRECT = not DEBUG  # Cambiato da 'Debug' a 'DEBUG'
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Session security
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

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

LANGUAGE_CODE = 'it-it'
TIME_ZONE = 'Europe/Rome'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'Cripto1', 'static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login URLs
LOGIN_URL = 'Cripto1:login'
LOGIN_REDIRECT_URL = 'Cripto1:dashboard'
LOGOUT_REDIRECT_URL = 'Cripto1:login'

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Error pages
HANDLER403 = 'Cripto1.views.permission_denied'

# Email configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# Email Configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_USE_SSL = os.getenv('EMAIL_USE_SSL', 'False').lower() == 'true'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = f'FortySeal <{EMAIL_HOST_USER}>'
SERVER_EMAIL = EMAIL_HOST_USER

# Site Configuration
SITE_URL = os.getenv('SITE_URL', 'http://127.0.0.1:8000')

# Cache configuration
# Migliorare la configurazione cache per produzione
if not DEBUG:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/1'),
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
        }
    }

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'Cripto1': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Aggiungi dopo le configurazioni esistenti

# Security headers aggiuntivi
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_TZ = True

# Limita upload file
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10MB

# Rate limiting
SESSION_COOKIE_AGE = 3600  # 1 ora

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
