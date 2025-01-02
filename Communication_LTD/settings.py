from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "django-insecure-gl=b&u71jf7ix(s^b^+y8^!eiubw&i43$r+l%)yhw#!fju)(p@"

DEBUG = True

ALLOWED_HOSTS = []

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "users",  # האפליקציה users
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "Communication_LTD.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / 'templates'],  # תיקיית templates
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.i18n",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "Communication_LTD.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_USER_MODEL = 'users.User'

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},  # אורך סיסמה מינימלי
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "he"

TIME_ZONE = "Asia/Jerusalem"

USE_I18N = True

USE_TZ = True

STATIC_URL = "static/"

# הוספת לוגיקה לנתיב LOGOUT
LOGOUT_REDIRECT_URL = 'login'  # מפנה לדף הלוגין לאחר התנתקות

# הוספת URL ברירת מחדל למקרה שאין למשתמש הרשאות
LOGIN_URL = '/login/'

# נתיב לדף הבית לאחר התחברות
LOGIN_REDIRECT_URL = '/'  # דף הבית לאחר התחברות

# הוספת מייל לשליחת טוקנים
DEFAULT_FROM_EMAIL = 'no-reply@communication_ltd.com'  # כתובת המייל לשליחת טוקנים

# הגדרות SMTP לשליחת מיילים
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'  # שרת ה-SMTP של Gmail
EMAIL_PORT = 587  # פורט TLS
EMAIL_USE_TLS = True  # השתמש ב-TLS לאבטחה
EMAIL_HOST_USER = 'communication.ltd001@gmail.com'  # כתובת המייל שלך ב-Gmail
EMAIL_HOST_PASSWORD = 'Aa123456789!'  # הסיסמה שלך ל-Gmail
DEFAULT_FROM_EMAIL = 'communication.ltd001@gmail.com'  # כתובת השולח שתופיע במיילים

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# הוספת הנתיב של קובץ הקונפיגורציה לניהול סיסמאות
PASSWORD_CONFIG_PATH = BASE_DIR / 'password_config.json'
