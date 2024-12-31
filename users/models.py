import os
import hmac
import hashlib
import re
import json
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator

# קריאת הגדרות הקונפיגורציה מקובץ JSON
with open('password_config.json') as f:
    config = json.load(f)


class UserManager(BaseUserManager):
    """Custom manager for User model."""
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError("Users must have an email address.")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email)
        if password:
            user.set_password(password)  # Use the customized password hashing
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        """Create a superuser with admin privileges."""
        user = self.create_user(username, email, password)
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    """Custom User model with HMAC + Salt for password handling."""
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    reset_token = models.CharField(max_length=100, blank=True, null=True)  # Token for password reset
    password_history = models.JSONField(default=list)  # שדה לשמירת היסטוריית סיסמאות

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def set_password(self, raw_password):
        """Override set_password to use HMAC + Salt and update password history."""
        if raw_password:
            # Validate password strength according to requirements
            self.validate_password_strength(raw_password)

            salt = os.urandom(16).hex()  # Generate a random Salt
            hashed_password = hmac.new(salt.encode(), raw_password.encode(), hashlib.sha256).hexdigest()
            new_password = f'{salt}${hashed_password}'  # Save salt and hash in the format: salt$hashed_password
            
            # Check if the new password matches the recent password history
            if any(hmac.compare_digest(old.split('$')[1], hashed_password) for old in self.password_history[-config["password_history"]:]):
                raise ValueError("Password cannot match the last 3 passwords.")
            
            # Update password and history
            self.password = new_password
            self.password_history.append(new_password)
            self.password_history = self.password_history[-config["password_history"]:]

    def check_password(self, raw_password):
        """Verify the user's password."""
        if not self.password:
            return False
        try:
            salt, stored_hash = self.password.split('$')
            entered_hash = hmac.new(salt.encode(), raw_password.encode(), hashlib.sha256).hexdigest()
            return stored_hash == entered_hash
        except ValueError:
            return False

    def validate_password_strength(self, password):
        """Ensure password meets all strength requirements."""
        if len(password) < config["min_password_length"]:
            raise ValidationError(f"Password must be at least {config['min_password_length']} characters long.")
        
        if config["password_requirements"]["uppercase"] and not any(c.isupper() for c in password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        if config["password_requirements"]["lowercase"] and not any(c.islower() for c in password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        if config["password_requirements"]["digits"] and not any(c.isdigit() for c in password):
            raise ValidationError("Password must contain at least one digit.")
        
        if config["password_requirements"]["special_characters"] and not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
            raise ValidationError("Password must contain at least one special character.")

        # אם נדרש מניעת מילים מתוך מילון, נוכל לבדוק את הסיסמה במילון (תוכנית חיצונית או רשימה מוגדרת)
        if config["dictionary_check"]:
            # לדוגמה, נוודא שהסיסמה לא כוללת את המילים השכיחות ביותר:
            common_passwords = ["123456", "password", "qwerty"]  # דוגמה
            if password in common_passwords:
                raise ValidationError("Password cannot be a common password.")
        
    def __str__(self):
        return self.username

    @property
    def is_staff(self):
        """Check if the user has admin privileges."""
        return self.is_admin


class Customer(models.Model):
    """Model for storing customer details."""
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    customer_id = models.CharField(max_length=10, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    phone_number = models.CharField(
        max_length=10,
        validators=[RegexValidator(r'^\d{10}$', message="Phone number must be 10 digits.")],
    )

    def __str__(self):
        return f"{self.firstname} {self.lastname}"
