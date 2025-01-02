from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import json
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import RegisterForm, CustomerForm
import random
import hashlib
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password, check_password
import re
from django.core.exceptions import ValidationError


# קריאת הגדרות הקונפיגורציה מקובץ JSON
with open(settings.BASE_DIR / 'password_config.json', 'r') as f:
    config = json.load(f)

# קריאת המילון החיצוני
with open('data/wordlist.txt', 'r') as f:
    common_passwords = set(line.strip().lower() for line in f.readlines())

# UserManager for creating and managing users
class UserManager(BaseUserManager):
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


# User model using custom manager
class User(AbstractBaseUser):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    reset_token = models.CharField(max_length=100, blank=True, null=True)  # Token for password reset
    password_history = models.JSONField(default=list)  # Store password history
    login_attempts = models.IntegerField(default=0)  # Login attempt field

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def set_password(self, raw_password):
        """Override set_password to use hashed password with password history."""
        if raw_password:
            # Validate password strength according to requirements
            self.validate_password_strength(raw_password)

            # Generate the hashed password
            hashed_password = make_password(raw_password)  # Use Django's built-in password hashing

            # Check if the new password matches the recent password history
            if any(check_password(raw_password, old) for old in self.password_history[-config["password_history"]:]):
                raise ValueError("Password cannot match the last 3 passwords.")
            
            # Update password and history
            self.password = hashed_password
            self.password_history.append(hashed_password)
            self.password_history = self.password_history[-config["password_history"]:]

    def check_password(self, raw_password):
        """Verify the user's password."""
        if not self.password:
            return False
        return check_password(raw_password, self.password)

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

        # If dictionary check is enabled, prevent common passwords
        if config["dictionary_check"]:
            password_lower = password.lower()  # Convert the password to lowercase for case-insensitive comparison
            if password_lower in common_passwords:
                raise ValidationError("Password cannot be a common password.")

    def __str__(self):
        return self.username

    @property
    def is_staff(self):
        """Check if the user has admin privileges."""
        return self.is_admin


# Login, registration, and password reset views (same as before)
def send_reset_email(user):
    """Send reset email with the generated token."""
    token = user.reset_token
    subject = "Password Reset Request"
    message = f"Use the following token to reset your password: {token}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

def user_login(request):
    """Handle user login"""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Attempt to get the user
        user = User.objects.filter(username=username).first()

        if user:
            # Check if login attempts exceed max allowed, lock account or show message
            if user.login_attempts >= config["max_login_attempts"]:
                messages.error(request, "Your account is locked due to too many failed login attempts.")
                return render(request, 'users/login.html')

            # Authenticate user
            authenticated_user = authenticate(request, username=username, password=password)
            if authenticated_user is not None:
                django_login(request, authenticated_user)
                authenticated_user.login_attempts = 0  # Reset the login attempts after successful login
                authenticated_user.save()
                messages.success(request, "Logged in successfully!")
                return redirect('home')
            else:
                # Increment login attempts on failure
                user.login_attempts += 1
                user.save()
                messages.error(request, "Invalid username or password. Please try again.")
        else:
            messages.error(request, "Invalid username or password. Please try again.")

    return render(request, 'users/login.html')

def register(request):
    """Handle user registration"""
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            
            # Check if the password is common or invalid
            if password.lower() in common_passwords:  # common_passwords is the set of common passwords
                messages.error(request, "Password cannot be a common password.")
                return render(request, 'users/register.html', {'form': form})

            # Continue with registration if password is valid
            form.save()
            messages.success(request, "Registration successful. Please log in.")
            return redirect('login')
        else:
            messages.error(request, "There was an error in your registration. Please correct the errors below.")
    else:
        form = RegisterForm()

    return render(request, 'users/register.html', {'form': form})

@login_required
def home(request):
    """Render the home page"""
    return render(request, 'users/home.html')

class CustomPasswordChangeView(PasswordChangeView):
    """Custom view for handling password change"""
    template_name = 'users/password_change.html'
    success_url = reverse_lazy('password_change_done')

    def form_valid(self, form):
        """Update the session after password change"""
        response = super().form_valid(form)
        update_session_auth_hash(self.request, form.user)
        messages.success(self.request, "Your password was changed successfully.")
        return response

@login_required
def password_change_done(request):
    """Display password change success message"""
    return render(request, 'users/password_change_done.html')

@login_required
def create_customer(request):
    """Handle creating a new customer"""
    if request.method == 'POST':
        form = CustomerForm(request.POST)
        if form.is_valid():
            customer = form.save()
            messages.success(request, f"Customer {customer.firstname} {customer.lastname} added successfully!")
            return redirect('home')
        else:
            messages.error(request, "Error in creating customer. Please check the form fields.")
    else:
        form = CustomerForm()

    return render(request, 'users/create_customer.html', {'form': form})

def forgot_password(request):
    """Handle forgot password functionality"""
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # Generate reset token
            random_value = f"{random.randint(1000, 9999)}{user.username}"
            reset_token = hashlib.sha1(random_value.encode()).hexdigest()
            user.reset_token = reset_token
            user.save()
            
            # Send reset token to email
            send_reset_email(user)
            
            messages.success(request, "Reset token sent to your email.")
        except User.DoesNotExist:
            messages.error(request, "No user found with this email.")
    return render(request, 'users/forgot_password.html')

def validate_password(password):
    """Check if the password meets the requirements."""
    if len(password) < 10:
        return False
    if not re.search(r'[A-Z]', password):  # Uppercase letter
        return False
    if not re.search(r'[a-z]', password):  # Lowercase letter
        return False
    if not re.search(r'[0-9]', password):  # Digit
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Special character
        return False
    return True

def reset_password(request):
    """Handle reset password functionality"""
    if request.method == 'POST':
        token = request.POST.get('token')
        new_password = request.POST.get('new_password')
        try:
            user = User.objects.get(reset_token=token)
            if validate_password(new_password):
                user.set_password(new_password)
                user.reset_token = None  # Clear the reset token
                user.save()
                messages.success(request, "Password reset successfully.")
                return redirect('login')
            else:
                messages.error(request, "Password does not meet the requirements.")
        except User.DoesNotExist:
            messages.error(request, "Invalid reset token.")
    return render(request, 'users/reset_password.html')
