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
from .models import User
import hashlib
import random
import re
from django.core.mail import send_mail

# קריאת הגדרות הקונפיגורציה מקובץ JSON
with open(settings.BASE_DIR / 'password_config.json', 'r') as f:
    config = json.load(f)

# קריאת המילון החיצוני
with open('data/wordlist.txt', 'r') as f:
    common_passwords = set(line.strip().lower() for line in f.readlines())

# פונקציה לשליחת המייל עם הטוקן
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

        try:
            user = User.objects.get(username=username)
            # If login attempts exceed max allowed, lock account or show message
            if user.login_attempts >= config["max_login_attempts"]:
                messages.error(request, "Your account is locked due to too many failed login attempts.")
                return render(request, 'users/login.html')

            # Authenticate user
            user = authenticate(request, username=username, password=password)
            if user is not None:
                django_login(request, user)
                user.login_attempts = 0  # Reset the login attempts after successful login
                user.save()
                messages.success(request, "Logged in successfully!")
                return redirect('home')
            else:
                user.login_attempts += 1  # Increment login attempts on failure
                user.save()
                messages.error(request, "Invalid username or password. Please try again.")
        except User.DoesNotExist:
            messages.error(request, "User does not exist.")
            
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
