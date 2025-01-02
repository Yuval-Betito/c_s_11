import hashlib
import secrets  # השתמש ב-secrets כדי ליצור ערך אקראי
import re  # ייבוא מודול regex לצורך החיפושים
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as django_login
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from .forms import RegisterForm, CustomerForm
from .models import User

# פונקציה לשליחת המייל עם הטוקן
def send_reset_email(user):
    """Send reset email with the generated token."""
    token = user.reset_token
    subject = "Password Reset Request"
    message = f"Use the following token to reset your password: {token}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

def forgot_password(request):
    """Handle forgot password functionality"""
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            # Generate reset token
            random_value = secrets.token_hex(16) + user.username  # יצירת ערך אקראי באמצעות secrets
            reset_token = hashlib.sha1(random_value.encode()).hexdigest()  # המרה ל-SHA-1
            user.reset_token = reset_token
            user.save()
            
            # Send reset token to email
            send_reset_email(user)
            
            messages.success(request, "Reset token sent to your email.")
        except User.DoesNotExist:
            messages.error(request, "No user found with this email.")
    return render(request, 'users/forgot_password.html')

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

def validate_password(password):
    """Check if the password meets the requirements."""
    if len(password) < 10:
        raise ValidationError("Password must be at least 10 characters long.")
    if not re.search(r'[A-Z]', password):  # Uppercase letter
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):  # Lowercase letter
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):  # Digit
        raise ValidationError("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Special character
        raise ValidationError("Password must contain at least one special character.")
    return True  # If the password passes all checks, return True
