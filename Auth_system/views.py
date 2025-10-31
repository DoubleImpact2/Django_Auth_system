from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication


class HomeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        content = {'message': 'Hello, World!'}
        return Response(content)


def home(request):
    return render(request, "home.html")


def register(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        # --- Validation ---
        if not all([first_name, last_name, username, email, password1, password2]):
            messages.error(request, "All fields are required.")
            return redirect("register")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        # --- Create user ---
        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=password1
        )

        # --- Auto login after registration ---
        login(request, user)
        messages.success(request, "Account created successfully!")
        return redirect("dashboard")

    return render(request, "register.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login successful!")
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("login")

    return render(request, "login.html")


def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("home")


@login_required(login_url="login")
def dashboard(request):
    return render(request, "dashboard.html")
