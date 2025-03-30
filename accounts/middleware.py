from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages

class RoleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Liste des URL accessibles à tous les utilisateurs authentifiés
            public_urls = [reverse('dashboard'), reverse('logout')]
            
            # Si l'utilisateur est un patient et qu'il essaie d'accéder à une URL non publique
            if request.user.is_patient and request.path not in public_urls:
                messages.error(request, "Vous n'avez pas les permissions nécessaires pour accéder à cette page.")
                return redirect('dashboard')
                
        return self.get_response(request)