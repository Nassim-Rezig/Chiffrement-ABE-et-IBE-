from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import UserPassesTestMixin
from django.views.generic import CreateView, ListView,UpdateView
from django.urls import reverse_lazy
from .forms import LaborantinForm, LoginForm, MedecinForm, PatientForm, RadiologueForm, UserCreationForm
from .models import User
from django.contrib import messages
from .real_abe_cipher import decrypt_attribute 
from .config_abe import ibe_decrypt

import json



class CustomLoginView(LoginView):
    form_class = LoginForm
    template_name = 'accounts/login.html'

@login_required
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

# ... existing code ...

PROFILE_FORMS = {
    'patient': PatientForm,
    'medecin': MedecinForm,
    'radiologue': RadiologueForm,
    'laborantin': LaborantinForm,
}

class UserCreateView(UserPassesTestMixin, CreateView):
    model = User
    form_class = UserCreationForm
    template_name = 'accounts/user_form.html'
    success_url = reverse_lazy('user_list')

    def test_func(self):
        # Seuls admins, médecins et praticiens peuvent créer des utilisateurs
        return self.request.user.is_admin or self.request.user.is_medecin or self.request.user.is_praticien

    def dispatch(self, request, *args, **kwargs):
        # Récupère le type de profil dans l'URL ; par défaut, "user" signifie sans profil additionnel
        self.profile_type = kwargs.get('profile_type', 'user')
        if self.profile_type != 'user' and self.profile_type not in PROFILE_FORMS:
            raise Http404("Type de profil non trouvé.")
        if self.profile_type != 'user':
            self.profile_form_class = PROFILE_FORMS[self.profile_type]
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Si le profil n'est pas "user", ajouter le formulaire spécifique en lui passant éventuellement l'utilisateur
        if self.profile_type != 'user':
            if self.request.POST:
                # On pourra par exemple passer l'utilisateur ici si nécessaire
                context['profile_form'] = self.profile_form_class(self.request.POST, user=self.request.user)
            else:
                context['profile_form'] = self.profile_form_class(user=self.request.user)
        context['profile_type'] = self.profile_type
        return context

    def form_valid(self, form):
        # Création de l'utilisateur
        user = form.save(commit=False)
        user.created_by = self.request.user

        # Vérification des permissions de création
        if (self.request.user.is_medecin or self.request.user.is_praticien) and user.role != 'PATIENT':
            messages.error(self.request, "Vous ne pouvez créer que des patients.")
            return self.form_invalid(form)
        if self.request.user.is_radiologue or self.request.user.is_laborantin:
            messages.error(self.request, "Vous n'avez pas les permissions pour créer des utilisateurs.")
            return self.form_invalid(form)
        user.save()

        # Si un profil additionnel doit être créé, le traiter
        if self.profile_type != 'user':
            # On passe l'utilisateur nouvellement créé au formulaire de profil
            profile_form = self.profile_form_class(self.request.POST, user=user)
            if profile_form.is_valid():
                profile = profile_form.save(commit=False)
                profile.user = user
                profile.save()
            else:
                messages.error(self.request, "Erreur lors de la création du profil.")
                return self.form_invalid(form)

        if self.profile_type != 'user':
            messages.success(
                self.request,
                f"L'utilisateur {user.email} et son profil {self.profile_type} ont été créés avec succès."
            )
        else:
            messages.success(
                self.request,
                f"L'utilisateur {user.email} a été créé avec succès."
            )
        return super().form_valid(form)


# ... existing code ...

    from django.contrib.auth import logout
    from django.shortcuts import redirect

    # Add this to your existing views.py file
from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    # Clear any session data
    request.session.flush()
    # Redirect to login page
    return redirect('login')
# ... existing code ...

class UserListView(UserPassesTestMixin, ListView):
    model = User
    template_name = 'accounts/user_list.html'
    context_object_name = 'users'
    
    def test_func(self):
        # Définir qui peut voir la liste des utilisateurs
        return (self.request.user.is_admin or 
                self.request.user.is_medecin or 
                self.request.user.is_radiologue or 
                self.request.user.is_laborantin or 
                self.request.user.is_praticien)
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filtrer selon le rôle
        if self.request.user.is_medecin:
            # Les médecins voient tous les patients
            return queryset.filter(role='PATIENT')
        elif self.request.user.is_radiologue:
            # Les radiologues voient tous les patients
            return queryset.filter(role='PATIENT')
        elif self.request.user.is_laborantin:
            # Les laborantins voient tous les patients
            return queryset.filter(role='PATIENT')
        elif self.request.user.is_praticien:
            # Les praticiens voient tous les patients
            return queryset.filter(role='PATIENT')
        
        # Les admins voient tout le monde
        return queryset

# ... existing code ...

# ... existing code ...
from django.views.generic.edit import DeleteView
from django.contrib.auth.mixins import UserPassesTestMixin
from django.urls import reverse_lazy

# ... existing code ...

class UserDeleteView(UserPassesTestMixin, DeleteView):
    model = User
    template_name = 'accounts/user_confirm_delete.html'
    success_url = reverse_lazy('user_list')
    
    def test_func(self):
        # Vérifier si l'utilisateur a le droit de supprimer
        user_to_delete = self.get_object()
        
        # L'admin peut supprimer n'importe quel compte
        if self.request.user.is_admin:
            return True
            
        # Un médecin peut supprimer uniquement les patients qu'il a créés
        if self.request.user.is_medecin and user_to_delete.is_patient and user_to_delete.created_by == self.request.user:
            return True
            
        # Un praticien peut supprimer uniquement les patients qu'il a créés
        if self.request.user.is_praticien and user_to_delete.is_patient and user_to_delete.created_by == self.request.user:
            return True
            
        return False
    
    def delete(self, request, *args, **kwargs):
        user_to_delete = self.get_object()
        messages.success(request, f"L'utilisateur {user_to_delete.email} a été supprimé avec succès.")
        return super().delete(request, *args, **kwargs)
    



from django.views.generic import DetailView
from django.contrib.auth.mixins import UserPassesTestMixin
from django.shortcuts import get_object_or_404
from django.http import Http404, HttpResponseForbidden

from .models import User, Patient, Medecin, Radiologue, Laborantin


class UserDetailView(UserPassesTestMixin, DetailView):
    model = User
    template_name = 'accounts/user_detail.html'
    context_object_name = 'user_object'  # Pour éviter la confusion avec request.user

    def test_func(self):
        user_to_view = self.get_object()
        # Autorisations : admin, utilisateur lui-même ou professionnels de santé
        if self.request.user.is_admin:
            return True
        if self.request.user == user_to_view:
            return True
        if (self.request.user.is_medecin or self.request.user.is_praticien or
            self.request.user.is_radiologue or self.request.user.is_laborantin):
            return True
        return False

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_object = self.get_object()

        # Ajout des attributs d'utilisateur (exemple)
        user_attributes = []
        if self.request.user.is_admin:
            user_attributes.append("ADMIN")
        if self.request.user.is_medecin:
            user_attributes.append("MEDECIN")
        if self.request.user.is_praticien:
            user_attributes.append("PRATICIEN")
        if self.request.user.is_radiologue:
            user_attributes.append("RADIOLOGUE")
        if self.request.user.is_laborantin:
            user_attributes.append("LABORANTIN")

        # Si l'utilisateur affiché est un patient avec un profil patient, tenter de déchiffrer l'assurance
        if user_object.is_patient and hasattr(user_object, 'patient_profile'):
            patient_profile = user_object.patient_profile
            context['profile'] = patient_profile

            encrypted_insurance = patient_profile.encrypted_insurance

            if encrypted_insurance:
                print("Contenu brut de encrypted_insurance:", encrypted_insurance)
            else:
                print("Aucune donnée d'assurance chiffrée trouvée.")

            try:
                # Ici, nous utilisons l'email de l'utilisateur comme identité
                insurance_number_decrypted = ibe_decrypt(encrypted_insurance, user_object.email)
                print("Déchiffrement réussi, résultat :", insurance_number_decrypted)
            except Exception as e:
                insurance_number_decrypted = f"Erreur lors du déchiffrement : {str(e)}"
                print(insurance_number_decrypted)

            context['insurance_number_decrypted'] = insurance_number_decrypted

        return context



        


class UserUpdateView(UserPassesTestMixin, UpdateView):
        model = User
        form_class = UserCreationForm  # Remplacez par UserUpdateForm si disponible
        template_name = 'accounts/user_form.html'
        success_url = reverse_lazy('user_list')

        def test_func(self):
            # Seuls admins, médecins et praticiens peuvent modifier des utilisateurs
            return self.request.user.is_admin or self.request.user.is_medecin or self.request.user.is_praticien

        def dispatch(self, request, *args, **kwargs):
            # Récupère le type de profil dans l'URL ; par défaut, "user" signifie sans profil additionnel
            self.profile_type = kwargs.get('profile_type', 'user')
            if self.profile_type != 'user' and self.profile_type not in PROFILE_FORMS:
                raise Http404("Type de profil non trouvé.")
            if self.profile_type != 'user':
                self.profile_form_class = PROFILE_FORMS[self.profile_type]
            return super().dispatch(request, *args, **kwargs)

        def get_context_data(self, **kwargs):
            context = super().get_context_data(**kwargs)
            # Si un profil additionnel doit être modifié, récupérez l'instance correspondante
            if self.profile_type != 'user':
                if self.request.POST:
                    context['profile_form'] = self.profile_form_class(
                        self.request.POST,
                        instance=getattr(self.object, f"{self.profile_type.lower()}_profile", None)
                    )
                else:
                    context['profile_form'] = self.profile_form_class(
                        instance=getattr(self.object, f"{self.profile_type.lower()}_profile", None)
                    )
            context['profile_type'] = self.profile_type
            return context

        def form_valid(self, form):
            user = form.save(commit=False)
            user.created_by = self.request.user

            # Vérification des permissions (exemple, ajustez si nécessaire)
            if (self.request.user.is_medecin or self.request.user.is_praticien) and user.role != 'PATIENT':
                messages.error(self.request, "Vous ne pouvez modifier que des patients.")
                return self.form_invalid(form)
            if self.request.user.is_radiologue or self.request.user.is_laborantin:
                messages.error(self.request, "Vous n'avez pas les permissions pour modifier des utilisateurs.")
                return self.form_invalid(form)

            user.save()

            # Mise à jour du profil additionnel s'il existe
            if self.profile_type != 'user':
                try:
                    profile_instance = getattr(user, f"{self.profile_type.lower()}_profile")
                except AttributeError:
                    profile_instance = None

                profile_form = self.profile_form_class(self.request.POST, instance=profile_instance)
                if profile_form.is_valid():
                    profile = profile_form.save(commit=False)
                    profile.user = user
                    profile.save()
                else:
                    messages.error(self.request, "Erreur lors de la modification du profil.")
                    return self.form_invalid(form)

            if self.profile_type != 'user':
                messages.success(
                    self.request,
                    f"L'utilisateur {user.email} et son profil {self.profile_type} ont été modifiés avec succès."
                )
            else:
                messages.success(
                    self.request,
                    f"L'utilisateur {user.email} a été modifié avec succès."
                )
            return super().form_valid(form)