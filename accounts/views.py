from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import UserPassesTestMixin
from django.views.generic import CreateView, ListView, UpdateView, DetailView, DeleteView
from django.urls import reverse_lazy
from django.db import models
from .forms import LaborantinForm, LoginForm, MedecinForm, MedicalRecordForm, PatientForm, RadiologueForm, UserCreationForm
from .models import User, MedicalRecord, Patient, Consultation
from django.contrib import messages
from django.http import Http404, HttpResponseForbidden
from .ibe_config import ibe_decrypt

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
    context_object_name = 'user_object'  # Évite la confusion avec request.user
    

    def test_func(self):
        user_to_view = self.get_object()
        print(f"Utilisateur connecté: {self.request.user}, Profil demandé: {user_to_view}")
        # Autorisations : admin, utilisateur lui-même ou professionnels de santé
        if self.request.user.is_admin:
            return True
        if self.request.user == user_to_view:
            return True
        if (self.request.user.is_medecin or self.request.user.is_praticien or
            self.request.user.is_radiologue or self.request.user.is_laborantin ):
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

        context['user_attributes'] = user_attributes

        # Si l'utilisateur affiché est un patient avec un profil patient, tenter de déchiffrer l'assurance
        if user_object.is_patient and hasattr(user_object, 'patient_profile'):
            patient_profile = user_object.patient_profile
            context['profile'] = patient_profile

            encrypted_insurance = patient_profile.encrypted_insurance

            insurance_number_decrypted = None

            if encrypted_insurance:
                try:
                    
                    insurance_number_decrypted = ibe_decrypt(encrypted_insurance, self.request.user.email)
                except Exception as e:
                    insurance_number_decrypted = f"Erreur lors du déchiffrement : {str(e)}"

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


# Vues pour la gestion des dossiers médicaux
class MedicalRecordListView(UserPassesTestMixin, ListView):
    model = MedicalRecord
    template_name = 'accounts/medical_record_list.html'
    context_object_name = 'medical_records'
    
    def test_func(self):
        # Seuls les médecins, les administrateurs et les praticiens peuvent voir la liste des dossiers médicaux
        return self.request.user.is_admin or self.request.user.is_medecin or self.request.user.is_praticien
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Les médecins voient les dossiers qu'ils ont créés et ceux auxquels ils sont assignés
        if self.request.user.is_medecin:
            return queryset.filter(
                models.Q(creator=self.request.user) | models.Q(assigned_to=self.request.user)
            ).distinct()
        
        # Les administrateurs voient tous les dossiers
        return queryset


class MedicalRecordDetailView(UserPassesTestMixin, DetailView):
    model = MedicalRecord
    template_name = 'accounts/medical_record_detail.html'
    context_object_name = 'record'
    
    def test_func(self):
        record = self.get_object()
        # Vérifier si l'utilisateur a le droit de voir ce dossier
        if self.request.user.is_admin:
            return True
        if self.request.user == record.creator:
            return True
        if self.request.user in record.assigned_to.all():
            return True
        return False
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        record = self.get_object()
        
        # Tenter de déchiffrer les données médicales
        decrypted_data = None
        try:
            # Ici, vous devriez utiliser la fonction de déchiffrement ABE appropriée
            # Cette partie dépend de votre implémentation du chiffrement ABE
            # decrypted_data = abe_decrypt(record.encrypted_data, self.request.user)
            decrypted_data = "Données médicales déchiffrées seraient affichées ici."
        except Exception as e:
            decrypted_data = None
        
        context['decrypted_data'] = decrypted_data
        
        # Récupérer les consultations associées au patient
        context['consultations'] = Consultation.objects.filter(patient=record.patient)
        
        # Tenter de déchiffrer le numéro d'assurance du patient
        insurance_number_decrypted = None
        if record.patient.encrypted_insurance:
            try:
                insurance_number_decrypted = ibe_decrypt(record.patient.encrypted_insurance, record.patient.user.email)
            except Exception as e:
                insurance_number_decrypted = None
        
        context['insurance_number_decrypted'] = insurance_number_decrypted
        
        return context


class MedicalRecordCreateView(UserPassesTestMixin, CreateView):
    model = MedicalRecord
    form_class = MedicalRecordForm
    template_name = 'accounts/medical_record_form.html'
    success_url = reverse_lazy('medical_record_list')
    
    def test_func(self):
        # Seuls les médecins et les administrateurs peuvent créer des dossiers médicaux
        return self.request.user.is_admin or self.request.user.is_medecin
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Récupérer tous les professionnels de santé pour l'assignation
        context['professionals'] = User.objects.filter(
            models.Q(role='MEDECIN') | models.Q(role='RADIOLOGUE') | 
            models.Q(role='LABORANTIN') | models.Q(role='PRATICIEN')
        )
        return context
    
    def form_valid(self, form):
        record = form.save(commit=False)
        record.creator = self.request.user
        
        # Récupérer les données médicales à chiffrer
        medical_data = self.request.POST.get('medical_data', '')
        
        # Ici, vous devriez utiliser la fonction de chiffrement ABE appropriée
        # Cette partie dépend de votre implémentation du chiffrement ABE
        # encrypted_data = abe_encrypt(medical_data, record.abe_policy)
        # record.encrypted_data = encrypted_data
        
        # Pour l'exemple, nous stockons simplement les données en clair
        # Dans une vraie implémentation, vous devriez les chiffrer
        record.encrypted_data = medical_data.encode('utf-8')
        
        record.save()
        
        # Gérer les professionnels assignés
        assigned_professionals = self.request.POST.getlist('assigned_to')
        record.assigned_to.set(assigned_professionals)
        
        messages.success(self.request, "Le dossier médical a été créé avec succès.")
        return super().form_valid(form)


class MedicalRecordUpdateView(UserPassesTestMixin, UpdateView):
    model = MedicalRecord
    form_class = MedicalRecordForm
    template_name = 'accounts/medical_record_form.html'
    context_object_name = 'record'
    
    def test_func(self):
        record = self.get_object()
        # Vérifier si l'utilisateur a le droit de modifier ce dossier
        if self.request.user.is_admin:
            return True
        if self.request.user == record.creator:
            return True
        return False
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        record = self.get_object()
        
        # Récupérer tous les professionnels de santé pour l'assignation
        context['professionals'] = User.objects.filter(
            models.Q(role='MEDECIN') | models.Q(role='RADIOLOGUE') | 
            models.Q(role='LABORANTIN') | models.Q(role='PRATICIEN')
        )
        
        # Tenter de déchiffrer les données médicales pour les afficher dans le formulaire
        try:
            # Ici, vous devriez utiliser la fonction de déchiffrement ABE appropriée
            # medical_data = abe_decrypt(record.encrypted_data, self.request.user)
            medical_data = record.encrypted_data.decode('utf-8')  # Pour l'exemple
            context['medical_data'] = medical_data
        except Exception as e:
            context['medical_data'] = ''
            messages.error(self.request, "Impossible de déchiffrer les données médicales.")
        
        return context
    
    def form_valid(self, form):
        record = form.save(commit=False)
        
        # Récupérer les données médicales à chiffrer
        medical_data = self.request.POST.get('medical_data', '')
        
        # Ici, vous devriez utiliser la fonction de chiffrement ABE appropriée
        # encrypted_data = abe_encrypt(medical_data, record.abe_policy)
        # record.encrypted_data = encrypted_data
        
        # Pour l'exemple, nous stockons simplement les données en clair
        record.encrypted_data = medical_data.encode('utf-8')
        
        record.save()
        
        # Gérer les professionnels assignés
        assigned_professionals = self.request.POST.getlist('assigned_to')
        record.assigned_to.set(assigned_professionals)
        
        messages.success(self.request, "Le dossier médical a été mis à jour avec succès.")
        return super().form_valid(form)
    
    def get_success_url(self):
        return reverse_lazy('medical_record_detail', kwargs={'pk': self.object.pk})


class MedicalRecordDeleteView(UserPassesTestMixin, DeleteView):
    model = MedicalRecord
    template_name = 'accounts/medical_record_confirm_delete.html'
    success_url = reverse_lazy('medical_record_list')
    
    def test_func(self):
        record = self.get_object()
        # Vérifier si l'utilisateur a le droit de supprimer ce dossier
        if self.request.user.is_admin:
            return True
        if self.request.user == record.creator:
            return True
        return False
    
    def delete(self, request, *args, **kwargs):
        record = self.get_object()
        messages.success(request, f"Le dossier médical de {record.patient.user.get_full_name()} a été supprimé avec succès.")
        return super().delete(request, *args, **kwargs)