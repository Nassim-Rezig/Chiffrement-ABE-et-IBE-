from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import ABEKey, Consultation, Laborantin, Medecin, MedicalRecord, Prescription, Radiologue, User,Patient
import base64
import json
import os

from .config_abe import ibe_encrypt
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
import hashlib
from datetime import datetime
from .config_abe import ibe_encrypt, serialize_ciphertext, group













class LoginForm(AuthenticationForm):
    username = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Mot de passe'}))

class UserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-control'}))
    first_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'form-control'}))
    role = forms.ChoiceField(choices=User.ROLE_CHOICES, widget=forms.Select(attrs={'class': 'form-control'}))
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'role', 'password1', 'password2')
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})
        
        # Limiter les choix de rôle en fonction de l'utilisateur connecté
        if self.user:
            if self.user.is_medecin or self.user.is_praticien:
                self.fields['role'].choices = [('PATIENT', 'Patient')]
            elif not self.user.is_admin:
                # Pour les autres rôles non-admin, désactiver le champ
                self.fields['role'].disabled = True
    
    def save(self, commit=True):
        user = super().save(commit=False)
        # Set username to be the same as email (or a portion of it)
        # This ensures username is unique since email is unique
        import uuid
        email_prefix = self.cleaned_data['email'].split('@')[0][:20]  # First 20 chars of email
        unique_suffix = str(uuid.uuid4())[:8]  # 8 chars from a UUID
        user.username = f"{email_prefix}_{unique_suffix}"
        
        if commit:
            user.save()
        return user
BLOOD_TYPE_CHOICES = [
            ('A+', 'A+'),
            ('A-', 'A-'),
            ('B+', 'B+'),
            ('B-', 'B-'),
            ('AB+', 'AB+'),
            ('AB-', 'AB-'),
            ('O+', 'O+'),
            ('O-', 'O-'),
        ]
class PatientForm(forms.ModelForm):
    insurance_number = forms.CharField(
        max_length=50, 
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Numéro d\'assurance'}),
        label='Numéro d\'assurance',
        help_text='Ce numéro sera chiffré pour protéger vos données'
    )
    
    class Meta:
        model = Patient
        fields = ['date_of_birth', 'blood_type', 'ibe_policy']
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'blood_type': forms.Select(choices=BLOOD_TYPE_CHOICES, attrs={'class': 'form-control'}),
            'ibe_policy': forms.TextInput(attrs={'class': 'form-control'}),
        }
        labels = {
            'date_of_birth': 'Date de naissance',
            'blood_type': 'Groupe sanguin',
            'ibe_policy': 'Politique ABE',
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def save_patient(self, commit=True):
        patient = super(PatientForm, self).save(commit=False)
        insurance_number = self.cleaned_data.get('insurance_number')
        # Ici, on utilise l'email de l'utilisateur connecté
        email = self.user.email if self.user else None
        if insurance_number and email:
            ibe_ciphertext = ibe_encrypt(insurance_number, email)
            ibe_ciphertext_serialized = serialize_ciphertext(ibe_ciphertext)
            # Stocker le ciphertext sous forme de JSON encodé en UTF-8
            patient.encrypted_insurance = json.dumps(ibe_ciphertext_serialized).encode('utf-8')
            patient.ibe_policy = f'email:{email}'
        # Assigner l'utilisateur au patient
        if self.user:
            patient.user = self.user
        patient.save()
        return patient



# Formulaire pour le profil Médecin
class MedecinForm(forms.ModelForm):
    class Meta:
        model = Medecin
        fields = ['specialization', 'phone_number']

# Formulaire pour le profil Radiologue
class RadiologueForm(forms.ModelForm):
    class Meta:
        model = Radiologue
        fields = ['radiology_field', 'phone_number']

# Formulaire pour le profil Laborantin
class LaborantinForm(forms.ModelForm):
    class Meta:
        model = Laborantin
        fields = ['lab_department', 'phone_number']

# Formulaire pour le Dossier Médical (MedicalRecord)
class MedicalRecordForm(forms.ModelForm):
    class Meta:
        model = MedicalRecord
        # Le patient, les données chiffrées et la politique ABE sont nécessaires.
        fields = ['patient',  'abe_policy']
        # Vous pouvez gérer le champ ManyToMany assigned_to dans le formulaire ou via une vue spécifique.

# Formulaire pour une Consultation
class ConsultationForm(forms.ModelForm):
    class Meta:
        model = Consultation
        # Le patient, les notes chiffrées, la politique ABE et l'indication de suivi.
        fields = ['patient',  'abe_policy', 'follow_up_required']

# Formulaire pour une Ordonnance (Prescription)
class PrescriptionForm(forms.ModelForm):
    class Meta:
        model = Prescription
        fields = ['consultation',  'abe_policy', 'validity_days']

# Formulaire pour une Clé ABE
class ABEKeyForm(forms.ModelForm):
    class Meta:
        model = ABEKey
        fields = ['attributes', 'public_key',  'revoked']