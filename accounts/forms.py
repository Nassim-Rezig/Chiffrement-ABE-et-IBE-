from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import ABEKey, Consultation, Laborantin, Medecin, MedicalRecord, Prescription, Radiologue, User,Patient
import base64
import json
import os
from .ibe_config import ibe_encrypt,serialize_ciphertext
from .abe_config import abe_encrypt





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
    
    def save(self, commit=True):
        patient = super(PatientForm, self).save(commit=False)
        insurance_number = self.cleaned_data.get('insurance_number')
        
        # On utilise l'email de l'utilisateur connecté comme identité IBE
        email = self.user.email if self.user else None
        print("numero d'assurance: ",insurance_number)
        print("email: ",email)

        if insurance_number and email:
            ibe_ciphertext = ibe_encrypt(insurance_number, email)
            ibe_ciphertext_serialized = ibe_ciphertext
            print("we are here 1")

            # Stocker le ciphertext sous forme de JSON encodé en UTF-8
            patient.encrypted_insurance = json.dumps(ibe_ciphertext_serialized).encode('utf-8')
            patient.ibe_policy = f'email:{email}'
            print("we are here 2")

        # Assigner l'utilisateur au patient
        if self.user:
            patient.user = self.user
            print("we are here 3")

        
        patient.save()
        print("we are here 4")
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
    medical_data = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        label='Données médicales',
        help_text='Ces données seront chiffrées pour protéger les informations du patient'
    )
    
    class Meta:
        model = MedicalRecord
        fields = ['patient', 'abe_policy']
        widgets = {
            'patient': forms.Select(attrs={'class': 'form-control'}),
            'abe_policy': forms.TextInput(attrs={'class': 'form-control'}),
        }
        labels = {
            'patient': 'Patient',
            'abe_policy': 'Politique ABE',
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
    
    def save(self, commit=True):
        record = super().save(commit=False)
        medical_data = self.cleaned_data.get('medical_data')
        
        # Chiffrer les données médicales
        if medical_data:
            try:
                # Convertir le contenu (texte) en entier
                message_int = int.from_bytes(medical_data.encode('utf-8'), 'big')
                # Utiliser la politique ABE indiquée dans le formulaire pour le chiffrement
                encrypted_data = abe_encrypt(message_int, record.abe_policy)
                # Stocker le ciphertext (en bytes)
                record.encrypted_data = encrypted_data
            except Exception as e:
                # En cas d'erreur, stocker le message en clair (à éviter en prod)
                record.encrypted_data = medical_data.encode('utf-8')
                print(f"Erreur lors du chiffrement ABE : {e}")
                # Afficher plus de détails sur l'erreur pour le débogage
                import traceback
                print(traceback.format_exc())
        
        if commit:
            record.save()
        return record

# Formulaire pour une Consultation


# Nouveau formulaire pour les ordonnances
class PrescriptionForm(forms.ModelForm):
    content = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        label='Contenu de l\'ordonnance',
        help_text='Ce contenu sera chiffré pour protéger les données du patient'
    )
    patient = forms.ModelChoiceField(
        queryset=Patient.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=False,
        label='Patient'
    )
    
    class Meta:
        model = Prescription
        fields = ['consultation', 'abe_policy', 'validity_days']
        widgets = {
            'consultation': forms.Select(attrs={'class': 'form-control'}),
            'abe_policy': forms.TextInput(attrs={'class': 'form-control'}),
            'validity_days': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
        }
        labels = {
            'consultation': 'Consultation',
            'abe_policy': 'Politique ABE',
            'validity_days': 'Validité (jours)',
        }
    
    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields['consultation'].required = False
    
    def save(self, commit=True):
        prescription = super().save(commit=False)
        content = self.cleaned_data.get('content')
        print("we are here 1")
        # Si aucune consultation n'est sélectionnée mais qu'un patient est choisi,
        # créer une nouvelle consultation
        if not self.cleaned_data.get('consultation') and self.cleaned_data.get('patient') and self.user:
            print("we are here 2")
            # Créer une nouvelle consultation
            consultation = Consultation.objects.create(
                patient=self.cleaned_data['patient'],
                professional=self.user,
                encrypted_notes=b'Consultation pour ordonnance',
                abe_policy=self.cleaned_data['abe_policy']
            )
            print("we are here 3")
            # Assigner explicitement la consultation à l'ordonnance
            prescription.consultation = consultation
            
            # Sauvegarder immédiatement pour établir la relation
            
            print("we are here 4")
            # Éviter une double sauvegarde si commit est True
            
        
        # Chiffrer le contenu de l'ordonnance
        if content:
            try:
                print("we are here 5")
                # Convertir le contenu (texte) en entier
                message_int = int.from_bytes(content.encode('utf-8'), 'big')
                print("le message en entier : ",message_int)
                # Utiliser la politique ABE indiquée dans le formulaire pour le chiffrement
                # La fonction abe_encrypt utilise maintenant serialize_ciphertext pour assurer une sérialisation correcte
                encrypted_content = abe_encrypt(message_int, prescription.abe_policy)
                # Stocker le ciphertext (ici en bytes)
                prescription.encrypted_content = encrypted_content
                print("we are here 6")
            except Exception as e:
                # En cas d'erreur, vous pouvez soit lever une exception, soit stocker le message en clair (à éviter en prod)
                prescription.encrypted_content = content.encode('utf-8')
                print(f"Erreur lors du chiffrement ABE : {e}")
                # Afficher plus de détails sur l'erreur pour le débogage
                import traceback
                print(traceback.format_exc())
        
        if commit:
            prescription.save()
            print("we are here 7")
        return prescription
    




class ConsultationForm(forms.ModelForm):
    class Meta:
        model = Consultation
        # Le patient, les notes chiffrées, la politique ABE et l'indication de suivi.
        fields = ['patient',  'abe_policy', 'follow_up_required']

# Formulaire pour une Clé ABE
class ABEKeyForm(forms.ModelForm):
    class Meta:
        model = ABEKey
        fields = ['attributes', 'public_key',  'revoked']