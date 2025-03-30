from django.contrib import admin
from .models import User, Patient, Medecin, Radiologue, Laborantin, MedicalRecord, Consultation, Prescription, ABEKey
import base64


# Pour le modèle User (si tu souhaites l'afficher ou le modifier)
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email', 'role', 'is_staff', 'is_superuser']
    search_fields = ['email']
    

# Pour le modèle Patient
@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):

    
    search_fields = ['user__email']
    fields = ('user', 'date_of_birth', 'blood_type', 'abe_policy', 'encrypted_insurance')
    readonly_fields = ('encrypted_insurance',)

    def display_encrypted_insurance(self, obj):
        """Affiche un extrait du champ binaire en Base64."""
        if obj.encrypted_insurance:
            encoded = base64.b64encode(obj.encrypted_insurance).decode('utf-8')
            return encoded[:50] + '...'  # Tronquer l'affichage pour éviter un affichage trop long
        return ''
    
    display_encrypted_insurance.short_description = "Encrypted Insurance (Base64)"


# Pour le modèle Medecin
@admin.register(Medecin)
class MedecinAdmin(admin.ModelAdmin):
    fields = ['user', 'specialization', 'phone_number']
    search_fields = ['user__email', 'specialization']

# Pour le modèle Radiologue
@admin.register(Radiologue)
class RadiologueAdmin(admin.ModelAdmin):
    fields = ['user', 'radiology_field', 'phone_number']
    search_fields = ['user__email', 'radiology_field']

# Pour le modèle Laborantin
@admin.register(Laborantin)
class LaborantinAdmin(admin.ModelAdmin):
    fields = ['user', 'lab_department', 'phone_number']
    search_fields = ['user__email', 'lab_department']

# Pour le modèle MedicalRecord
@admin.register(MedicalRecord)
class MedicalRecordAdmin(admin.ModelAdmin):
    fields = ['patient', 'creator', 'creation_date', 'last_modified','assigned_to','abe_policy','encrypted_data']
    search_fields = ['patient__user__email', 'creator__email']
    list_filter = ['creation_date']

    readonly_fields = ('encrypted_data','last_modified','creation_date')

    def display_encrypted_data(self, obj):
        """Affiche un extrait du champ binaire en Base64."""
        if obj.encrypted_insurance:
            encoded = base64.b64encode(obj.encrypted_data ).decode('utf-8')
            return encoded[:50] + '...'  # Tronquer l'affichage pour éviter un affichage trop long
        return ''
    
    display_encrypted_data .short_description = "Encrypted data (Base64)"

# Pour le modèle Consultation
@admin.register(Consultation)
class ConsultationAdmin(admin.ModelAdmin):
    fields = ['patient', 'professional', 'date', 'follow_up_required','abe_policy','encrypted_notes']
    search_fields = ['patient__user__email', 'professional__email']
    list_filter = ['date', 'follow_up_required']

    readonly_fields = ('date','encrypted_notes')

    def display_encrypted_notes(self, obj):
        """Affiche un extrait du champ binaire en Base64."""
        if obj.encrypted_insurance:
            encoded = base64.b64encode(obj.encrypted_notes).decode('utf-8')
            return encoded[:50] + '...'  # Tronquer l'affichage pour éviter un affichage trop long
        return ''
    
    display_encrypted_notes .short_description = "Encrypted notes (Base64)"

# Pour le modèle Prescription
@admin.register(Prescription)
class PrescriptionAdmin(admin.ModelAdmin):
    fields = ['consultation', 'issue_date', 'validity_days','abe_policy']
    search_fields = ['consultation__patient__user__email']

    readonly_fields = ('encrypted_content','issue_date')

    def display_encrypted_content(self, obj):
        """Affiche un extrait du champ binaire en Base64."""
        if obj.encrypted_insurance:
            encoded = base64.b64encode(obj.encrypted_content).decode('utf-8')
            return encoded[:50] + '...'  # Tronquer l'affichage pour éviter un affichage trop long
        return ''
    
    display_encrypted_content .short_description = "Encrypted content (Base64)"

# Pour le modèle ABEKey
@admin.register(ABEKey)
class ABEKeyAdmin(admin.ModelAdmin):
    fields = ['user', 'created_at', 'revoked']
    search_fields = ['user__email']
    list_filter = ['revoked', 'created_at']
