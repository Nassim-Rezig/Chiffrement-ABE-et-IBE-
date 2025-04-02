from django.urls import path
from . import views
# Remove the LogoutView import since we're using our custom view

urlpatterns = [
    path('login/', views.CustomLoginView.as_view(), name='login'),
    # Use our custom logout view instead
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('users/', views.UserListView.as_view(), name='user_list'),
    path('users/create/<str:profile_type>/', views.UserCreateView.as_view(), name='user_create'),
    path('users/<int:pk>/delete/', views.UserDeleteView.as_view(), name='user_delete'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('user/<int:pk>/edit/', views.UserUpdateView.as_view(), name='user_update'),
    
    # Routes pour la gestion des dossiers médicaux
    path('medical-records/', views.MedicalRecordListView.as_view(), name='medical_record_list'),
    path('medical-records/create/', views.MedicalRecordCreateView.as_view(), name='medical_record_create'),
    path('medical-records/<int:pk>/', views.MedicalRecordDetailView.as_view(), name='medical_record_detail'),
    path('medical-records/<int:pk>/update/', views.MedicalRecordUpdateView.as_view(), name='medical_record_update'),
    path('medical-records/<int:pk>/delete/', views.MedicalRecordDeleteView.as_view(), name='medical_record_delete'),
    
    # Routes pour la gestion des consultations
    path('consultations/<int:pk>/', views.ConsultationDetailView.as_view(), name='consultation_detail'),
    path('consultations/<int:pk>/update/', views.ConsultationUpdateView.as_view(), name='consultation_update'),
    
    # Routes pour la gestion des ordonnances
    path('prescriptions/', views.PrescriptionListView.as_view(), name='prescription_list'),
    path('prescriptions/create/', views.PrescriptionCreateView.as_view(), name='prescription_create'),
    path('prescriptions/<int:pk>/', views.PrescriptionDetailView.as_view(), name='prescription_detail'),
    path('prescriptions/<int:pk>/update/', views.PrescriptionUpdateView.as_view(), name='prescription_update'),
    path('prescriptions/<int:pk>/delete/', views.PrescriptionDeleteView.as_view(), name='prescription_delete'),
]