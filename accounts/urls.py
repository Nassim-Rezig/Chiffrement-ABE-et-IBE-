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
]