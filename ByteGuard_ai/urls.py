from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('attack-paths/', views.attack_paths, name='attack_paths'),
    path('risk-explanation/', views.risk_explanation, name='risk_explanation'),
    path('remediation/', views.remediation, name='remediation'),
]