from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('api/scan/', views.cerebras_scan, name='cerebras_scan'),
    path('attack-paths/', views.attack_paths, name='attack_paths'),
    path('risk-explanation/', views.risk_explanation, name='risk_explanation'),
    path('remediation/', views.remediation, name='remediation'),
    path('omni-scan/', views.execute_omni_agent, name='omni_scan'),
    path('omni-scan/<int:scan_id>/', views.omni_scan_detail, name='omni_scan_detail'),
]