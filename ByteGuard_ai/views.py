from django.shortcuts import render
from django.utils import timezone


def get_dashboard_summary():
    return {
        'active_assets': 423,
        'attack_paths': 12,
        'critical_paths': 4,
        'remediation_suggestions': 8,
        'last_refresh': timezone.now(),
    }


def get_sample_attack_paths():
    return [
        {
            'name': 'Internet → Load Balancer → API Pod → Service Account → Critical Storage Bucket',
            'criticality': 'HIGH',
            'window': '15–45 minutes',
            'status': 'Active',
            'recommendation': 'Restrict network policy and isolate the service account.',
        },
        {
            'name': 'Dev VPN → Bastion Host → Kubernetes API → Database Pod',
            'criticality': 'MEDIUM',
            'window': '30–90 minutes',
            'status': 'Review',
            'recommendation': 'Rotate credentials and enforce MFA on bastion access.',
        },
        {
            'name': 'External SMTP → Mail Gateway → Internal App → Data Store',
            'criticality': 'LOW',
            'window': '45–120 minutes',
            'status': 'Monitored',
            'recommendation': 'Harden ingress rules and apply least privilege service account.',
        },
    ]


def get_sample_explanations():
    return [
        {
            'title': 'Overly permissive network policy',
            'summary': 'A cluster policy allows broad ingress to the reporting namespace, exposing sensitive backend services.',
            'impact': 'Restricting this policy removes multiple high-risk attack paths without disrupting production traffic.',
        },
        {
            'title': 'Service account privilege exposure',
            'summary': 'A default service account is used by a high-value pod with write access to the finance database.',
            'impact': 'Move workloads to dedicated service accounts and limit RBAC permissions.',
        },
    ]


def get_sample_remediations():
    return [
        {
            'name': 'Lock down SSH access',
            'type': 'Terraform patch',
            'detail': 'Restrict security group ingress for SSH to authorized CIDRs only.',
        },
        {
            'name': 'Enforce Kubernetes RBAC least privilege',
            'type': 'Kubernetes patch',
            'detail': 'Replace cluster-admin bindings with constrained RoleBindings.',
        },
        {
            'name': 'Restrict public S3 bucket access',
            'type': 'AWS remediation',
            'detail': 'Generate policy to enforce private bucket ACLs for sensitive storage.',
        },
    ]


def home(request):
    return render(request, 'ByteGuard_ai/home.html', {
        'features': [
            'Graph-based attack path simulation',
            'LLM-assisted operational risk explanations',
            'Reviewable remediation patch generation',
            'Continuous infrastructure validation dashboard',
        ],
    })


def dashboard(request):
    return render(request, 'ByteGuard_ai/dashboard.html', {
        'summary': get_dashboard_summary(),
        'paths': get_sample_attack_paths(),
    })


def attack_paths(request):
    return render(request, 'ByteGuard_ai/attack_paths.html', {
        'attack_paths': get_sample_attack_paths(),
    })


def risk_explanation(request):
    return render(request, 'ByteGuard_ai/risk_explanation.html', {
        'explanations': get_sample_explanations(),
    })


def remediation(request):
    return render(request, 'ByteGuard_ai/remediation.html', {
        'recommendations': get_sample_remediations(),
    })
