import json
import os
import re
import urllib.request
import urllib.error

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import OmniScan



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
    return render(request, 'ByteGuard_ai/scanner.html')


@csrf_exempt
@require_POST
def cerebras_scan(request):
    api_key = os.environ.get('CEREBRAS_API_KEY', '')
    if not api_key:
        return JsonResponse(
            {'error': 'CEREBRAS_API_KEY is not configured on this server.'},
            status=500,
        )

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    target = body.get('target', '').strip()
    mode = body.get('mode', 'website')
    depth = body.get('depth', 'standard')
    context = body.get('context', '').strip()

    if not target:
        return JsonResponse({'error': 'Target system identifier is required.'}, status=400)

    if re.search(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)', target):
        target = 'internal-network-isolated-node.local'

    mode_context = {
        'website': 'Analyze the web application architecture, application layer profiles, and security headers.',
        'code': 'Analyze application source structures, logic patterns, and library dependency paths.',
        'system': 'Analyze infrastructure, container configurations, and operating system deployment manifests.',
        'hardware': 'Analyze embedded firmware structures, binary interfaces, and hardware registers.',
        'network': 'Analyze network topology layouts, routing rules, and exposed communication vectors.',
    }.get(mode, 'Analyze standard operational target environments.')

    depth_instr = {
        'quick': 'Identify top critical misconfigurations or immediate exposure points.',
        'standard': 'Provide a comprehensive audit covering standard configuration gaps and known vulnerability patterns.',
        'deep': 'Perform an exhaustive architectural dependency and design flow evaluation.',
        'pentest': 'Map sophisticated, multi-stage attack paths involving initial exposure, privilege escalation, and lateral movement vectors.',
    }.get(depth, 'Perform standard architectural security evaluation.')

    system_prompt = f"""You are ByteGuard AI, an elite enterprise security architecture intelligence engine.
Your task is to analyze the target configuration profile: {mode_context}
Operational Depth: {depth_instr}

You MUST return a single, valid JSON object matching the exact schema below.
Do NOT wrap your response in markdown code blocks (no backticks, no ```json). Start directly with {{ and end with }}.

Schema:
{{
  "target_summary": "High-level architectural profiling of the evaluated target.",
  "risk_score": 0-100,
  "vulnerabilities": [
    {{
      "id": "BG-001",
      "name": "Descriptive title of issue",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss": 0.0-10.0,
      "category": "Classification (e.g., Auth, Encryption, Config)",
      "description": "Clear conceptual breakdown of why this configuration or architecture presents a risk.",
      "affected_component": "Component or layer involved",
      "exploit_scenario": "The theoretical structural progression an adversary could exploit.",
      "fix": "Concrete remediation steps and architectural requirements.",
      "code_fix": "Remediation artifact snippet (e.g., secure configuration block, patch file, or policy definition). Keep empty if not applicable."
    }}
  ],
  "attack_paths": [
    "Step-by-step structural visualization of how an attack spreads through this misconfiguration"
  ],
  "remediation_plan": [
    {{
      "priority": 1,
      "title": "Action title",
      "description": "What to change and the architectural rationale",
      "effort": "Low|Medium|High",
      "impact": "Low|Medium|High|Critical"
    }}
  ],
  "compliance_gaps": ["List specific compliance shortfalls e.g., SOC2 Type II, ISO 27001, PCI-DSS, GDPR"]
}}"""

    user_msg = f"Target Reference: {target}\nAnalysis Mode: {mode}\nScope Strategy: {depth}\n{('Contextual Architecture Logs:\n' + context) if context else ''}\n\nGenerate the structural JSON evaluation report."

    payload = json.dumps({
        'model': 'llama3.1-8b',
        'max_completion_tokens': 3500,
        'temperature': 0.1,
        'top_p': 1,
        'stream': False,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_msg},
        ],
    }).encode('utf-8')

    req = urllib.request.Request(
        'https://api.cerebras.ai/v1/chat/completions',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            cerebras_data = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return JsonResponse({'error': f'API Error {e.code}: Operational exception encountered.'}, status=502)
    except urllib.error.URLError as e:
        return JsonResponse({'error': f'Upstream communication failure: {e.reason}'}, status=502)

    raw = cerebras_data.get('choices', [{}])[0].get('message', {}).get('content', '')
    raw = re.sub(r'^```json\s*', '', raw, flags=re.IGNORECASE)
    raw = raw.replace('```', '').strip()

    try:
        report = json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\{[\s\S]*\}', raw)
        if m:
            try:
                report = json.loads(m.group(0))
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Failed to normalize structured output schema.'}, status=502)
        else:
            return JsonResponse({'error': 'Incompatible response format returned by engine.'}, status=502)

    return JsonResponse(report)


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


def execute_omni_agent(request):
    if request.method != 'POST':
        return render(request, 'ByteGuard_ai/omni_scan_form.html')

    target_type = request.POST.get('target_type')
    target_identifier = request.POST.get('target_identifier')

    scan = OmniScan.objects.create(
        target_type=target_type,
        target_identifier=target_identifier,
        status='SCANNING',
    )

    probe_log = ''
    try:
        if target_type == 'WEBSITE':
            result = subprocess.run(
                ['nikto', '-h', target_identifier, '-Tuning', '123b'],
                capture_output=True,
                text=True,
                timeout=300,
            )
            probe_log = result.stdout or result.stderr
        elif target_type == 'SYSTEM':
            result = subprocess.run(
                ['nmap', '-sV', '--script=vuln', target_identifier],
                capture_output=True,
                text=True,
                timeout=300,
            )
            probe_log = result.stdout or result.stderr
        elif target_type == 'HARDWARE':
            result = subprocess.run(
                ['binwalk', '-e', target_identifier],
                capture_output=True,
                text=True,
                timeout=300,
            )
            probe_log = result.stdout or result.stderr
        else:
            raise ValueError('Unsupported target type')

        scan.raw_probe_output = probe_log
        scan.status = 'ANALYZING'
        scan.save()

    except Exception as exc:
        scan.status = 'FAILED'
        scan.raw_probe_output = f'Tooling execution failed: {str(exc)}'
        scan.save()
        return JsonResponse({'error': 'Hardware/Network probing failed.'}, status=500)

    system_prompt = (
        'You are an Elite Autonomous Penetration Tester and Cyber-remediation Engineer. '
        'Analyze the provided raw scanner logs. Identify explicit vulnerabilities, map outcomes, '
        'and generate a fully automated remediation response.\n\n'
        'You must respond exclusively in structured JSON format with these exact keys:\n'
        '- "vulnerabilities": A complete list of issues found with impact analyses.\n'
        '- "remediation_plan": A structured step-by-step master plan outlining how to resolve the issues.\n'
        '- "fix_script": A fully complete, self-executing Bash or Python script designed to automatically '
        'fix the flaws (e.g., modifying configurations, updating packages, editing specific config files, shutting down bad ports).'
    )

    try:
        from cerebras.cloud.sdk import Cerebras

        client = Cerebras(api_key=os.environ.get('CEREBRAS_API_KEY'))

        completion = client.chat.completions.create(
            messages=[
                {'role': 'system', 'content': system_prompt},
                {
                    'role': 'user',
                    'content': f'TARGET CLASSIFICATION: {target_type}\nRAW PROBE DATA:\n{probe_log}',
                },
            ],
            model='llama3.1-70b',
            max_completion_tokens=4096,
            temperature=0.0,
            top_p=1,
            stream=False,
        )

        ai_payload = json.loads(completion.choices[0].message.content.strip())

        scan.vulnerabilities_found = json.dumps(ai_payload.get('vulnerabilities', []), indent=2)
        scan.remediation_plan = ai_payload.get('remediation_plan')
        scan.execution_script = ai_payload.get('fix_script')
        scan.status = 'FIXING'
        scan.save()

        script_content = scan.execution_script
        if script_content:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.sh', mode='w', encoding='utf-8') as script_file:
                script_file.write(script_content)
                script_path = script_file.name

            if os.name != 'nt':
                subprocess.run(['chmod', '+x', script_path], check=True)

            execution_run = subprocess.run(
                [script_path],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if execution_run.returncode == 0:
                scan.status = 'COMPLETED'
            else:
                scan.status = 'FAILED'
                scan.remediation_plan = f"{scan.remediation_plan}\n\n[Execution Failure Log]:\n{execution_run.stderr}"
        else:
            scan.status = 'COMPLETED'

        scan.save()
        return redirect('omni_scan_detail', scan_id=scan.id)

    except Exception as exc:
        scan.status = 'FAILED'
        scan.save()
        return JsonResponse({'error': f'AI processing or patch execution failed: {str(exc)}'}, status=500)


def omni_scan_detail(request, scan_id):
    scan = get_object_or_404(OmniScan, id=scan_id)
    return render(request, 'ByteGuard_ai/omni_scan_detail.html', {'scan': scan})
