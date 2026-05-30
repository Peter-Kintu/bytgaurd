import json
import logging
import os
import re
import socket
import ipaddress
import http.client
import urllib.request
import urllib.error
from urllib.parse import urlparse

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

logger = logging.getLogger(__name__)


def _resolve_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
        return True, infos[0][4][0]
    except socket.gaierror as exc:
        return False, str(exc)


def _is_public_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local)
    except ValueError:
        return False


def _probe_common_ports(host, resolved_ip):
    common_ports = [80, 443, 22, 3389, 3306, 5432]
    for port in common_ports:
        try:
            with socket.create_connection((resolved_ip, port), timeout=5):
                return True, port
        except Exception:
            continue
    return False, None


def _verify_http_target(target):
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', target):
        target = 'http://' + target

    parsed = urlparse(target)
    if not parsed.hostname:
        return False, None, 'Invalid website target format.'

    if parsed.scheme not in ('http', 'https'):
        return False, None, f'Unsupported URL scheme: {parsed.scheme}.'

    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    resolved, resolved_ip = _resolve_host(parsed.hostname)
    if not resolved:
        return False, None, f'Host resolution failed: {resolved_ip}'

    if not _is_public_address(resolved_ip):
        return False, None, f'Resolved address {resolved_ip} is not a public internet host.'

    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    conn_cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
    conn = conn_cls(parsed.hostname, port, timeout=8)
    try:
        conn.request('HEAD', path, headers={'User-Agent': 'ByteGuard/1.0'})
        resp = conn.getresponse()
        if resp.status == 405:
            conn.close()
            conn = conn_cls(parsed.hostname, port, timeout=8)
            conn.request('GET', path, headers={'User-Agent': 'ByteGuard/1.0'})
            resp = conn.getresponse()
        resp.read()
        return True, parsed.geturl(), (
            f'{parsed.scheme.upper()} reachable at {resolved_ip}:{port} ({resp.status} {resp.reason})'
        )
    except Exception as exc:
        return False, None, f'Connectivity check failed: {exc}'
    finally:
        conn.close()


def _verify_host_target(target):
    parsed = urlparse(target if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', target) else '//' + target)
    host = parsed.hostname or target.split('/')[0]
    if not host:
        return False, None, 'Invalid host target format.'

    resolved, resolved_ip = _resolve_host(host)
    if not resolved:
        return False, None, f'Host resolution failed: {resolved_ip}'

    if not _is_public_address(resolved_ip):
        return False, None, f'Resolved address {resolved_ip} is not a public internet host.'

    open_port, port = _probe_common_ports(host, resolved_ip)
    if not open_port:
        return False, None, 'Host resolved successfully but no common service ports were reachable on the public internet.'

    return True, host, f'Resolved host to {resolved_ip}; service port {port} is reachable.'


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

    model_name = os.environ.get('CEREBRAS_MODEL', 'llama3-8b-instruct')

    if not target:
        return JsonResponse({'error': 'Target system identifier is required.'}, status=400)

    if mode == 'website':
        valid, normalized_target, verification = _verify_http_target(target)
    elif mode in ('system', 'network', 'hardware'):
        valid, normalized_target, verification = _verify_host_target(target)
    else:
        valid, normalized_target, verification = True, target, 'No external reachability validation performed for code analysis mode.'

    if not valid:
        return JsonResponse({'error': f'Target validation failed: {verification}'}, status=400)

    target = normalized_target

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
Your task is to analyze the verified live target configuration profile: {mode_context}
Operational Depth: {depth_instr}

The target has been validated as a reachable public internet host or website, and only confirmed infrastructure should be analyzed.

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

    user_msg = (
        f"Target Reference: {target}\n"
        f"Verification: {verification}\n"
        f"Analysis Mode: {mode}\n"
        f"Scope Strategy: {depth}\n"
        f"{('Contextual Architecture Logs:\n' + context) if context else ''}\n\n"
        "Generate the structural JSON evaluation report."
    )

    payload = json.dumps({
        'model': model_name,
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
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://api.cerebras.ai/',
            'Origin': 'https://api.cerebras.ai',
            'Connection': 'keep-alive',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            cerebras_data = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore')
        upstream_message = err_body
        try:
            json_err = json.loads(err_body)
            upstream_message = json_err.get('message') or json_err.get('error') or err_body
        except json.JSONDecodeError:
            pass
        logger.error('Cerebras upstream HTTPError %s: %s', e.code, upstream_message)
        return JsonResponse(
            {
                'error': (
                    f'Upstream API response error ({e.code}). '
                    f'Model={model_name}. {upstream_message}'
                )
            },
            status=e.code,
        )
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
        model_name = os.environ.get('CEREBRAS_MODEL', 'llama3-8b-instruct')

        completion = client.chat.completions.create(
            messages=[
                {'role': 'system', 'content': system_prompt},
                {
                    'role': 'user',
                    'content': f'TARGET CLASSIFICATION: {target_type}\nRAW PROBE DATA:\n{probe_log}',
                },
            ],
            model=model_name,
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
