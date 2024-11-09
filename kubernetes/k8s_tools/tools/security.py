import asyncio
import json
from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

class AsyncKubernetesTool(KubernetesTool):
    async def _run_kubectl(self, command):
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return json.loads(stdout)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Wrap the content in an async executor
        original_content = kwargs.get('content', '')
        self.content = f"""
        #!/bin/bash
        set -e
        
        # Run the original commands in parallel
        {{
            {original_content}
        }} & 
        wait
        """

rbac_analyzer_tool = AsyncKubernetesTool(
    name="rbac_analyzer",
    description="Conducts a focused assessment of RBAC configurations across the cluster",
    content="""
    echo "🔒 *RBAC Analysis:*"
    echo "================="
    
    # Run queries in parallel
    {{
        kubectl get clusterroles -o json | jq -r '
            .items[] | 
            select(.rules[].verbs[] | contains("*")) |
            "  ⚠️  Role: \(.metadata.name) | Remediation: Review permissions"
        '
    }} &
    
    {{
        kubectl get clusterrolebindings,rolebindings --all-namespaces -o json | jq -r '
            .items[] | 
            select(.subjects[]?.name == "system:anonymous") |
            "  ⚠️  Binding: \(.metadata.name) | Remediation: Remove anonymous access"
        '
    }} &
    
    wait
    """,
    args=[],
)

service_account_analyzer_tool = AsyncKubernetesTool(
    name="service_account_analyzer",
    description="Audits service account usage and their associated roles across all namespaces",
    content="""
    echo "👤 *Service Account Analysis:*"
    echo "=========================="
    
    # Run queries in parallel
    {{
        kubectl get pods --all-namespaces -o json | jq -r '
            .items[] | 
            select(.spec.serviceAccountName == "default") |
            "  ⚠️  Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Create dedicated SA"
        '
    }} &
    
    {{
        kubectl get sa --all-namespaces -o json | jq -r '
            .items[] | 
            select(.secrets | length == 0) |
            "  ℹ️  Namespace: \(.metadata.namespace), SA: \(.metadata.name) | Remediation: Remove if not needed"
        '
    }} &
    
    wait
    """,
    args=[],
)

privileged_workload_detector_tool = AsyncKubernetesTool(
    name="privileged_workload_detector",
    description="Detects privileged containers and security risks",
    content="""
    echo "🔍 *Security Context Analysis:*"
    echo "=============================="
    
    # Run queries in parallel
    {{
        kubectl get pods --all-namespaces -o json | jq -r '
            .items[] | 
            (
                if (.spec.containers[].securityContext.privileged == true) then
                    "  🚨 Privileged Container - Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Remove privileged flag"
                elif (.spec.volumes[]?.hostPath != null) then
                    "  📁 Host Path Volume - Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Use persistent volumes"
                elif (.spec.containers[].securityContext.runAsNonRoot != true) then
                    "  👤 Root User - Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Set runAsNonRoot: true"
                else empty
                end
            )
        '
    }} &
    
    wait
    """,
    args=[],
)

secret_analyzer_tool = AsyncKubernetesTool(
    name="secret_analyzer",
    description="Analyzes Kubernetes secrets usage and mounting across all namespaces",
    content="""
    echo "🔐 *Secrets Analysis:*"
    echo "=================="
    
    # Run queries in parallel
    {{
        kubectl get secrets -n default -o json | jq -r '
            .items[] | 
            select(.type != "kubernetes.io/service-account-token") |
            "  ⚠️  Secret: \(.metadata.name) | Remediation: Move to dedicated namespace"
        '
    }} &
    
    {{
        kubectl get pods --all-namespaces -o json | jq -r '
            .items[] | 
            select(.spec.volumes[]?.secret != null) |
            "  🔑 Namespace: \(.metadata.namespace), Pod: \(.metadata.name), Secret: \(.spec.volumes[].secret.secretName)"
        '
    }} &
    
    wait
    """,
    args=[],
)

network_policy_analyzer_tool = AsyncKubernetesTool(
    name="network_policy_analyzer",
    description="Analyzes network policies and pod isolation across all namespaces",
    content="""
    echo "🌐 *Network Policy Analysis:*"
    echo "========================="
    
    # Run queries in parallel
    {{
        kubectl get ns,networkpolicy --all-namespaces -o json | jq -r '
            .items[] | 
            select(.kind == "Namespace") |
            select(.metadata.name as $ns | 
                ([..| select(.kind == "NetworkPolicy" and .metadata.namespace == $ns)] | length) == 0
            ) |
            "  🚨 Namespace: \(.metadata.name) | Remediation: Apply default deny policy"
        '
    }} &
    
    {{
        kubectl get networkpolicies --all-namespaces -o json | jq -r '
            .items[] | 
            select(.spec.ingress[]?.from == null or .spec.egress[]?.to == null) |
            "  ⚠️  Namespace: \(.metadata.namespace), Policy: \(.metadata.name) | Remediation: Restrict traffic flows"
        '
    }} &
    
    wait
    """,
    args=[],
)

# Register all tools
tools = [
    rbac_analyzer_tool,
    service_account_analyzer_tool,
    privileged_workload_detector_tool,
    secret_analyzer_tool,
    network_policy_analyzer_tool,
]

for tool in tools:
    tool_registry.register("kubernetes", tool) 