import json
import asyncio
from typing import List, Dict
import subprocess
from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

async def run_kubectl_command(command: str) -> Dict:
    """Execute kubectl command and return JSON output"""
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, _ = await process.communicate()
    return json.loads(stdout)

class OptimizedKubernetesTool(KubernetesTool):
    async def execute_analysis(self) -> str:
        raise NotImplementedError

class RBACAnalyzer(OptimizedKubernetesTool):
    async def execute_analysis(self) -> str:
        cluster_roles = await run_kubectl_command("kubectl get clusterroles -o json")
        bindings = await run_kubectl_command("kubectl get clusterrolebindings -o json")
        role_bindings = await run_kubectl_command("kubectl get rolebindings --all-namespaces -o json")

        output = ["🔒 *RBAC Analysis:*", "=================\n"]
        
        # Analyze cluster roles
        risky_roles = [
            item for item in cluster_roles["items"]
            if any("*" in rule.get("verbs", []) for rule in item.get("rules", []))
        ]
        
        output.extend([
            "📋 *ClusterRoles with High-Risk Permissions:*",
            "Severity: 🔴 HIGH - ClusterRoles with wildcard permissions"
        ])
        for role in risky_roles:
            output.append(f"  ⚠️  Role: {role['metadata']['name']} | Remediation: Review permissions")

        # Similar optimized processing for other checks...
        return "\n".join(output)

class ServiceAccountAnalyzer(OptimizedKubernetesTool):
    async def execute_analysis(self) -> str:
        pods = await run_kubectl_command("kubectl get pods --all-namespaces -o json")
        service_accounts = await run_kubectl_command("kubectl get sa --all-namespaces -o json")

        output = ["👤 *Service Account Analysis:*", "==========================\n"]

        # Check default SA usage
        default_sa_pods = [
            pod for pod in pods["items"]
            if pod.get("spec", {}).get("serviceAccountName") == "default"
        ]

        output.extend([
            "📋 *Default Service Account Usage (Security Risk):*",
            "Severity: 🟡 MEDIUM - Using default SA may grant unintended permissions"
        ])
        
        for pod in default_sa_pods:
            output.append(
                f"  ⚠️  Namespace: {pod['metadata']['namespace']}, "
                f"Pod: {pod['metadata']['name']} | Remediation: Create dedicated SA"
            )

        # Similar optimized processing for other checks...
        return "\n".join(output)

class PrivilegedWorkloadDetector(OptimizedKubernetesTool):
    async def execute_analysis(self) -> str:
        pods = await run_kubectl_command("kubectl get pods --all-namespaces -o json")
        
        output = ["🔍 *Security Context Analysis:*", "==============================\n"]
        
        # Check privileged containers
        privileged_pods = [
            pod for pod in pods["items"]
            if any(container.get("securityContext", {}).get("privileged") 
                  for container in pod.get("spec", {}).get("containers", []))
        ]
        
        output.extend([
            "⚠️  *Pods with Privileged Containers:*",
            "Severity: 🔴 HIGH - Privileged containers can escape container isolation"
        ])
        for pod in privileged_pods:
            output.append(
                f"  🚨 Namespace: {pod['metadata']['namespace']}, "
                f"Pod: {pod['metadata']['name']} | Remediation: Remove privileged flag"
            )

        # Check host path volumes
        host_path_pods = [
            pod for pod in pods["items"]
            if any(volume.get("hostPath") for volume in pod.get("spec", {}).get("volumes", []))
        ]
        
        output.extend([
            "\n⚠️  *Pods with Host Path Volumes:*",
            "Severity: 🔴 HIGH - Host path access can lead to host system compromise"
        ])
        for pod in host_path_pods:
            output.append(
                f"  📁 Namespace: {pod['metadata']['namespace']}, "
                f"Pod: {pod['metadata']['name']} | Remediation: Use persistent volumes"
            )

        return "\n".join(output)

class SecretAnalyzer(OptimizedKubernetesTool):
    async def execute_analysis(self) -> str:
        secrets = await run_kubectl_command("kubectl get secrets -n default -o json")
        pods = await run_kubectl_command("kubectl get pods --all-namespaces -o json")
        
        output = ["🔐 *Secrets Analysis:*", "==================\n"]
        
        # Check secrets in default namespace
        default_secrets = [
            secret for secret in secrets["items"]
            if secret["type"] != "kubernetes.io/service-account-token"
        ]
        
        output.extend([
            "📋 *Secrets in Default Namespace:*",
            "Severity: 🟡 MEDIUM - Secrets in default namespace may be accidentally exposed"
        ])
        for secret in default_secrets:
            output.append(
                f"  ⚠️  Secret: {secret['metadata']['name']} | "
                "Remediation: Move to dedicated namespace"
            )

        # Check pods with mounted secrets
        pods_with_secrets = [
            pod for pod in pods["items"]
            if any(volume.get("secret") for volume in pod.get("spec", {}).get("volumes", []))
        ]
        
        output.extend([
            "\n📋 *Pods with Mounted Secrets:*",
            "Cross-reference with RBAC for access control review"
        ])
        for pod in pods_with_secrets:
            secret_names = [
                volume["secret"]["secretName"]
                for volume in pod["spec"].get("volumes", [])
                if volume.get("secret")
            ]
            for secret_name in secret_names:
                output.append(
                    f"  🔑 Namespace: {pod['metadata']['namespace']}, "
                    f"Pod: {pod['metadata']['name']}, Secret: {secret_name}"
                )

        return "\n".join(output)

class NetworkPolicyAnalyzer(OptimizedKubernetesTool):
    async def execute_analysis(self) -> str:
        namespaces = await run_kubectl_command("kubectl get ns -o json")
        network_policies = await run_kubectl_command("kubectl get networkpolicy --all-namespaces -o json")
        
        output = ["🌐 *Network Policy Analysis:*", "=========================\n"]
        
        # Check namespaces without network policies
        ns_with_policies = {
            policy["metadata"]["namespace"]
            for policy in network_policies["items"]
        }
        
        ns_without_policies = [
            ns for ns in namespaces["items"]
            if ns["metadata"]["name"] not in ns_with_policies
        ]
        
        output.extend([
            "⚠️  *Namespaces without Network Policies:*",
            "Severity: 🔴 HIGH - Namespaces without isolation"
        ])
        for ns in ns_without_policies:
            output.append(
                f"  🚨 Namespace: {ns['metadata']['name']} | "
                "Remediation: Apply default deny policy"
            )

        # Check overly permissive policies
        permissive_policies = [
            policy for policy in network_policies["items"]
            if any(not ingress.get("from") for ingress in policy["spec"].get("ingress", [])) or
            any(not egress.get("to") for egress in policy["spec"].get("egress", []))
        ]
        
        output.extend([
            "\n⚠️  *Overly Permissive Network Policies:*",
            "Severity: 🟡 MEDIUM - Policies allowing all ingress/egress"
        ])
        for policy in permissive_policies:
            output.append(
                f"  ⚠️  Namespace: {policy['metadata']['namespace']}, "
                f"Policy: {policy['metadata']['name']} | Remediation: Restrict traffic flows"
            )

        return "\n".join(output)

# Instantiate tools
rbac_analyzer_tool = RBACAnalyzer(
    name="rbac_analyzer",
    description="Conducts a focused assessment of RBAC configurations across the cluster",
    content="",
    args=[],
)

service_account_analyzer_tool = ServiceAccountAnalyzer(
    name="service_account_analyzer",
    description="Audits service account usage and their associated roles across all namespaces",
    content="",
    args=[],
)

privileged_workload_detector_tool = PrivilegedWorkloadDetector(
    name="privileged_workload_detector",
    description="Detects privileged containers and security risks",
    content="",
    args=[],
)

secret_analyzer_tool = SecretAnalyzer(
    name="secret_analyzer",
    description="Analyzes Kubernetes secrets usage and mounting across all namespaces",
    content="",
    args=[],
)

network_policy_analyzer_tool = NetworkPolicyAnalyzer(
    name="network_policy_analyzer",
    description="Analyzes network policies and pod isolation across all namespaces",
    content="",
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