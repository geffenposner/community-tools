from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

rbac_analyzer_tool = KubernetesTool(
    name="rbac_analyzer",
    description="Conducts a focused assessment of RBAC configurations across the cluster, highlighting security risks, potential vulnerabilities, and recommended remediation steps.",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔒 *RBAC Analysis:*"
    echo "================="
    
    echo "📋 *ClusterRoles with High-Risk Permissions:*"
    echo "Severity: 🔴 HIGH - ClusterRoles with wildcard permissions or sensitive operations"
    kubectl get clusterroles -o json | jq -r '
        .items[] | 
        select(.rules[].verbs[] | contains("*")) |
        "  ⚠️  Role: \(.metadata.name) | Remediation: Review and limit wildcard permissions"
    '
    
    echo "\n📋 *ClusterRoleBindings to system:anonymous:*"
    echo "Severity: 🔴 HIGH - Anonymous access should be strictly limited"
    kubectl get clusterrolebindings -o json | jq -r '
        .items[] | 
        select(.subjects[] | select(.name == "system:anonymous")) |
        "  ⚠️  Binding: \(.metadata.name) | Remediation: Remove anonymous access"
    '
    
    echo "\n📋 *Service Account Role Bindings:*"
    echo "Cross-reference with service-account-analyzer for complete access review"
    kubectl get rolebindings --all-namespaces -o json | jq -r '
        .items[] | 
        select(.subjects[] | select(.kind == "ServiceAccount")) |
        "  👤 Namespace: \(.metadata.namespace), Binding: \(.metadata.name), SA: \(.subjects[].name)"
    '
    """,
    args=[],
)

service_account_analyzer_tool = KubernetesTool(
    name="service_account_analyzer",
    description="Audits service account usage and their associated roles across all namespaces, identifying security risks, potential vulnerabilities, and recommended remediation steps.",
    content="""
    #!/bin/bash
    set -e
    
    echo "👤 *Service Account Analysis:*"
    echo "=========================="
    
    echo "📋 *Default Service Account Usage (Security Risk):*"
    echo "Severity: 🟡 MEDIUM - Using default SA may grant unintended permissions"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.serviceAccountName == "default") |
        "  ⚠️  Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Create dedicated SA"
    '
    
    echo "\n📋 *Unused Service Accounts:*"
    echo "Severity: 🟢 LOW - Cleanup recommended"
    kubectl get sa --all-namespaces -o json | jq -r '
        .items[] | 
        select(.secrets | length == 0) |
        "  ℹ️  Namespace: \(.metadata.namespace), SA: \(.metadata.name) | Remediation: Remove if not needed"
    '
    
    echo "\n📋 *Cross-Reference with RBAC:*"
    echo "Use rbac-analyzer to review associated role permissions"
    """,
    args=[],
)

privileged_workload_detector_tool = KubernetesTool(
    name="privileged_workload_detector",
    description="Detects privileged containers, security policies, and potential security risks across all namespaces.",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔍 *Security Context Analysis:*"
    echo "=============================="
    
    echo "⚠️  *Pods with Privileged Containers:*"
    echo "Severity: 🔴 HIGH - Privileged containers can escape container isolation"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.privileged == true) |
        "  🚨 Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Remove privileged flag"
    '
    
    echo "\n⚠️  *Pods with Host Path Volumes:*"
    echo "Severity: 🔴 HIGH - Host path access can lead to host system compromise"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.volumes[]?.hostPath != null) |
        "  📁 Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Use persistent volumes"
    '
    
    echo "\n⚠️  *Pods Running as Root:*"
    echo "Severity: 🟡 MEDIUM - Running as root poses security risks"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.runAsNonRoot != true) |
        "  👤 Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Set runAsNonRoot: true"
    '
    """,
    args=[],
)

secret_analyzer_tool = KubernetesTool(
    name="secret_analyzer",
    description="Analyzes Kubernetes secrets usage and mounting across all namespaces, focusing on security risks, potential vulnerabilities, and recommended remediation steps.",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔐 *Secrets Analysis:*"
    echo "=================="
    
    echo "📋 *Secrets in Default Namespace:*"
    echo "Severity: 🟡 MEDIUM - Secrets in default namespace may be accidentally exposed"
    kubectl get secrets -n default -o json | jq -r '
        .items[] | 
        select(.type != "kubernetes.io/service-account-token") |
        "  ⚠️  Secret: \(.metadata.name) | Remediation: Move to dedicated namespace"
    '
    
    echo "\n📋 *Pods with Mounted Secrets:*"
    echo "Cross-reference with RBAC for access control review"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.volumes[]?.secret != null) |
        "  🔑 Namespace: \(.metadata.namespace), Pod: \(.metadata.name), Secret: \(.spec.volumes[].secret.secretName)"
    '
    
    echo "\n📋 *Unused Secrets:*"
    echo "Severity: 🟢 LOW - Cleanup recommended"
    # Complex jq query to find unused secrets would go here
    """,
    args=[],
)

network_policy_analyzer_tool = KubernetesTool(
    name="network_policy_analyzer",
    description="Analyzes network policies and pod isolation across all namespaces, identifying security risks, potential vulnerabilities, and recommended remediation steps.",
    content="""
    #!/bin/bash
    set -e
    
    echo "🌐 *Network Policy Analysis:*"
    echo "========================="
    
    echo "⚠️  *Namespaces without Network Policies:*"
    echo "Severity: 🔴 HIGH - Namespaces without isolation"
    kubectl get ns -o json | jq -r '
        .items[] | 
        select(.metadata.name as $ns | 
            ([$(kubectl get networkpolicy --all-namespaces -o json | 
                jq -r ".items[] | select(.metadata.namespace == \"\($ns)\") | .metadata.name")] | length) == 0
        ) |
        "  🚨 Namespace: \(.metadata.name) | Remediation: Apply default deny policy"
    '
    
    echo "\n⚠️  *Overly Permissive Network Policies:*"
    echo "Severity: 🟡 MEDIUM - Policies allowing all ingress/egress"
    kubectl get networkpolicies --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.ingress[]?.from == null or .spec.egress[]?.to == null) |
        "  ⚠️  Namespace: \(.metadata.namespace), Policy: \(.metadata.name) | Remediation: Restrict traffic flows"
    '
    
    echo "\n📋 *Cross-Reference with Workloads:*"
    echo "Use privileged-workload-detector to review pods with host network access"
    """,
    args=[],
)

# Register all tools
for tool in [
    rbac_analyzer_tool,
    service_account_analyzer_tool,
    privileged_workload_detector_tool,
    secret_analyzer_tool,
    network_policy_analyzer_tool,
]:
    tool_registry.register("kubernetes", tool) 