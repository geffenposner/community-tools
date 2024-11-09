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
    
    echo "📋 *ClusterRoles:*"
    kubectl get clusterroles -o custom-columns=NAME:.metadata.name,VERBS:.rules[*].verbs[*],RESOURCES:.rules[*].resources[*]
    
    echo "\n📋 *ClusterRoleBindings:*"
    kubectl get clusterrolebindings -o custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name
    
    echo "\n📋 *Roles across all namespaces:*"
    kubectl get roles --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,VERBS:.rules[*].verbs[*],RESOURCES:.rules[*].resources[*]
    
    echo "\n📋 *RoleBindings across all namespaces:*"
    kubectl get rolebindings --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name
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
    
    echo "📋 *Service Accounts:*"
    kubectl get serviceaccounts --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SECRETS:.secrets[*].name
    
    echo "\n📋 *Service Accounts Usage in Pods:*"
    kubectl get pods --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SERVICEACCOUNT:.spec.serviceAccountName
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
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.privileged == true) |
        "  🚨 Namespace: \(.metadata.namespace), Pod: \(.metadata.name)"
    '
    
    echo "\n⚠️  *Pods with Host Path Volumes:*"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.volumes[]?.hostPath != null) |
        "  📁 Namespace: \(.metadata.namespace), Pod: \(.metadata.name)"
    '
    
    echo "\n⚠️  *Pods with Host Network:*"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.hostNetwork == true) |
        "  🌐 Namespace: \(.metadata.namespace), Pod: \(.metadata.name)"
    '
    
    echo "\n📋 *Pod Security Policies:*"
    kubectl get psp -o custom-columns=NAME:.metadata.name,PRIV:.spec.privileged,SELINUX:.spec.seLinux.rule,RUNASUSER:.spec.runAsUser.rule 2>/dev/null || echo "  No Pod Security Policies found"
    
    echo "\n📋 *Security Context Constraints:*"
    kubectl get scc 2>/dev/null || echo "  No Security Context Constraints found (OpenShift specific)"
    
    echo "\n📋 *Admission Controllers:*"
    kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations 2>/dev/null || echo "  No webhook configurations found"
    
    echo "\n📋 *Resource Quotas:*"
    kubectl get resourcequotas --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,HARD:.spec.hard,USED:.status.used
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
    
    echo "📋 *Secrets Overview:*"
    kubectl get secrets --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type
    
    echo "\n📋 *Pods Mounting Secrets:*"
    kubectl get pods --all-namespaces -o json | jq -r '
        .items[] | 
        select(.spec.volumes[]?.secret != null) |
        "  🔑 Namespace: \(.metadata.namespace), Pod: \(.metadata.name), Secret: \(.spec.volumes[].secret.secretName)"
    '
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
    
    echo "📋 *Network Policies:*"
    kubectl get networkpolicies --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,POD-SELECTOR:.spec.podSelector.matchLabels
    
    echo "\n⚠️  *Namespaces without Network Policies:*"
    kubectl get ns -o json | jq -r '
        .items[] | 
        select(.metadata.name as $ns | 
            ([$(kubectl get networkpolicy --all-namespaces -o json | 
                jq -r ".items[] | select(.metadata.namespace == \"\($ns)\") | .metadata.name")] | length) == 0
        ) |
        "  🚨 \(.metadata.name)"
    '
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