from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

rbac_analyzer_tool = KubernetesTool(
    name="rbac_analyzer",
    description="Analyzes RBAC configurations across the cluster",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔒 RBAC Analysis:"
    echo "================="
    
    echo "📋 ClusterRoles:"
    kubectl get clusterroles -o custom-columns=NAME:.metadata.name,VERBS:.rules[*].verbs[*],RESOURCES:.rules[*].resources[*]
    
    echo "\n📋 ClusterRoleBindings:"
    kubectl get clusterrolebindings -o custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name
    
    if [ -n "$namespace" ]; then
        echo "\n📋 Roles in namespace $namespace:"
        kubectl get roles -n "$namespace" -o custom-columns=NAME:.metadata.name,VERBS:.rules[*].verbs[*],RESOURCES:.rules[*].resources[*]
        
        echo "\n📋 RoleBindings in namespace $namespace:"
        kubectl get rolebindings -n "$namespace" -o custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECTS:.subjects[*].name
    fi
    """,
    args=[
        Arg(name="namespace", type="str", description="Optional: Specific namespace to analyze", required=False),
    ],
)

service_account_analyzer_tool = KubernetesTool(
    name="service_account_analyzer",
    description="Audits service account usage and their associated roles",
    content="""
    #!/bin/bash
    set -e
    
    echo "👤 Service Account Analysis:"
    echo "=========================="
    
    if [ -n "$namespace" ]; then
        namespace_flag="-n $namespace"
    else
        namespace_flag="--all-namespaces"
    fi
    
    echo "📋 Service Accounts:"
    kubectl get serviceaccounts $namespace_flag -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SECRETS:.secrets[*].name
    
    echo "\n📋 Service Accounts Usage in Pods:"
    kubectl get pods $namespace_flag -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SERVICEACCOUNT:.spec.serviceAccountName
    """,
    args=[
        Arg(name="namespace", type="str", description="Optional: Specific namespace to analyze", required=False),
    ],
)

privileged_workload_detector_tool = KubernetesTool(
    name="privileged_workload_detector",
    description="Detects privileged containers and potential security risks",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔍 Privileged Container Analysis:"
    echo "=============================="
    
    if [ -n "$namespace" ]; then
        namespace_flag="-n $namespace"
    else
        namespace_flag="--all-namespaces"
    fi
    
    echo "⚠️  Pods with Privileged Containers:"
    kubectl get pods $namespace_flag -o json | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.privileged == true) |
        "  🚨 Namespace: \(.metadata.namespace), Pod: \(.metadata.name)"
    '
    
    echo "\n⚠️  Pods with Host Path Volumes:"
    kubectl get pods $namespace_flag -o json | jq -r '
        .items[] | 
        select(.spec.volumes[]?.hostPath != null) |
        "  📁 Namespace: \(.metadata.namespace), Pod: \(.metadata.name)"
    '
    
    echo "\n⚠️  Pods with Host Network:"
    kubectl get pods $namespace_flag -o json | jq -r '
        .items[] | 
        select(.spec.hostNetwork == true) |
        "  🌐 Namespace: \(.metadata.namespace), Pod: \(.metadata.name)"
    '
    """,
    args=[
        Arg(name="namespace", type="str", description="Optional: Specific namespace to analyze", required=False),
    ],
)

secret_analyzer_tool = KubernetesTool(
    name="secret_analyzer",
    description="Analyzes Kubernetes secrets usage and mounting",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔐 Secrets Analysis:"
    echo "=================="
    
    if [ -n "$namespace" ]; then
        namespace_flag="-n $namespace"
    else
        namespace_flag="--all-namespaces"
    fi
    
    echo "📋 Secrets Overview:"
    kubectl get secrets $namespace_flag -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type
    
    echo "\n📋 Pods Mounting Secrets:"
    kubectl get pods $namespace_flag -o json | jq -r '
        .items[] | 
        select(.spec.volumes[]?.secret != null) |
        "  🔑 Namespace: \(.metadata.namespace), Pod: \(.metadata.name), Secret: \(.spec.volumes[].secret.secretName)"
    '
    """,
    args=[
        Arg(name="namespace", type="str", description="Optional: Specific namespace to analyze", required=False),
    ],
)

network_policy_analyzer_tool = KubernetesTool(
    name="network_policy_analyzer",
    description="Analyzes network policies and pod isolation",
    content="""
    #!/bin/bash
    set -e
    
    echo "🌐 Network Policy Analysis:"
    echo "========================="
    
    if [ -n "$namespace" ]; then
        namespace_flag="-n $namespace"
    else
        namespace_flag="--all-namespaces"
    fi
    
    echo "📋 Network Policies:"
    kubectl get networkpolicies $namespace_flag -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,POD-SELECTOR:.spec.podSelector.matchLabels
    
    echo "\n⚠️  Namespaces without Network Policies:"
    kubectl get ns -o json | jq -r '
        .items[] | 
        select(.metadata.name as $ns | 
            ([$(kubectl get networkpolicy --all-namespaces -o json | 
                jq -r ".items[] | select(.metadata.namespace == \"\($ns)\") | .metadata.name")] | length) == 0
        ) |
        "  🚨 \(.metadata.name)"
    '
    """,
    args=[
        Arg(name="namespace", type="str", description="Optional: Specific namespace to analyze", required=False),
    ],
)

security_audit_report_tool = KubernetesTool(
    name="security_audit_report",
    description="Generates a basic security audit report using kubectl",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔒 Kubernetes Security Audit Report"
    echo "================================="
    
    if [ -n "$namespace" ]; then
        namespace_flag="-n $namespace"
        echo "📍 Analyzing namespace: $namespace"
    else
        namespace_flag="--all-namespaces"
        echo "📍 Analyzing all namespaces"
    fi
    
    echo "\n1️⃣ RBAC Configuration"
    echo "-------------------"
    kubectl get clusterroles,clusterrolebindings $namespace_flag
    
    echo "\n2️⃣ Service Accounts"
    echo "----------------"
    kubectl get serviceaccounts $namespace_flag
    
    echo "\n3️⃣ Pod Security"
    echo "-------------"
    kubectl get pods $namespace_flag -o json | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.privileged == true or 
               .spec.volumes[]?.hostPath != null or 
               .spec.hostNetwork == true) |
        "  ⚠️  Security concerns in Pod: \(.metadata.namespace)/\(.metadata.name)"
    '
    
    echo "\n4️⃣ Network Policies"
    echo "-----------------"
    kubectl get networkpolicies $namespace_flag
    
    echo "\n5️⃣ Secrets Usage"
    echo "-------------"
    kubectl get secrets $namespace_flag -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type
    
    echo "\n6️⃣ Resource Quotas"
    echo "----------------"
    kubectl get resourcequotas $namespace_flag
    
    echo "\n7️⃣ Pod Security Policies"
    echo "----------------------"
    kubectl get psp 2>/dev/null || echo "  No Pod Security Policies found"
    """,
    args=[
        Arg(name="namespace", type="str", description="Optional: Specific namespace to analyze", required=False),
    ],
)

# Register all tools
for tool in [
    rbac_analyzer_tool,
    service_account_analyzer_tool,
    privileged_workload_detector_tool,
    secret_analyzer_tool,
    network_policy_analyzer_tool,
    security_audit_report_tool,
]:
    tool_registry.register("kubernetes", tool) 