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
    
    # Run kubectl command in background and save to temp file
    kubectl get clusterroles,clusterrolebindings,rolebindings --all-namespaces -o json > /tmp/rbac_data.json &
    RBAC_PID=$!
    
    # Wait for data
    wait $RBAC_PID
    RBAC_DATA=$(cat /tmp/rbac_data.json)
    rm /tmp/rbac_data.json
    
    echo "📋 *ClusterRoles with High-Risk Permissions:*"
    echo "Severity: 🔴 HIGH - ClusterRoles with wildcard permissions or sensitive operations"
    echo "$RBAC_DATA" | jq -r '
        .items[] | 
        select(.kind == "ClusterRole") |
        select(.rules[].verbs[] | contains("*")) |
        "  ⚠️  Role: \(.metadata.name) | Remediation: Review and limit wildcard permissions"
    '
    
    echo "\n📋 *ClusterRoleBindings to system:anonymous:*"
    echo "Severity: 🔴 HIGH - Anonymous access should be strictly limited"
    echo "$RBAC_DATA" | jq -r '
        .items[] | 
        select(.kind == "ClusterRoleBinding") |
        select(.subjects[] | select(.name == "system:anonymous")) |
        "  ⚠️  Binding: \(.metadata.name) | Remediation: Remove anonymous access"
    '
    
    echo "\n📋 *Service Account Role Bindings:*"
    echo "Cross-reference with service-account-analyzer for complete access review"
    echo "$RBAC_DATA" | jq -r '
        .items[] | 
        select(.kind == "RoleBinding") |
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
    
    # Run kubectl commands in parallel
    kubectl get pods --all-namespaces -o json > /tmp/pods_data.json &
    PODS_PID=$!
    
    kubectl get sa --all-namespaces -o json > /tmp/sa_data.json &
    SA_PID=$!
    
    # Wait for all data
    wait $PODS_PID $SA_PID
    
    PODS_DATA=$(cat /tmp/pods_data.json)
    SA_DATA=$(cat /tmp/sa_data.json)
    
    # Cleanup
    rm /tmp/pods_data.json /tmp/sa_data.json
    
    echo "📋 *Default Service Account Usage (Security Risk):*"
    echo "Severity: 🟡 MEDIUM - Using default SA may grant unintended permissions"
    echo "$PODS_DATA" | jq -r '
        .items[] | 
        select(.spec.serviceAccountName == "default") |
        "  ⚠️  Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Create dedicated SA"
    '
    
    echo "\n📋 *Unused Service Accounts:*"
    echo "Severity: 🟢 LOW - Cleanup recommended"
    echo "$SA_DATA" | jq -r '
        .items[] | 
        select(.secrets | length == 0) |
        "  ℹ️  Namespace: \(.metadata.namespace), SA: \(.metadata.name) | Remediation: Remove if not needed"
    '
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
    
    # Run kubectl command in background
    kubectl get pods --all-namespaces -o json > /tmp/pods_data.json &
    PODS_PID=$!
    
    # Wait for data
    wait $PODS_PID
    PODS_DATA=$(cat /tmp/pods_data.json)
    rm /tmp/pods_data.json
    
    echo "⚠️  *Pods with Privileged Containers:*"
    echo "Severity: 🔴 HIGH - Privileged containers can escape container isolation"
    echo "$PODS_DATA" | jq -r '
        .items[] | 
        select(.spec.containers[].securityContext.privileged == true) |
        "  🚨 Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Remove privileged flag"
    '
    
    echo "\n⚠️  *Pods with Host Path Volumes:*"
    echo "Severity: 🔴 HIGH - Host path access can lead to host system compromise"
    echo "$PODS_DATA" | jq -r '
        .items[] | 
        select(.spec.volumes[]?.hostPath != null) |
        "  📁 Namespace: \(.metadata.namespace), Pod: \(.metadata.name) | Remediation: Use persistent volumes"
    '
    
    echo "\n⚠️  *Pods Running as Root:*"
    echo "Severity: 🟡 MEDIUM - Running as root poses security risks"
    echo "$PODS_DATA" | jq -r '
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
    
    # Run kubectl commands in parallel
    kubectl get secrets --all-namespaces -o json > /tmp/secrets_data.json &
    SECRETS_PID=$!
    
    kubectl get pods --all-namespaces -o json > /tmp/pods_data.json &
    PODS_PID=$!
    
    # Wait for all data
    wait $SECRETS_PID $PODS_PID
    
    SECRETS_DATA=$(cat /tmp/secrets_data.json)
    PODS_DATA=$(cat /tmp/pods_data.json)
    
    # Cleanup
    rm /tmp/secrets_data.json /tmp/pods_data.json
    
    echo "📋 *Secrets in Default Namespace:*"
    echo "Severity: 🟡 MEDIUM - Secrets in default namespace may be accidentally exposed"
    echo "$SECRETS_DATA" | jq -r '
        .items[] | 
        select(.metadata.namespace == "default") |
        select(.type != "kubernetes.io/service-account-token") |
        "  ⚠️  Secret: \(.metadata.name) | Remediation: Move to dedicated namespace"
    '
    
    echo "\n📋 *Pods with Mounted Secrets:*"
    echo "Cross-reference with RBAC for access control review"
    echo "$PODS_DATA" | jq -r '
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
    
    # Run kubectl commands in parallel
    kubectl get networkpolicies --all-namespaces -o json > /tmp/netpol_data.json &
    NETPOL_PID=$!
    
    kubectl get ns -o json > /tmp/ns_data.json &
    NS_PID=$!
    
    # Wait for all data
    wait $NETPOL_PID $NS_PID
    
    NETPOL_DATA=$(cat /tmp/netpol_data.json)
    NS_DATA=$(cat /tmp/ns_data.json)
    
    # Cleanup
    rm /tmp/netpol_data.json /tmp/ns_data.json
    
    echo "⚠️  *Namespaces without Network Policies:*"
    echo "Severity: 🔴 HIGH - Namespaces without isolation"
    
    # Create an associative array of namespaces with policies
    declare -A ns_with_policies
    while IFS= read -r line; do
        ns_with_policies[$line]=1
    done < <(echo "$NETPOL_DATA" | jq -r '.items[].metadata.namespace' | sort -u)
    
    # Check namespaces without policies
    echo "$NS_DATA" | jq -r '.items[].metadata.name' | while read ns; do
        if [[ -z "${ns_with_policies[$ns]}" ]]; then
            echo "  🚨 Namespace: $ns | Remediation: Apply default deny policy"
        fi
    done
    
    echo "\n⚠️  *Overly Permissive Network Policies:*"
    echo "Severity: 🟡 MEDIUM - Policies allowing all ingress/egress"
    echo "$NETPOL_DATA" | jq -r '
        .items[] | 
        select(.spec.ingress[]?.from == null or .spec.egress[]?.to == null) |
        "  ⚠️  Namespace: \(.metadata.namespace), Policy: \(.metadata.name) | Remediation: Restrict traffic flows"
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