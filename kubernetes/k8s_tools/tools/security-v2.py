from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

def create_jq_filter(severity="HIGH"):
    """Helper to format output with severity levels"""
    if severity == "HIGH":
        return "'\\u001b[31m[HIGH]\\u001b[0m'"
    elif severity == "MEDIUM":
        return "'\\u001b[33m[MEDIUM]\\u001b[0m'"
    else:
        return "'\\u001b[32m[LOW]\\u001b[0m'"

cluster_hardening_tool = KubernetesTool(
    name="cluster_hardening_analyzer",
    description="Analyzes cluster hardening according to CNCF security guidelines",
    content="""
    #!/bin/bash
    set -e
    
    echo "🔒 *Critical Security Findings:*"
    
    # Parallel execution using subshell
    (
        # API server analysis
        kubectl get pods -n kube-system -l component=kube-apiserver -o json | \
        jq -r '.items[].spec.containers[].command[] | 
            select(
                contains("--anonymous-auth=true") or
                contains("--authorization-mode=AlwaysAllow")
            ) | "\\u001b[31m[HIGH]\\u001b[0m Insecure API Server Config: " + .'
    ) &
    
    (
        # Namespace analysis
        kubectl get ns -o json | \
        jq -r '.items[] | 
            select(.metadata.labels["pod-security.kubernetes.io/enforce"] != "restricted") |
            "\\u001b[31m[HIGH]\\u001b[0m Missing Pod Security: " + .metadata.name'
    ) &
    
    wait
    """,
    args=[],
)

network_security_tool = KubernetesTool(
    name="network_security_analyzer",
    description="Analyzes network security according to CNCF guidelines",
    content="""
    #!/bin/bash
    set -e
    
    # Parallel data collection
    kubectl get netpol --all-namespaces -o json > /tmp/netpol.json &
    kubectl get ns -o json > /tmp/ns.json &
    wait
    
    echo "🌐 *Network Security Risks:*"
    
    # Focused output - only critical findings
    jq -r '.items[] | 
        select(.spec.ingress == null) |
        "\\u001b[31m[HIGH]\\u001b[0m No Ingress Rules: " + .metadata.namespace + "/" + .metadata.name
    ' /tmp/netpol.json
    
    # Compare against all namespaces
    comm -23 \
        <(jq -r '.items[].metadata.name' /tmp/ns.json | sort) \
        <(jq -r '.items[].metadata.namespace' /tmp/netpol.json | sort -u) | \
    while read ns; do
        echo -e "\\u001b[31m[HIGH]\\u001b[0m No Network Policies: ${ns}"
    done
    
    rm -f /tmp/netpol.json /tmp/ns.json
    """,
    args=[],
)

auth_security_tool = KubernetesTool(
    name="auth_security_analyzer",
    description="Analyzes authentication and authorization according to CNCF guidelines",
    content="""
    #!/bin/bash
    set -e
    
    # Parallel data collection
    kubectl get clusterroles -o json > /tmp/roles.json &
    kubectl get rolebindings,clusterrolebindings -A -o json > /tmp/bindings.json &
    wait
    
    echo "🔑 *Auth Security Risks:*"
    
    # Only show high-risk configurations
    jq -r '.items[] | 
        select(
            .rules[].verbs[] == "*" and
            .rules[].resources[] == "*"
        ) |
        "\\u001b[31m[HIGH]\\u001b[0m Wildcard Permissions: " + .metadata.name
    ' /tmp/roles.json
    
    jq -r '.items[] | 
        select(
            .subjects[].kind == "ServiceAccount" and
            .roleRef.kind == "ClusterRole"
        ) |
        "\\u001b[31m[HIGH]\\u001b[0m SA with Cluster Rights: " + 
        (.metadata.namespace // "cluster-wide") + "/" + .subjects[0].name
    ' /tmp/bindings.json
    
    rm -f /tmp/roles.json /tmp/bindings.json
    """,
    args=[],
)

secret_security_tool = KubernetesTool(
    name="secret_security_analyzer",
    description="Analyzes secret management according to CNCF guidelines",
    content="""
    #!/bin/bash
    set -e
    
    # Parallel data collection
    kubectl get secrets -A -o json > /tmp/secrets.json &
    kubectl get pods -A -o json > /tmp/pods.json &
    wait
    
    echo "🔐 *Secret Security Risks:*"
    
    # Focus on critical secret issues
    jq -r '.items[] | 
        select(
            .type != "kubernetes.io/service-account-token" and
            .metadata.namespace == "default"
        ) |
        "\\u001b[31m[HIGH]\\u001b[0m Secret in Default NS: " + .metadata.name
    ' /tmp/secrets.json
    
    jq -r '.items[] | 
        select(.spec.volumes[]?.secret != null) |
        "\\u001b[33m[MEDIUM]\\u001b[0m Secret Mount: " + .metadata.namespace + "/" + .metadata.name
    ' /tmp/pods.json
    
    rm -f /tmp/secrets.json /tmp/pods.json
    """,
    args=[],
)

supply_chain_tool = KubernetesTool(
    name="supply_chain_analyzer",
    description="Analyzes supply chain security according to CNCF guidelines",
    content="""
    #!/bin/bash
    set -e
    
    # Single data collection since we're only analyzing pods
    kubectl get pods -A -o json > /tmp/pods.json
    
    echo "📦 *Supply Chain Risks:*"
    
    # Focus on critical image security issues
    jq -r '.items[] | 
        .spec.containers[] | 
        select(
            (.image | contains(":latest")) or
            (.imagePullPolicy != "Always")
        ) |
        "\\u001b[31m[HIGH]\\u001b[0m Image Security: " + .image
    ' /tmp/pods.json
    
    rm -f /tmp/pods.json
    """,
    args=[],
)

# Register all tools
security_tools = [
    cluster_hardening_tool,
    network_security_tool,
    auth_security_tool,
    secret_security_tool,
    supply_chain_tool
]

for tool in security_tools:
    tool_registry.register("kubernetes", tool)