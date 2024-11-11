from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

def create_jq_filter(severity="HIGH"):
    """Helper to format output with severity levels"""
    return f'"\u001b[31m[{severity}]\u001b[0m"' if severity == "HIGH" else \
           f'"\u001b[33m[{severity}]\u001b[0m"' if severity == "MEDIUM" else \
           f'"\u001b[32m[{severity}]\u001b[0m"'

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
        jq -c --arg HIGH ${create_jq_filter("HIGH")} '
            .items[].spec.containers[].command[] | 
            select(
                contains("--anonymous-auth=true") or
                contains("--authorization-mode=AlwaysAllow")
            ) | [$HIGH, "Insecure API Server Config:", .]
        '
    ) &
    
    (
        # Namespace analysis
        kubectl get ns -o json | \
        jq -c --arg HIGH ${create_jq_filter("HIGH")} '
            .items[] | 
            select(.metadata.labels["pod-security.kubernetes.io/enforce"] != "restricted") |
            [$HIGH, "Missing Pod Security:", .metadata.name]
        '
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
    jq -c --arg HIGH ${create_jq_filter("HIGH")} '
        .items[] | 
        select(.spec.ingress == null) |
        [$HIGH, "No Ingress Rules:", .metadata.namespace + "/" + .metadata.name]
    ' /tmp/netpol.json
    
    # Store namespaces with policies
    jq -r '.items[].metadata.namespace' /tmp/netpol.json | sort -u > /tmp/ns_with_policies.txt
    
    # Compare against all namespaces
    jq -r '.items[].metadata.name' /tmp/ns.json | while read ns; do
        if ! grep -q "^${ns}$" /tmp/ns_with_policies.txt; then
            echo "[HIGH] No Network Policies: ${ns}"
        fi
    done
    
    rm /tmp/netpol.json /tmp/ns.json /tmp/ns_with_policies.txt
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
    jq -c --arg HIGH ${create_jq_filter("HIGH")} '
        .items[] | 
        select(
            .rules[].verbs[] == "*" and
            .rules[].resources[] == "*"
        ) |
        [$HIGH, "Wildcard Permissions:", .metadata.name]
    ' /tmp/roles.json
    
    jq -c --arg HIGH ${create_jq_filter("HIGH")} '
        .items[] | 
        select(
            .subjects[].kind == "ServiceAccount" and
            .roleRef.kind == "ClusterRole"
        ) |
        [$HIGH, "SA with Cluster Rights:", .metadata.namespace + "/" + .subjects[0].name]
    ' /tmp/bindings.json
    
    rm /tmp/roles.json /tmp/bindings.json
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
    jq -c --arg HIGH ${create_jq_filter("HIGH")} '
        .items[] | 
        select(
            .type != "kubernetes.io/service-account-token" and
            .metadata.namespace == "default"
        ) |
        [$HIGH, "Secret in Default NS:", .metadata.name]
    ' /tmp/secrets.json
    
    jq -c --arg MED ${create_jq_filter("MEDIUM")} '
        .items[] | 
        select(.spec.volumes[]?.secret != null) |
        [$MED, "Secret Mount:", .metadata.namespace + "/" + .metadata.name]
    ' /tmp/pods.json
    
    rm /tmp/secrets.json /tmp/pods.json
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
    jq -c --arg HIGH ${create_jq_filter("HIGH")} '
        .items[] | 
        .spec.containers[] | 
        select(
            (.image | contains(":latest")) or
            (.imagePullPolicy != "Always")
        ) |
        [$HIGH, "Image Security:", .image]
    ' /tmp/pods.json
    
    rm /tmp/pods.json
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