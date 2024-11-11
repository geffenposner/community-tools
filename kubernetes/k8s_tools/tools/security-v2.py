from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

cluster_hardening_tool = KubernetesTool(
    name="cluster_hardening_analyzer",
    description="Performs comprehensive cluster security assessment focusing on control plane configurations and pod security standards",
    content="""
    #!/bin/bash
    set -e
    
    # API server analysis
    kubectl get pods -n kube-system -l component=kube-apiserver -o json | \
    jq -r '.items[].spec.containers[].command[] | 
        select(
            contains("--anonymous-auth=true") or
            contains("--authorization-mode=AlwaysAllow")
        ) | "Insecure API Server Config: " + .'
    
    # Namespace analysis
    kubectl get ns -o json | \
    jq -r '.items[] | 
        select(.metadata.labels["pod-security.kubernetes.io/enforce"] != "restricted") |
        "Missing Pod Security: " + .metadata.name'
    """,
    args=[],
)

network_security_tool = KubernetesTool(
    name="network_security_analyzer",
    description="Evaluates cluster-wide network isolation and traffic control patterns",
    content="""
    #!/bin/bash
    set -e
    
    kubectl get netpol --all-namespaces -o json > /tmp/netpol.json
    kubectl get ns -o json > /tmp/ns.json
    
    # Check for missing ingress rules
    jq -r '.items[] | 
        select(.spec.ingress | length == 0) |
        "No Ingress Rules: " + .metadata.namespace + "/" + .metadata.name
    ' /tmp/netpol.json
    
    # Find namespaces without network policies
    join -v 1 \
        <(jq -r '.items[].metadata.name' /tmp/ns.json | sort) \
        <(jq -r '.items[].metadata.namespace' /tmp/netpol.json | sort -u) | \
    while read ns; do
        echo "No Network Policies: ${ns}"
    done
    
    rm -f /tmp/netpol.json /tmp/ns.json
    """,
    args=[],
)

auth_security_tool = KubernetesTool(
    name="auth_security_analyzer",
    description="Examines authentication mechanisms and permission configurations across the cluster",
    content="""
    #!/bin/bash
    set -e
    
    kubectl get clusterroles -o json > /tmp/roles.json
    kubectl get rolebindings,clusterrolebindings -A -o json > /tmp/bindings.json
    
    # Check for wildcard permissions
    jq -r '.items[] | 
        select(
            (.rules // [])[] | 
            select(
                (.verbs // [])[] == "*" and
                (.resources // [])[] == "*"
            )
        ) |
        "Wildcard Permissions: " + .metadata.name
    ' /tmp/roles.json
    
    # Check for service accounts with cluster rights
    jq -r '.items[] | 
        select(
            (.subjects // [])[] | 
            select(
                .kind == "ServiceAccount"
            )
        ) |
        select(.roleRef.kind == "ClusterRole") |
        "SA with Cluster Rights: " + 
        (.metadata.namespace // "cluster-wide") + "/" + 
        (.subjects[0].name // "unknown")
    ' /tmp/bindings.json
    
    rm -f /tmp/roles.json /tmp/bindings.json
    """,
    args=[],
)

secret_security_tool = KubernetesTool(
    name="secret_security_analyzer",
    description="Analyzes sensitive data handling practices and secret storage configurations",
    content="""
    #!/bin/bash
    set -e
    
    kubectl get secrets -A -o json > /tmp/secrets.json
    kubectl get pods -A -o json > /tmp/pods.json
    
    # Check for secrets in default namespace
    jq -r '.items[] | 
        select(
            .type != "kubernetes.io/service-account-token" and
            .metadata.namespace == "default"
        ) |
        "Secret in Default NS: " + .metadata.name
    ' /tmp/secrets.json
    
    # Check for secret mounts
    jq -r '.items[] | 
        select(.spec.volumes[]?.secret != null) |
        "Secret Mount: " + .metadata.namespace + "/" + .metadata.name
    ' /tmp/pods.json
    
    rm -f /tmp/secrets.json /tmp/pods.json
    """,
    args=[],
)

supply_chain_tool = KubernetesTool(
    name="supply_chain_analyzer",
    description="Evaluates container image security and workload configurations",
    content="""
    #!/bin/bash
    set -e
    
    kubectl get pods -A -o json > /tmp/pods.json
    
    # Check image security issues
    jq -r '.items[] | 
        .spec.containers[] | 
        select(
            (.image | contains(":latest")) or
            (.imagePullPolicy != "Always")
        ) |
        "Image Security Issue: " + .image
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