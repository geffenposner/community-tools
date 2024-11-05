from kubiya_sdk.tools import Arg
from .base import KubernetesTool
from kubiya_sdk.tools.registry import tool_registry

service_management_tool = KubernetesTool(
    name="service_management",
    description="Creates, deletes, or retrieves information on a Kubernetes service.",
    content="""
    #!/bin/bash
    set -e

    # Ensure namespace is provided
    if [ -z "$namespace" ]; then
        echo "❌ Error: Namespace is required to manage a specific service."
        exit 1
    fi

    # Define flags for service creation
    namespace_flag="-n $namespace"
    type_flag=$( [ "$action" = "create" ] && [ -n "$type" ] && echo "--type=$type" || echo "" )
    port_flag=$( [ "$action" = "create" ] && [ -n "$port" ] && echo "--port=$port" || echo "" )
    target_port_flag=$( [ "$action" = "create" ] && [ -n "$target_port" ] && echo "--target-port=$target_port" || echo "" )

    # Execute the kubectl command
    kubectl $action service $name $type_flag $port_flag $target_port_flag $namespace_flag
    """,
    args=[
        Arg(name="action", type="str", description="Action to perform (create, delete, get)", required=True),
        Arg(name="name", type="str", description="Name of the service", required=True),
        Arg(name="namespace", type="str", description="Kubernetes namespace (required for managing a specific service)", required=True),
        Arg(name="type", type="str", description="Type of service (ClusterIP, NodePort, LoadBalancer) - only for create action", required=False),
        Arg(name="port", type="int", description="Port number - only for create action", required=False),
        Arg(name="target_port", type="int", description="Target port number - only for create action", required=False),
    ],
)

service_update_tool = KubernetesTool(
    name="service_update",
    description="Updates the type, port, or target port for an existing Kubernetes service.",
    content="""
    #!/bin/bash
    set -e

    # Ensure namespace is provided
    if [ -z "$namespace" ]; then
        echo "❌ Error: Namespace is required to update a specific service."
        exit 1
    fi

    # Start with an empty object and build it using jq
    jq_filter='.spec = {}'
    
    # Add type if provided
    if [ -n "${type:-}" ]; then
        jq_filter="$jq_filter | .spec.type = \$type"
    fi

    # Add ports if either port or target_port is provided
    if [ -n "${port:-}" ] || [ -n "${target_port:-}" ]; then
        # Start building the port object filter
        port_obj='{}'
        
        if [ -n "${port:-}" ]; then
            jq_filter="$jq_filter | .spec.ports = [{\\\"port\\\": \$port"
            if [ -n "${target_port:-}" ]; then
                jq_filter="$jq_filter, \\\"targetPort\\\": \$targetPort}]"
            else
                jq_filter="$jq_filter}]"
            fi
        elif [ -n "${target_port:-}" ]; then
            jq_filter="$jq_filter | .spec.ports = [{\\\"targetPort\\\": \$targetPort}]"
        fi
    fi

    # Build the final patch content
    patch_args=()
    if [ -n "${type:-}" ]; then
        patch_args+=(--arg type "$type")
    fi
    if [ -n "${port:-}" ]; then
        patch_args+=(--argjson port "$port")
    fi
    if [ -n "${target_port:-}" ]; then
        patch_args+=(--argjson targetPort "$target_port")
    fi

    patch_content=$(echo '{}' | jq "${patch_args[@]}" "$jq_filter")

    # Debug: Output the final patch content for verification
    echo "Patch content: $patch_content"

    # Ensure that something valid was added to the patch
    if [ "$patch_content" = "{\"spec\": {}}" ]; then
        echo "❌ Error: No valid fields provided for update."
        exit 1
    fi

    # Execute the kubectl patch command
    kubectl patch service $name -n $namespace -p "$patch_content"
    """,
    args=[
        Arg(name="name", type="str", description="Name of the service", required=True),
        Arg(name="namespace", type="str", description="Kubernetes namespace (required for updating a specific service)", required=True),
        Arg(name="type", type="str", description="New type for the service (ClusterIP, NodePort, LoadBalancer)", required=False),
        Arg(name="port", type="int", description="New port number", required=False),
        Arg(name="target_port", type="int", description="New target port number", required=False),
    ],
)


# Service Describe Tool
service_describe_tool = KubernetesTool(
    name="service_describe",
    description="Describes a Kubernetes service, providing detailed configuration and status information.",
    content="""
    #!/bin/bash
    set -e

    # Ensure namespace is provided
    if [ -z "$namespace" ]; then
        echo "❌ Error: Namespace is required to describe a specific service."
        exit 1
    fi

    # Describe the service
    kubectl describe service $name -n $namespace
    """,
    args=[
        Arg(name="name", type="str", description="Name of the service", required=True),
        Arg(name="namespace", type="str", description="Kubernetes namespace (required for describing a specific service)", required=True),
    ],
)

# Register Tools
for tool in [
    service_management_tool,
    service_update_tool,
    service_describe_tool,
]:
    tool_registry.register("kubernetes", tool)
