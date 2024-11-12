from kubiya_sdk.tools import Tool

ZOOM_ICON_URL = "https://seeklogo.com/images/Z/zoom-icon-logo-C552F99BAB-seeklogo.com.png"

class ZoomTool(Tool):
    def __init__(
        self,
        name,
        description,
        content,
        args=[],
        env=[],
        secrets=["ZOOM_API_KEY", "ZOOM_API_SECRET"],
        long_running=False,
        with_files=None,
        image="python:3.9-alpine",
        mermaid=None
    ):
        # Add common setup for all Zoom tools
        setup_script = """
        #!/bin/sh
        set -e

        # Install required packages
        apk add --no-cache curl jq

        # Install Python packages
        pip install --no-cache-dir zoomus requests
        """
        
        full_content = setup_script + "\n" + content

        super().__init__(
            name=name,
            description=description,
            icon_url=ZOOM_ICON_URL,
            type="docker",
            image=image,
            content=full_content,
            args=args,
            env=env,
            secrets=secrets,
            long_running=long_running,
            with_files=with_files,
            mermaid=mermaid
        ) 