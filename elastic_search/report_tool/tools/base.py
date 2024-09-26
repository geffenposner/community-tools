from kubiya_sdk.tools.models import Tool

REPORT_ICON_URL = "https://example.com/report-icon.png"  # Replace with an appropriate icon URL

class ReportTool(Tool):
    def __init__(self, name, description, content, args, long_running=False, mermaid_diagram=None):
        super().__init__(
            name=name,
            description=description,
            icon_url=REPORT_ICON_URL,
            type="python",
            content=content,
            args=args,
            requirements=["requests", "boto3", "kubiya-sdk"],
            env=["ES_USER", "ES_PASS"],
            long_running=long_running,
            mermaid=mermaid_diagram,
            requirements=["requests", "boto3", "kubiya-sdk"],
            # image="python:3.8-alpine"
        )
