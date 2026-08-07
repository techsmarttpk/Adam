import jinja2
from typing import Any
from .markdown import MarkdownRenderer

class HTMLRenderer:
    def __init__(self):
        self.md_renderer = MarkdownRenderer()
        # Fallback simple jinja2 template
        self.template = jinja2.Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ADAM Report</title>
            <style>
                body { font-family: sans-serif; margin: 40px; }
                pre { background: #f4f4f4; padding: 10px; }
            </style>
        </head>
        <body>
            <pre>{{ content }}</pre>
        </body>
        </html>
        """)

    def render(self, data: dict[str, Any]) -> str:
        # Just reuse markdown for simplicity and wrap it in the Jinja template
        md_content = self.md_renderer.render(data)
        return self.template.render(content=md_content)
