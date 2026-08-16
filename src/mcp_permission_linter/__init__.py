"""Static least-privilege checks for MCP server and tool manifests."""

from .analyzer import analyze_document, analyze_path
from .models import Finding, Severity

__all__ = ["Finding", "Severity", "analyze_document", "analyze_path"]
__version__ = "0.1.1"
