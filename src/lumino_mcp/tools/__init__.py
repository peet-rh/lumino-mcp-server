"""Tool modules for Lumino MCP server.

Each module registers tools by importing mcp from server.py and using @mcp.tool().
Import all modules here to trigger registration.
"""

from . import pipeline
from . import events
from . import logs
from . import diagnostics
from . import prom
