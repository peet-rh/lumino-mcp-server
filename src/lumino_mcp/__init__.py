import click


@click.command()
@click.option("--transport", default="stdio", help="MCP transport: stdio or sse")
def main(transport: str):
    from .server import mcp
    mcp.run(transport=transport)
