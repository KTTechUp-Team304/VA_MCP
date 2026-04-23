import sys
from va_mcp.app import create_app

mcp = create_app()

def main() -> None:
    print("[va-mcp] stdio server starting...", file=sys.stderr, flush=True)
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()