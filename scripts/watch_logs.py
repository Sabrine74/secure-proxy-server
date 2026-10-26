"""Live dashboard: tails logs/proxy.log and shows colored, readable events."""
import time
from pathlib import Path
from rich.console import Console
from rich.text import Text

LOG_FILE = Path("logs/proxy.log")
console = Console()

def colorize(line: str) -> Text:
    t = Text(line.rstrip())
    if "authenticated as" in line:
        t.stylize("bold green")
    elif "401" in line or "Unauthorized" in line:
        t.stylize("bold red")
    elif "403" in line or "Forbidden" in line:
        t.stylize("bold red")
    elif "408" in line or "timeout" in line:
        t.stylize("bold yellow")
    elif "500" in line or "502" in line:
        t.stylize("bold magenta")
    elif "listening" in line or "===" in line:
        t.stylize("bold cyan")
    elif "done:" in line:
        t.stylize("dim")
    return t

def main():
    console.rule("[bold cyan]Secure Proxy — Live Log Dashboard[/bold cyan]")
    if not LOG_FILE.exists():
        console.print(f"[red]Log file not found: {LOG_FILE}[/red]")
        console.print("Start the proxy first (Terminal B), then rerun this.")
        return
    with LOG_FILE.open("r") as f:
        f.seek(0, 2)  # only show new lines from now on
        console.print("[dim]Watching for new events... (Ctrl+C to stop)[/dim]\n")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            console.print(colorize(line))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")
