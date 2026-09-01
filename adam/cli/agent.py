import typer
import httpx
import asyncio
from rich.console import Console
from rich.table import Table

console = Console()
app = typer.Typer(help="ADAM Guest Agent Management CLI")

@app.command("status")
def status():
    """Queries and displays live guest agent version and SHA-256 synchronization status."""
    try:
        resp = httpx.get("http://127.0.0.1:8000/api/v1/agent/status", timeout=3.0)
        if resp.status_code != 200:
            console.print(f"[bold red]Failed to fetch status:[/] HTTP {resp.status_code}")
            return
        data = resp.json()

        table = Table(title="ADAM Guest Agent Status", title_style="bold cyan")
        table.add_column("Property", style="bold")
        table.add_column("Host Canonical", style="green")
        table.add_column("Guest Deployed", style="yellow")

        table.add_row("Agent Version", data["host"].get("version", "unknown"), data["guest"].get("version", "unknown"))
        table.add_row("SHA-256 Hash", data["host"].get("sha256", "")[:16] + "...", data["guest"].get("sha256", "")[:16] + "..." if data["guest"].get("sha256") else "Unreachable")
        table.add_row("Reachable", "N/A", "YES" if data["guest"].get("reachable") else "NO")
        table.add_row("Status Badge", data["sync_status"], data["guest"].get("status", "unknown"))

        console.print(table)
        if data["sync_status"] == "CURRENT":
            console.print("[bold green]✓ Agent is fully synchronized with host.[/]")
        elif data["sync_status"] == "UPDATE_AVAILABLE":
            console.print("[bold yellow]⚠ Update available. Run 'python -m adam.cli.agent deploy' to synchronize.[/]")
        else:
            console.print("[bold red]⚠ Guest VM agent is unreachable.[/]")

    except Exception as e:
        console.print(f"[bold red]Error querying agent status:[/] {e}")

@app.command("deploy")
def deploy(session_id: str = typer.Option("sess_continuous_live", help="Target session ID")):
    """Synchronizes the host-side adam_agent.ps1 to the guest VM and reloads the agent process."""
    try:
        console.print("[cyan]Initiating automatic agent deployment...[/]")
        resp = httpx.post(
            "http://127.0.0.1:8000/api/v1/agent/deploy",
            json={"session_id": session_id},
            timeout=20.0
        )
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[bold green]✓ {data.get('message', 'Success')}[/] (Took {data.get('duration_seconds', 0):.2f}s)")
            console.print(f"[green]Verified SHA-256: {data.get('guest_sha256', '')}[/]")
        else:
            console.print(f"[bold red]Deployment failed:[/] {resp.text}")
    except Exception as e:
        console.print(f"[bold red]Error deploying agent:[/] {e}")

@app.command("restart")
def restart(session_id: str = typer.Option("sess_continuous_live", help="Target session ID")):
    """Triggers clean single-instance restart of the guest agent."""
    try:
        console.print("[cyan]Triggering agent restart...[/]")
        resp = httpx.post(
            "http://127.0.0.1:8000/api/v1/agent/restart",
            json={"session_id": session_id},
            timeout=20.0
        )
        if resp.status_code == 200:
            console.print("[bold green]✓ Agent restarted successfully.[/]")
        else:
            console.print(f"[bold red]Restart failed:[/] {resp.text}")
    except Exception as e:
        console.print(f"[bold red]Error restarting agent:[/] {e}")

if __name__ == "__main__":
    app()
