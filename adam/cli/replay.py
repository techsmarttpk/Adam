import typer
import asyncio
import json
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
import hashlib

from adam.contracts.envelope import Envelope
from adam.contracts.raw_event import RawEvent
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics
from adam.contracts.enums import Arm, SessionStatus, NetworkMode
from adam.api.deps import init_dependencies, shutdown_dependencies, deps

console = Console()

def replay_main(
    log_path: str = typer.Argument(..., help="Path to raw.jsonl or 'synthetic' to run generated events"),
):
    """Replay a session offline via Fusion -> Policy -> Deception."""
    
    async def _run():
        await init_dependencies()
        try:
            import uuid
            session_id = f"replay_{uuid.uuid4().hex[:8]}"
            experiment_id = "exp_replay"
            
            sample = SampleRef(
                sha256="a"*64,
                md5="b"*32,
                filename="replay.exe",
                size_bytes=1024,
                file_type="binary"
            )
            config = SessionConfig(
                deception_enabled=True,
                policy_ruleset="default",
                vm_profile="windows-10",
                timeout_seconds=300,
                network_mode=NetworkMode.SIMULATED
            )
            metadata = AnalysisSession(
                session_id=session_id,
                experiment_id=experiment_id,
                arm=Arm.TREATMENT,
                sample=sample,
                config=config,
                status=SessionStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
                metrics=SessionMetrics()
            )
            await deps.session_repo.create(metadata)
            
            events_to_replay = []
            
            if log_path == "synthetic":
                from adam.fusion.log_generate import generate_attack_chain, generate_benign_events
                import random
                random.seed(42)
                start_time = datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)
                attack_events = generate_attack_chain("WKSTN-666", "j.smith", start_time)
                benign_events = generate_benign_events(50, start_time)
                all_events = benign_events + attack_events
                random.shuffle(all_events)
                
                for ev in all_events:
                    try:
                        ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
                    except:
                        ts = datetime.now(timezone.utc)
                    raw_event = RawEvent(
                        event_id=f"raw_{uuid.uuid4().hex[:8]}",
                        session_id=session_id,
                        source="SYSMON",
                        source_event_id=1,
                        category="PROCESS",
                        occurred_at=ts,
                        observed_at=datetime.now(timezone.utc),
                        attributes=ev
                    )
                    env = Envelope[RawEvent](
                        envelope_version="1.0",
                        message_id=str(uuid.uuid4()),
                        message_type="RawEvent",
                        session_id=session_id,
                        correlation_id=f"corr_{uuid.uuid4().hex[:8]}",
                        emitted_at=datetime.now(timezone.utc),
                        emitter="sim",
                        payload=raw_event
                    )
                    events_to_replay.append(env)
            else:
                p = Path(log_path)
                if not p.is_file():
                    console.print(f"[red]error:[/red] file not found: {log_path}")
                    raise typer.Exit(code=2)
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        data = json.loads(line)
                        if data.get("message_type") == "RawEvent":
                            env = Envelope[RawEvent].model_validate(data)
                            # Override session_id so it gets processed correctly in this run
                            env.session_id = session_id
                            env.payload.session_id = session_id
                            events_to_replay.append(env)

            console.print(f"Replaying {len(events_to_replay)} events for session {session_id}...")
            
            for env in events_to_replay:
                await deps.bus.publish(env)
            
            # Allow some time for bus handlers to flush
            await asyncio.sleep(0.5)
            
            metadata.status = SessionStatus.COMPLETED
            metadata.ended_at = datetime.now(timezone.utc)
            metadata.metrics.raw_events = len(events_to_replay)
            await deps.session_repo.update(metadata)
            
            # Fetch summary
            decisions = await deps.decision_repo.get_by_session(session_id)
            mutations = await deps.mutation_repo.get_by_session(session_id)
            semantic_events = await deps.event_repo.get_semantic_by_session(session_id)
            
            console.print(f"[green]Replay complete.[/green]")
            console.print(f"Semantic Events: {len(semantic_events)}")
            console.print(f"Policy Decisions: {len(decisions)}")
            console.print(f"Mutations Applied: {len(mutations)}")
            console.print(f"Session ID: {session_id}")
            
        finally:
            await shutdown_dependencies()

    asyncio.run(_run())
