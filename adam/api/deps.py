from adam.common.config import load_settings, Settings
from adam.common.bus import EventBus
from adam.db.connection import DbConnection
from adam.db.writer import DbWriter
from adam.db.repositories.sessions import SessionRepository
from adam.db.repositories.events import EventRepository
from adam.db.repositories.decisions import DecisionRepository
from adam.db.repositories.mutations import MutationRepository
from adam.sandbox.controller import SandboxController
from adam.fusion.engine import FusionEngine
from adam.policy.engine import PolicyEngine
from adam.deception.engine import DeceptionEngine

settings: Settings = load_settings()
event_bus: EventBus = EventBus(
    default_queue_size=settings.bus.default_queue_size,
    overflow_policy=settings.bus.overflow_policy,
)
db_conn: DbConnection = DbConnection(settings.db)
db_writer: DbWriter = DbWriter(db_conn, settings.db)

session_repo = SessionRepository(db_conn, db_writer)
event_repo = EventRepository(db_conn, db_writer)
decision_repo = DecisionRepository(db_conn, db_writer)
mutation_repo = MutationRepository(db_conn, db_writer)

from adam.orchestrator.serial_listener import WindowsNamedPipeServer

sandbox_controller = SandboxController(settings.sandbox)
fusion_engine = FusionEngine(settings.fusion, event_bus)
policy_engine = PolicyEngine(settings.policy, event_bus)
deception_engine = DeceptionEngine(sandbox_controller, event_bus)
serial_server = WindowsNamedPipeServer(settings.sandbox.serial_pipe_name, event_bus)

async def get_settings() -> Settings:
    return settings

async def get_event_bus() -> EventBus:
    return event_bus

async def get_session_repo() -> SessionRepository:
    return session_repo

async def get_event_repo() -> EventRepository:
    return event_repo

async def get_decision_repo() -> DecisionRepository:
    return decision_repo

async def get_mutation_repo() -> MutationRepository:
    return mutation_repo

async def get_sandbox_controller() -> SandboxController:
    return sandbox_controller

async def get_fusion_engine() -> FusionEngine:
    return fusion_engine

async def get_policy_engine() -> PolicyEngine:
    return policy_engine

async def get_deception_engine() -> DeceptionEngine:
    return deception_engine

agent_deployment_manager = sandbox_controller.deployment_manager

async def get_agent_deployment_manager():
    return agent_deployment_manager
