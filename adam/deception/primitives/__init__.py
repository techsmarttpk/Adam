from .filesystem_lures import FilesystemLures
from .registry_lures import RegistryLures
from .network_lures import NetworkLures
from .process_lures import ProcessLures
from .observation_mutations import ObservationMutations

ALL_PRIMITIVES = (
    FilesystemLures.PRIMITIVES
    + RegistryLures.PRIMITIVES
    + NetworkLures.PRIMITIVES
    + ProcessLures.PRIMITIVES
    + ObservationMutations.PRIMITIVES
)
