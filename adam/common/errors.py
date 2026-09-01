class AdamError(Exception):
    """Base exception for all ADAM operations."""
    pass

class ConfigError(AdamError):
    """Invalid or missing configuration."""
    pass

class ContractViolationError(AdamError):
    """A message failed schema validation."""
    pass

class SandboxError(AdamError):
    """Base error for sandbox and VM operations."""
    pass

class VMOperationError(SandboxError):
    """Subprocess or QEMU operational command failure."""
    pass

class SandboxStateError(SandboxError):
    """Illegal FSM state transition."""
    pass

class GuestTimeoutError(SandboxError):
    """Guest agent or system unresponsive."""
    pass

class SampleTransferError(SandboxError):
    """Failure to copy sample binary to guest."""
    pass

class CollectorError(AdamError):
    """Base error for telemetry collectors."""
    pass

class ParserError(CollectorError):
    """Failed to parse log or pcap entry."""
    pass

class SourceUnavailableError(CollectorError):
    """Telemetry log or network interface unavailable."""
    pass

class FusionError(AdamError):
    """Base error for telemetry fusion engine."""
    pass

class DetectorError(FusionError):
    """A specific semantic detector raised an exception."""
    pass

class PolicyError(AdamError):
    """Base error for policy engine."""
    pass

class RuleSyntaxError(PolicyError):
    """Malformed policy YAML syntax."""
    pass

class RuleCompilationError(PolicyError):
    """Failed to compile YAML logic into predicate structures."""
    pass

class PredicateError(PolicyError):
    """Custom Python predicate failed at runtime."""
    pass

class DeceptionError(AdamError):
    """Base error for deception mutation engine."""
    pass

class PrimitiveError(DeceptionError):
    """Deception primitive failed initialization."""
    pass

class MutationFailedError(DeceptionError):
    """Failure during environment modification execution."""
    pass

class PersistenceError(AdamError):
    """Database read/write exception."""
    pass

class ReportingError(AdamError):
    """Failed to generate comparison report."""
    pass
