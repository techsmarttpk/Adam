"""
adam/sandbox/vbox/ntstatus.py

Decodes well-known Windows NTSTATUS values into their symbolic names, for
attaching to VMOperationResult.termination_reason (see models.py).

This is a decoding step, not an interpretation step. It does not change
whether an operation is considered successful, and it does not explain why
a code occurred -- e.g. it will decode 0xC0000374 to "STATUS_HEAP_CORRUPTION"
but has nothing to say about the fact that this specific code is a known
symptom of cmd.exe crashing during shutdown when launched without an
attached console (see client.py's guest-execution section for that context;
that reasoning belongs to whatever consumes this result, not to this table).

Not exhaustive -- covers common process-crash / abnormal-termination codes
likely to show up as a Windows process's reported exit code. This is a flat
lookup table, not a framework: extend it by adding entries as new codes are
observed in practice.
"""

from __future__ import annotations

_KNOWN_NTSTATUS: dict[int, str] = {
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "STATUS_INTEGER_OVERFLOW",
    0xC0000135: "STATUS_DLL_NOT_FOUND",
    0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
    0xC0000142: "STATUS_DLL_INIT_FAILED",
    0xC000013A: "STATUS_CONTROL_C_EXIT",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC0000420: "STATUS_ASSERTION_FAILURE",
    0x80000003: "STATUS_BREAKPOINT",
}


def decode_ntstatus(return_code: int | None) -> str | None:
    """
    Return the symbolic name for return_code if it matches a well-known
    Windows NTSTATUS value, else None. None in, None out.

    Deliberately a simple dict lookup, not a bitmask/severity decomposition --
    ADAM only needs to recognize specific known values (a name to show a
    person reading a result), not a general-purpose NTSTATUS parser.
    """
    if return_code is None:
        return None
    return _KNOWN_NTSTATUS.get(return_code)
