class ObservationMutations:
    """Observation-Preserving and Measurement-Enabling Mutations.
    
    Distinct from deception lures; these protect and extend ADAM's instrumentation and telemetry capture.
    """
    PRIMITIVES = [
        "ACTIVATE_EPT_MEMORY_CAPTURE",
        "ENABLE_PROCESS_TRACKING",
        "ENABLE_FILE_ACTIVITY_MONITOR",
        "PRESERVE_FORENSIC_ARTIFACT",
        "ENABLE_NETWORK_CAPTURE",
        "EXTEND_CAPTURE_WINDOW",
        "ENABLE_STAGE_TRACKING",
        "ACTIVATE_MEMORY_MONITOR",
        "ACTIVATE_EPT_SHADOW_HOOK"
    ]
