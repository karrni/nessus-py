from dataclasses import dataclass, field


@dataclass
class ScanCreateSettings:
    """Not complete, only the necessary settings."""

    name: str
    text_targets: str
    description: str = None

    enabled: bool = True

    policy_id: int = None
    folder_id: int = None
