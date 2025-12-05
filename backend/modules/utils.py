from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any


@dataclass
class Event:
    # Injected by state.next_event_id()
    id: int

    # Automatic timestamp
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Required fields (generators must supply real values)
    source_ip: str = ""
    dest_port: int = 0

    # High-level flow categorization
    phase: str = "noise"            # noise | attack | replay | system | etc.
    category: str = "benign"        # portscan | brute_force | probe | benign | etc.
    severity: str = "benign"        # benign | suspicious | malicious | critical

    # Correlation fields
    chain_id: str | None = None      # shared across multi-event attack chains
    stage: str | None = None         # noise | recon | bruteforce | exploit | critical
    
    # Human-friendly + structured detail
    raw: str = ""                    # short description/title: "Healthcheck from bot"
    parsed: Dict[str, Any] = field(default_factory=dict)

    # Filled later by recommender
    recommendation: Dict[str, Any] = field(default_factory=dict)
