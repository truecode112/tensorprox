from pydantic import Field, BaseModel
import bittensor as bt
from typing import Dict, Tuple
from tensorprox import *
from tensorprox import settings
settings.settings = settings.Settings.load(mode="validator")
settings = settings.settings

class MachineDetails(BaseModel):
    ip: str | None = None
    username: str | None = None
    private_ip: str | None = None
    
    def get(self, key, default=None):
        return getattr(self, key, default)
    
class MachineConfig(BaseModel):
    key_pair: Tuple[str, str] = ("", "")
    traffic_generators: list[MachineDetails] = []
    infra_nodes: Dict[str, MachineDetails] = {
        "king": MachineDetails(),
        "moat": MachineDetails(),
    }
    
class AvailabilitySynapse(bt.Synapse):
    """AvailabilitySynapse is a specialized implementation of the `Synapse` class used to allow miners to let validators know
    about their status/availability to serve certain tasks"""
    task_availabilities: dict[str, bool]

class PingSynapse(bt.Synapse):
    machine_availabilities: MachineConfig = Field(
        default_factory=MachineConfig,
        title="Machine's Availabilities",
        description="Contains both traffic generators and fixed infra nodes (king, moat).",
        allow_mutation=True,
    )

    def serialize(self) -> dict:
        return {
            "machine_availabilities": {
                "key_pair": self.machine_availabilities.key_pair,
                "traffic_generators": [m.dict() for m in self.machine_availabilities.traffic_generators],
                "infra_nodes": {
                    role: node.dict() for role, node in self.machine_availabilities.infra_nodes.items()
                },
            },
        }

    @classmethod
    def deserialize(cls, data: dict) -> "PingSynapse":
        avail_data = data.get("machine_availabilities", {})
        return cls(
            machine_availabilities=MachineConfig(
                key_pair=tuple(avail_data.get("key_pair", ("", ""))),
                traffic_generators=[
                    MachineDetails(**m) for m in avail_data.get("traffic_generators", [])
                ],
                infra_nodes={
                    role: MachineDetails(**node)
                    for role, node in avail_data.get("infra_nodes", {}).items()
                },
            ),
        )


class ChallengeSynapse(bt.Synapse):
    """
    Synapse for sending challenge state to miners.
    """

    task: str = Field(
        ..., title="Task Name", description="Description of the task assigned to miners."
    )

    state: str = Field(
        ..., title="State", description="State of the task assigned."
    )


    def serialize(self) -> dict:
        """
        Serializes the ChallengeSynapse into a dictionary.
        """
        return {
            "task" : self.task,
            "state" : self.state,
        }

    @classmethod
    def deserialize(cls, data: dict) -> "ChallengeSynapse":
        """
        Deserializes a dictionary into a ChallengeSynapse instance.
        Converts ISO 8601 date strings to datetime.
        """
        return cls(
            task=data["task"],
            state=data["state"],
        )

