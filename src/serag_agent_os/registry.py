import json
from pathlib import Path
from .models import AgentSpec


class AgentRegistry:
    def __init__(self, agents: list[AgentSpec]):
        self._agents = {agent.id: agent for agent in agents}
        if len(self._agents) != len(agents):
            raise ValueError("Duplicate agent id")

    @classmethod
    def from_file(cls, path: str | Path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        agents = [
            AgentSpec(item["id"], item["name_ar"], tuple(item["capabilities"]))
            for item in data["agents"]
        ]
        return cls(agents)

    def get(self, agent_id: str) -> AgentSpec:
        return self._agents[agent_id]

    def for_capability(self, capability: str) -> AgentSpec:
        matches = [a for a in self._agents.values() if capability in a.capabilities]
        if len(matches) != 1:
            raise ValueError(f"Capability must map to exactly one agent: {capability}")
        return matches[0]

    def all(self) -> tuple[AgentSpec, ...]:
        return tuple(self._agents.values())
