from dataclasses import dataclass
from typing import Any

@dataclass
class TestCase:
    test_id: str
    category: str
    attack_technique: str
    user_prompt: str
    setup_required: dict[str, Any] | None
    expected_vulnerability: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.test_id,
            "category": self.category,
            "attack_technique": self.attack_technique,
            "user_prompt": self.user_prompt,
            "setup_required": self.setup_required,
            "expected_vulnerability": self.expected_vulnerability
        }