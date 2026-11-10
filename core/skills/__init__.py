"""Read-only SKILL.md adapter. Pin metadata only; no vendored bodies."""

from core.skills.adapter import (
    SkillAdapterError,
    list_skill_packs,
    read_skill,
)

__all__ = ["SkillAdapterError", "list_skill_packs", "read_skill"]
