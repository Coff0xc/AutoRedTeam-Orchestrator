from core.agent_roles import RoleKind, build_default_team
from core.agent_runtime import Action, ActionKind, ActionPolicy


def test_default_team_contains_expected_roles():
    team = build_default_team()
    data = team.to_dict()

    assert data["count"] == 6
    assert team.get(RoleKind.RESEARCHER) is not None
    assert team.get("executor") is not None
    assert team.get("reporter").allowed_action_kinds == [ActionKind.REPORT]


def test_role_rejects_disallowed_action_kind():
    team = build_default_team()
    action = Action(
        name="shell from reporter",
        kind=ActionKind.SHELL,
        policy=ActionPolicy(risk_level="low", network_policy="deny"),
    )

    issues = team.validate_action(RoleKind.REPORTER, action)

    assert "action_kind_not_allowed_for_role" in issues


def test_executor_requires_human_gate_for_critical_action():
    team = build_default_team()
    action = Action(
        name="critical active action",
        kind=ActionKind.TOOL_CALL,
        policy=ActionPolicy(
            risk_level="critical",
            network_policy="scoped",
            requires_human_gate=False,
        ),
    )

    issues = team.validate_action(RoleKind.EXECUTOR, action)

    assert "high_risk_action_missing_human_gate" in issues


def test_executor_allows_scoped_high_risk_action_with_gate():
    team = build_default_team()
    action = Action(
        name="approved scoped action",
        kind=ActionKind.TOOL_CALL,
        policy=ActionPolicy(
            risk_level="critical",
            network_policy="scoped",
            requires_human_gate=True,
        ),
    )

    assert team.validate_action(RoleKind.EXECUTOR, action) == []
