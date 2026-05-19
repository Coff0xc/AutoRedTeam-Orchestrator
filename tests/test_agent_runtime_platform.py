from core.agent_runtime import (
    Action,
    ActionKind,
    ActionPolicy,
    AgentRunState,
    Flow,
    RunMemory,
    SandboxPolicy,
    Task,
    build_observability_snapshot,
    score_run_summary,
)


def test_run_memory_add_and_query():
    memory = RunMemory()
    memory.add("target.demo", "http://127.0.0.1:8000", record_type="target", confidence=0.9)
    memory.add("finding.demo", "dry-run only", record_type="finding")

    assert len(memory.query(record_type="target")) == 1
    assert memory.to_dict()["count"] == 2


def test_observability_snapshot_counts_risk_and_network_policy():
    flow = Flow(name="platform-test")
    task = flow.add_task(Task(name="plan"))
    action = Action(
        name="dry-run action",
        kind=ActionKind.TOOL_CALL,
        policy=ActionPolicy(risk_level="moderate", network_policy="deny"),
    )
    action.mark_skipped()
    task.add_action(action)
    state = AgentRunState(flow=flow)

    snapshot = build_observability_snapshot(state).to_dict()

    assert snapshot["metrics"]["actions"] == 1
    assert snapshot["metrics"]["risk_counts"]["moderate"] == 1
    assert snapshot["metrics"]["network_policy_counts"]["deny"] == 1


def test_benchmark_scores_skipped_dry_run_as_policy_success():
    result = score_run_summary(
        "dry-run",
        {"actions": 2, "action_status": {"skipped": 2}, "policy_violations": 0},
    )

    assert result.success_rate == 1.0
    assert result.blocked_actions == 0
    assert result.policy_violations == 0


def test_sandbox_policy_is_plan_only():
    policy = SandboxPolicy(enabled=True, provider="docker", network_policy="deny")

    assert policy.allows_network() is False
    assert policy.to_dict()["provider"] == "docker"


def test_agent_run_state_tracks_memory_records():
    state = AgentRunState(flow=Flow(name="memory-state"))

    state.add_memory("scope.mode", "dry-run", record_type="policy", confidence=1.0)

    data = state.to_dict()
    assert data["summary"]["memory_records"] == 1
    assert data["memory"][0]["key"] == "scope.mode"
