from core.agent_runtime import (
    Action,
    ActionKind,
    ActionPolicy,
    BenchmarkCase,
    BenchmarkHarness,
    AgentRunState,
    Artifact,
    Flow,
    HumanGate,
    RuntimePipeline,
    RunMemory,
    SandboxPolicy,
    Task,
    TraceEvent,
    agent_run_state_from_dict,
    build_observability_snapshot,
    build_run_view,
    clear_runtime_runs,
    enforce_sandbox_policy,
    execute_action_in_docker_sandbox,
    get_run_view_response,
    get_runtime_run,
    get_runs_index_response,
    list_runtime_runs,
    make_runtime_http_handler,
    register_runtime_run,
    score_run_summary,
    smoke_docker_sandbox,
)
from core.sandbox.config import CommandResult


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


def test_benchmark_harness_detects_policy_failures():
    harness = BenchmarkHarness(
        [BenchmarkCase(name="strict", min_success_rate=1.0, max_blocked_actions=0)]
    )
    summary = {"actions": 2, "action_status": {"skipped": 1, "blocked": 1}}

    result = harness.evaluate_all(summary)[0]

    assert result.passed is False
    assert "success_rate_below_minimum" in result.failures
    assert "blocked_actions_above_maximum" in result.failures


def test_sandbox_policy_is_plan_only():
    policy = SandboxPolicy(enabled=True, provider="docker", network_policy="deny")

    assert policy.allows_network() is False
    assert policy.to_dict()["provider"] == "docker"


def test_sandbox_policy_blocks_active_without_enabled_sandbox():
    action = Action(
        name="active tool",
        kind=ActionKind.TOOL_CALL,
        policy=ActionPolicy(risk_level="moderate", network_policy="deny"),
    )

    decision = enforce_sandbox_policy(action, SandboxPolicy(enabled=False), mode="active")

    assert decision.allowed is False
    assert "enabled sandbox" in decision.reason


def test_docker_sandbox_execution_requires_explicit_allow_execute():
    action = Action(
        name="docker action",
        kind=ActionKind.SHELL,
        policy=ActionPolicy(risk_level="moderate", network_policy="deny"),
    )

    result = execute_action_in_docker_sandbox(
        action,
        SandboxPolicy(enabled=True, provider="docker", network_policy="deny"),
        command="echo blocked",
    )

    assert result.exit_code == -1
    assert "allow_execute=True" in result.stderr


def test_docker_sandbox_smoke_reports_unavailable(monkeypatch):
    import core.agent_runtime.sandbox as sandbox_module

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("Docker daemon unavailable")

    monkeypatch.setattr(sandbox_module, "execute_action_in_docker_sandbox", unavailable)

    result = smoke_docker_sandbox(timeout_seconds=1)

    assert result["success"] is False
    assert result["skipped"] is True
    assert result["reason"] == "docker_unavailable"


def test_docker_sandbox_smoke_passes_with_marker(monkeypatch):
    import core.agent_runtime.sandbox as sandbox_module

    def smoke_result(*_args, **_kwargs):
        return CommandResult(stdout="autort-docker-sandbox-smoke\n", exit_code=0, duration=0.01)

    monkeypatch.setattr(sandbox_module, "execute_action_in_docker_sandbox", smoke_result)

    result = smoke_docker_sandbox(timeout_seconds=1)

    assert result["success"] is True
    assert result["skipped"] is False
    assert result["network_mode"] == "none"


def test_runtime_pipeline_blocks_network_when_sandbox_denies_it():
    state = AgentRunState(flow=Flow(name="middleware"))
    action = Action(
        name="network tool",
        kind=ActionKind.TOOL_CALL,
        policy=ActionPolicy(risk_level="moderate", network_policy="scoped"),
    )
    state.flow.add_task(Task(name="plan")).add_action(action)
    pipeline = RuntimePipeline()

    pipeline.apply_action(state, action)

    assert action.status.value == "blocked"
    assert not state.human_gates
    assert any(event.event_type == "middleware_decision" for event in state.trace)


def test_agent_run_state_tracks_memory_records():
    state = AgentRunState(flow=Flow(name="memory-state"))

    state.add_memory("scope.mode", "dry-run", record_type="policy", confidence=1.0)

    data = state.to_dict()
    assert data["summary"]["memory_records"] == 1
    assert data["memory"][0]["key"] == "scope.mode"


def test_agent_run_state_from_dict_preserves_serialized_state():
    flow = Flow(name="serialized", flow_id="flow_demo", metadata={"component": "test"})
    task = flow.add_task(Task(name="handoff", task_id="task_demo", metadata={"role": "planner"}))
    action = task.add_action(
        Action(
            name="handoff",
            kind=ActionKind.TOOL_CALL,
            action_id="action_demo",
            inputs={"from_role": "planner", "to_role": "executor"},
            policy=ActionPolicy(risk_level="high", network_policy="deny", requires_human_gate=True),
            status="completed",
            output={"tool_executed": False},
            artifact_ids=["artifact_demo"],
        )
    )
    state = AgentRunState(
        flow=flow,
        run_id="run_demo",
        artifacts=[
            Artifact(
                name="report",
                artifact_type="json",
                artifact_id="artifact_demo",
                uri="memory://report",
            )
        ],
        human_gates=[
            HumanGate(
                reason="approval",
                gate_id="gate_demo",
                action_id=action.action_id,
                approved=True,
                approver="tester",
            )
        ],
        trace=[
            TraceEvent(
                event_type="agent_handoff",
                message="handoff recorded",
                event_id="trace_demo",
                action_id=action.action_id,
            )
        ],
        metadata={"observability": {"ok": True}},
        memory=[{"key": "scope.mode", "value": "dry-run", "record_type": "policy"}],
    )

    restored = agent_run_state_from_dict(state.to_dict())
    view = build_run_view(restored)

    assert restored.run_id == "run_demo"
    assert restored.flow.flow_id == "flow_demo"
    assert restored.flow.tasks[0].task_id == "task_demo"
    assert restored.flow.tasks[0].actions[0].action_id == "action_demo"
    assert restored.human_gates[0].approved is True
    assert restored.trace[0].event_type == "agent_handoff"
    assert restored.memory[0]["key"] == "scope.mode"
    assert view["actions"][0]["action_id"] == "action_demo"


def test_build_run_view_contains_web_api_summary():
    state = AgentRunState(flow=Flow(name="view-state"))
    task = state.flow.add_task(Task(name="report"))
    action = task.add_action(Action(name="report", kind=ActionKind.REPORT))
    action.mark_skipped()

    view = build_run_view(state)

    assert view["run_id"] == state.run_id
    assert view["flow"]["name"] == "view-state"
    assert view["actions"][0]["status"] == "skipped"


def test_read_only_run_view_api_response():
    state = AgentRunState(flow=Flow(name="api-state"))
    store = {state.run_id: state}

    response = get_run_view_response(state.run_id, store)
    index = get_runs_index_response(store)
    missing = get_run_view_response("missing", store)

    assert response["success"] is True
    assert response["data"]["run_id"] == state.run_id
    assert index["count"] == 1
    assert missing["success"] is False


def test_global_runtime_registry_feeds_default_api_response():
    clear_runtime_runs()
    try:
        state = AgentRunState(flow=Flow(name="registered-api-state"))
        register_runtime_run(state)

        response = get_run_view_response(state.run_id)
        index = get_runs_index_response()

        assert get_runtime_run(state.run_id) is state
        assert list_runtime_runs() == [state]
        assert response["success"] is True
        assert response["data"]["run_id"] == state.run_id
        assert index["count"] == 1
    finally:
        clear_runtime_runs()


def test_stdlib_runtime_http_handler_can_be_created():
    state = AgentRunState(flow=Flow(name="api-state"))
    handler = make_runtime_http_handler({state.run_id: state})

    assert handler.__name__ == "RuntimeAPIHandler"


def test_stdlib_runtime_http_handler_can_use_global_registry():
    clear_runtime_runs()
    try:
        handler = make_runtime_http_handler()

        assert handler.__name__ == "RuntimeAPIHandler"
    finally:
        clear_runtime_runs()
