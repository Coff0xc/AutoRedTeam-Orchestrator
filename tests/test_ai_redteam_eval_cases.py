from core.agent_runtime import Action, ActionKind, ActionPolicy, AgentRunState, Flow, Task
from core.ai_redteam import evaluate_run_cases


def test_default_eval_cases_pass_safe_dry_run():
    state = AgentRunState(flow=Flow(name="safe"))
    task = state.flow.add_task(Task(name="plan"))
    action = task.add_action(
        Action(
            name="dry-run",
            kind=ActionKind.TOOL_CALL,
            policy=ActionPolicy(risk_level="moderate", network_policy="deny"),
        )
    )
    action.mark_skipped({"message": "no unsafe markers"})

    result = evaluate_run_cases(state)

    assert result["passed"] is True
    assert result["summary"]["failed"] == 0
    assert result["summary"]["total"] == 6


def test_eval_cases_detect_unsafe_tool_output_and_missing_gate():
    state = AgentRunState(flow=Flow(name="unsafe"))
    task = state.flow.add_task(Task(name="execute"))
    action = task.add_action(
        Action(
            name="critical",
            kind=ActionKind.TOOL_CALL,
            policy=ActionPolicy(
                risk_level="critical",
                network_policy="deny",
                requires_human_gate=False,
            ),
        )
    )
    action.mark_completed({"next": "execute_shell credential_spray"})

    result = evaluate_run_cases(state)
    failed = {case["case_id"] for case in result["cases"] if not case["passed"]}

    assert result["passed"] is False
    assert "agent.high_risk_actions_have_gates" in failed
    assert "tool.no_unsafe_output" in failed


def test_eval_cases_detect_rag_leakage_tool_drift_and_missing_handoff_trace():
    state = AgentRunState(flow=Flow(name="unsafe-handoff"))
    task = state.flow.add_task(Task(name="handoff"))
    action = task.add_action(
        Action(
            name="handoff",
            kind=ActionKind.TOOL_CALL,
            inputs={"from_role": "planner", "to_role": "executor"},
            policy=ActionPolicy(risk_level="moderate", network_policy="deny"),
        )
    )
    action.mark_completed(
        {
            "message": "retrieved_context included internal document",
            "tool_executed": True,
        }
    )

    result = evaluate_run_cases(state)
    failed = {case["case_id"] for case in result["cases"] if not case["passed"]}

    assert "rag.no_reference_leakage" in failed
    assert "tool.permission_drift" in failed
    assert "agent.multi_agent_handoff_trace" in failed
