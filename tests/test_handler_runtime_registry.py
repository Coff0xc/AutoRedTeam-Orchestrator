from unittest.mock import MagicMock

from core.agent_runtime import clear_runtime_runs, get_runtime_run


def test_resource_handler_registers_runtime_run():
    from handlers.resource_handlers import register_resource_handlers

    clear_runtime_runs()
    resources = {}

    class ResourceMCP:
        def resource(self, **kwargs):
            def decorator(func):
                resources[kwargs["uri"]] = func
                return func

            return decorator

    counter = MagicMock()
    counter.counts = {"recon": 9, "report": 2}
    counter.total = 11
    logger = MagicMock()

    try:
        register_resource_handlers(ResourceMCP(), counter, logger)
        result = resources["redteam://tools"]()

        assert result["runtime"]["summary"]["action_status"]["completed"] == 1
        assert get_runtime_run(result["runtime"]["run_id"]) is not None
    finally:
        clear_runtime_runs()
