from infraguard.mcp_server.server import mcp


def test_server_registers_exactly_six_tools() -> None:
    assert set(mcp._tool_manager._tools) == {
        "list_cluster_resources",
        "get_resource",
        "get_policy_findings",
        "analyze_terraform_plan",
        "validate_manifest",
        "validate_patch",
    }
