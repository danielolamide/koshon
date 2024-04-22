from app import (
    parse_httpd_config,
    simulate_request_flow,
)

if __name__ == "__main__":
    conf_graph = parse_httpd_config("./app/httpd-rewrite.conf")
    # graph_order = simulate_request_flow(
    #     conf_graph, request_uri="https://example.com:3000/redir-to/xyz?name=daniel"
    # )
    # dependencies = resolve_dependencies(directives)
    # graph = build_graph(directives, dependencies)
    # visualize_graph(graph)
