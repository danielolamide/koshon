from app import (
    parse_httpd_config,
    simulate_request_flow,
)

if __name__ == "__main__":
    conf_graph = parse_httpd_config("./app/httpd-rewrite.conf")
    simulate_request_flow(
        conf_graph, "https://example.com:3000/redir-to/xyz?name=daniel"
    )

