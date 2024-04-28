import re
from typing import List, Tuple
import networkx as nx
import matplotlib.pyplot as plt
from urllib.parse import urlparse
from termcolor import colored

server_variables = {
    "QUERY_STRING": {"get": lambda x: urlparse(x).query},
}


def parse_httpd_config(config):
    # Regular expressions for matching RewriteRule and RewriteCond directives
    rule_pattern = re.compile(r"RewriteRule\s+(.+?)\s+(.+?)(?:\s*\[(.*?)\])?\s*$")
    cond_pattern = re.compile(r"RewriteCond\s+(.+?)\s+(.+?)(?:\s*\[(.*?)\])?\s*$")

    # Initialize graph and node attribute index
    graph = nx.DiGraph()
    node_index = 0

    # with open(config, "r") as config_lines:
    current_rule = None
    current_conds = []  # List to store multiple conditions associated with a rule
    for line in config.splitlines():
        # for line in config_lines:
        line = line.strip()
        # Match RewriteConds
        cond_match = cond_pattern.match(line)
        if cond_match:
            teststring, condition, flags = cond_match.groups()
            graph.add_node(
                node_index,
                type="Cond",
                teststring=teststring,
                condition=condition,
                flags=flags,
                line=line,
            )
            current_conds.append(node_index)  # Append cond node index to the list
            node_index += 1

        # Match RewriteRules
        rule_match = rule_pattern.match(line)
        if rule_match:
            source_url, target_url, flags = rule_match.groups()
            graph.add_node(
                node_index,
                type="Rule",
                source=source_url,
                target=target_url,
                flags=flags,
                line=line,
            )
            current_rule = node_index
            node_index += 1

            # Link each condition to the current rule
            for cond_node in current_conds:
                graph.add_edge(cond_node, current_rule)
            current_conds = []  # Reset the list for the next rule

    print("Nodes:", graph.nodes(data=True))
    print("Edges:", graph.edges)
    print(graph)

    return graph


def simulate_request_flow(graph: nx.DiGraph, uri: str):
    print(f"Simulating request to {uri}")
    rewrite_rules = []
    rule_to_conds = {}
    current_uri = uri
    for node_index in graph.nodes():
        node_data = graph.nodes[node_index]
        node_type = node_data["type"]
        if node_type == "Rule":
            rewrite_rules.append(
                (
                    node_index,
                    node_data["source"],
                    node_data["target"],
                    node_data["flags"],
                )
            )
            predecessors = list(graph.predecessors(node_index))
            print("Predecessors:", predecessors)
            print("Predecessors Type:", type(predecessors))
            if predecessors:
                rule_to_conds.setdefault(node_index, []).extend(predecessors)

    for rule in rewrite_rules:
        conds = rule_to_conds.get(rule[0], [])
        corresponding_conds = []
        for cond in conds:
            corresponding_cond = graph.nodes[cond]
            corresponding_conds.append(
                (
                    corresponding_cond["teststring"],
                    corresponding_cond["condition"],
                    corresponding_cond["flags"],
                )
            )
        current_uri = rewrite_engine(rule, corresponding_conds, current_uri)

    print(colored(f"Final URI to be served {current_uri}", "green"))
    return current_uri


def rewrite_engine(rule: List, conditions: List[Tuple], uri: str):
    request = get_uri_segments(uri)
    path = request.path
    rule_pattern = rule[1]
    target = rule[2]
    rule_pattern_match = re.match(rule_pattern, path)
    url_changed = False
    cond_backreferences = {}
    rule_backreferences = {}
    if rule_pattern_match:
        # create rule backreferences
        for i, val in enumerate(rule_pattern_match.groups(), start=1):
            rule_backreferences[str(i)] = val
        # Corresponding rule conditions must be evaluated before transformation
        for condition in conditions:
            teststring = condition[0]
            pattern = condition[1]
            url_changed, cond_backreferences = validate_condition(
                teststring, pattern, uri
            )
            if url_changed:
                continue
            else:
                break

    if url_changed:
        # Distinguish between external and internal redirect
        path = request.path
        print(f"Rewriting {rule_pattern} to {target}")
        path = re.sub(rule_pattern, target, path)
        if cond_backreferences:
            for key, value in cond_backreferences.items():
                path = path.replace("%" + key, value)
        if rule_backreferences:
            for key, value in rule_backreferences.items():
                path = path.replace("$" + key, value)
        request = request._replace(path=path, query=None)
        print(colored(f"URL Returned: {request.geturl()}", "green"))
        # request = request._replace(path=rule[2])
    else:
        print(colored(f"URL Returned: {request.geturl()}", "red"))
    request = request.geturl()
    return request


def get_uri_segments(request_uri: str):
    return urlparse(request_uri)


def validate_condition(teststring: str, condition: str, request_uri) -> Tuple:
    # Teststring value has to be determined - it is usually some sort of variable (apache variable or user variable)
    backreferences = {}
    teststring = expand_variable(teststring)
    if teststring in server_variables:
        teststring = server_variables[teststring]["get"](request_uri)
    condition_matched = re.match(condition, teststring)
    if condition_matched:
        for i, val in enumerate(condition_matched.groups(), start=1):
            backreferences[str(i)] = val
        return True, backreferences
    else:
        return False, None


def expand_variable(var: str) -> str:
    var_pattern = re.compile(r"%{([^}]+)}")
    var_found = var_pattern.match(var)
    return var_found.group(1) if var_found else var


def visualize_graph(graph: nx.DiGraph):
    fig = plt.figure()
    labels = nx.get_node_attributes(graph, "line")
    # node_positions = nx.multipartite_layout(graph)
    nx.draw_networkx(graph, with_labels=True, labels=labels, font_size=5)
    return fig
