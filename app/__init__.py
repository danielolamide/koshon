from enum import Enum
import re
from typing import List, Tuple
import networkx as nx
import matplotlib.pyplot as plt
from urllib.parse import urlparse
from termcolor import colored, cprint

server_variables = {
    "QUERY_STRING": {"get": lambda x: urlparse(x).query},
    "REQUEST_URI": {"get": lambda x: urlparse(x).path},
}
EngineAction = Enum("EngineAction", ["NO_CHANGE", "REWRITE"])


def parse_httpd_config(config):
    # Regular expressions for matching RewriteRule and RewriteCond directives
    rule_pattern = re.compile(r"RewriteRule\s+(.+?)\s+(.+?)(?:\s*\[(.*?)\])?\s*$")
    cond_pattern = re.compile(r"RewriteCond\s+(.+?)\s+(.+?)(?:\s*\[(.*?)\])?\s*$")

    # maintain node order of processing by initializing
    graph = nx.DiGraph()
    node_index = 0

    # with open(config, "r") as config_lines:
    current_rule = None
    # Make it easier to store multiple corresponding conditions for a rule
    current_conds = []
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


def simulate_request_flow(graph: nx.DiGraph, url: str):
    rewrite_rules = []
    rule_to_conds = {}
    # the request has to pass through all nodes, still maintaining the order they were defined in the httpd.conf
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
            if predecessors:
                rule_to_conds.setdefault(node_index, []).extend(predecessors)

    # the REQUEST_URI will be looped around the entire ruleset until no more rules match
    # while action is not no_change
    # take request_uri through rewrite_engine
    # output from rewrite_engine should include action and current request url
    # we would then return the request url returned with either serve/ext_redirect
    engine_action = EngineAction.REWRITE
    current_url = url
    engine_run_count = 0

    while engine_action != EngineAction.NO_CHANGE:
        cprint(f"Simulation #{engine_run_count}", "white", "on_light_cyan")
        print(f"Simulating request to {current_url}")
        urls = []
        actions = []
        # eval whether url is internal/external URL
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
            current_url, action = rewrite_engine(rule, corresponding_conds, current_url)
            actions.append(action)
            urls.append(current_url)

        if EngineAction.REWRITE not in actions:
            engine_action = EngineAction.NO_CHANGE

        engine_run_count += 1

    cprint(f"Final URI to be served {current_url}", "green")
    return current_url


def rewrite_engine(rule: List, conditions: List[Tuple], uri: str):
    cprint(f"Rule: {rule}, conditions: {conditions}", "white", "on_dark_grey")
    request = urlparse(uri)
    path = request.path
    rule_pattern = rf"{rule[1]}"
    target = rule[2]
    print(rule_pattern, path)
    rule_pattern_match = re.match(rule_pattern, path)
    valid_conditions = False
    cond_backreferences = {}
    rule_backreferences = {}
    if rule_pattern_match:
        cprint("Pattern matched", "black", "on_green")
        # create rule backreferences
        for i, val in enumerate(rule_pattern_match.groups(), start=1):
            rule_backreferences[str(i)] = val
        # Corresponding rule conditions must be evaluated before transformation
        # unless [OR] flag exists, we expect all conditions to be true for rule to be applied
        for condition in conditions:
            teststring = condition[0]
            pattern = rf"{condition[1]}"
            cond_flags = condition[2]
            is_cond_valid, cond_backreferences = validate_condition(
                teststring, pattern, uri
            )
            if is_cond_valid:
                valid_conditions = True
                continue
            else:
                valid_conditions = False
                break
    else:
        cprint("No match", "black", "on_light_yellow")
        return request.geturl(), EngineAction.NO_CHANGE

    if valid_conditions:
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
        print(colored(f"URL Rewrite: {request.geturl()}", "green"))
        return request.geturl(), EngineAction.REWRITE
    else:
        print(colored(f"No valid corresponding conditions", "red"))
        return request.geturl(), EngineAction.NO_CHANGE


def validate_condition(teststring: str, condition: str, request_uri) -> Tuple:
    # Teststring value has to be determined - usually a variable (apache variable or user variable)
    backreferences = {}
    teststring = expand_variable(teststring)
    cprint(f"Validating conditions {teststring}", "black", "on_yellow")
    if teststring in server_variables:
        teststring = server_variables[teststring]["get"](request_uri)
    else:
        cprint(f"{teststring} not found in variables")
    condition_matched = re.match(condition, teststring)
    if condition_matched:
        for i, val in enumerate(condition_matched.groups(), start=1):
            backreferences[str(i)] = val
        cprint(f"Validation passed {teststring}", "black", "on_green")
        return True, backreferences
    else:
        cprint(f"Validation failed {teststring} {condition}", "red", "on_light_red")
        return False, None


def expand_variable(var: str) -> str:
    """
    Get httpd variable and value
    """
    var_pattern = re.compile(r"%{([^}]+)}")
    httpd_var = var_pattern.match(var)
    return httpd_var.group(1) if httpd_var else ""


def visualize_graph(graph: nx.DiGraph):
    fig = plt.figure()
    labels = nx.get_node_attributes(graph, "line")
    # node_positions = nx.multipartite_layout(graph)
    nx.draw_networkx(graph, with_labels=True, labels=labels, font_size=5)
    return fig
