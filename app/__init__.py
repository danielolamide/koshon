import re
from typing import List, Tuple
import networkx as nx
import matplotlib.pyplot as plt
from urllib.parse import urlparse

server_variables = {
        'CONTEXT_PREFIX': None,
        'CONTEXT_DOCUMENT_ROOT': None,
        'DOCUMENT_ROOT': None,
        'SCRIPT_FILENAME': None,
        'SCRIPT_GROUP': None,
        'SCRIPT_USER': None,
        'SERVER_ADDR': None,
        'SERVER_ADMIN': None,
        'SERVER_NAME': None,
        'SERVER_PORT': None,
        'SERVER_PROTOCOL': None,
        'SERVER_SOFTWARE': None
        }
def parse_httpd_config(config_file_path):
    # Regular expressions for matching RewriteRule and RewriteCond directives
    # rule_pattern = r"RewriteRule\s+(.+?)\s+(.+?)\s+(\[.*?\])"
    rule_pattern = re.compile(r"RewriteRule\s+(.+?)\s+(.+?)(?:\s*\[(.*?)\])?\s*$")
    cond_pattern = re.compile(r"RewriteCond\s+(.+?)\s+(.+?)(?:\s*\[(.*?)\])?\s*$")

    # cond_pattern = r"RewriteCond\s+(.+)"

    # Initialize graph and node attribute index
    graph = nx.DiGraph()
    node_index = 0

    with open(config_file_path, "r") as config_lines:

        current_rule = None
        current_conds = []  # List to store multiple conditions associated with a rule

        for line in config_lines:
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
                )
                current_rule = node_index
                node_index += 1

                # Link each condition to the current rule
                for cond_node in current_conds:
                    graph.add_edge(cond_node, current_rule)
                current_conds = []  # Reset the list for the next rule

    print("Nodes:", graph.nodes(data=True))
    print(graph)

    return graph


def simulate_request_flow(graph: nx.DiGraph, request_uri: str):
    rewrite_rules = []
    rule_to_conds = {}
    for node_index in graph.nodes():
        node_data = graph.nodes[node_index]
        node_type = node_data["type"]
        if node_type == "Rule":
            rewrite_rules.append(
                (node_data["source"], node_data["target"], node_data["flags"])
            )
            predecessors = list(graph.predecessors(node_index))
            if predecessors:
                rule_to_conds.setdefault(node_index, []).append(*predecessors)
    for index, rule in enumerate(rewrite_rules):
        conds = rule_to_conds.get(index, [])
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
        # print(rewrite_engine(rule, teststring_conds, request_uri))


def rewrite_engine(rule: Tuple, conditions: List[Tuple], request_uri: str):
    path = get_uri_segments(request_uri).path
    rule_pattern = rule[0]
    rule_pattern_match = re.match(rule_pattern, path)
    if rule_pattern_match:
        for condition in conditions:
            teststring = condition[0]
            pattern = condition[1]
            transform_url = True if validate_condition(teststring, pattern) else False
            # request uri substitution
        # Coressponding rule conditions must be evaluated before transformaiton
        pass
    else:
        return request_uri


def get_uri_segments(request_uri: str):
    return urlparse(request_uri)


def validate_condition(teststring: str, condition: str) -> bool:
    # Teststring value has to be determined - it is usually some sort of variable (apache variable or user variable)
    condition_matched = re.match(condition, teststring)
    return True if condition_matched else False

def set_server_variables(line: str)
