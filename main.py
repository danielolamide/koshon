from app import (
    parse_httpd_config,
    simulate_request_flow,
    visualize_graph,
)
import streamlit as st
import os

if __name__ == "__main__":
    # conf_graph = parse_httpd_config("./app/httpd-rewrite.conf")
    # simulate_request_flow(
    #     conf_graph, "https://example.com:3000/redir-to/xyz?name=daniel"
    # )
    os.system("clear")
    st.title("Koshon")
    st.header("Test Apache Pre-deployment")
    with st.form("apache_config_form"):
        url = st.text_input(
            label="Enter your request URL",
            help="The rules in your configuration file will be executed against this URL",
        )
        httpd_config = st.text_area(label="Paste your Apache configuration here")
        submit_config = st.form_submit_button(label="Submit")

        if submit_config:
            if all((httpd_config, url)):
                graph = parse_httpd_config(httpd_config)
                final_url = simulate_request_flow(graph, url)
                fig = visualize_graph(graph)
                st.text(f"Served URL: {final_url}")
                st.pyplot(fig)
            else:
                print("not submitted")
