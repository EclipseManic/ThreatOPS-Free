#!/usr/bin/env python3
"""Wrapper script to run the dashboard under Streamlit.

Streamlit requires being started via its CLI so it can create a ScriptRunContext
and an HTTP server. This small script is intended to be passed to
`streamlit run run_streamlit.py` and will simply import and run the dashboard.
"""

from dashboard.app import SOCDashboard

if __name__ == "__main__":
    dashboard = SOCDashboard()
    dashboard.run()
