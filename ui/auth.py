"""Simple session authentication for ledger write access."""

import streamlit as st


def require_admin_password() -> bool:
    """Check if the user has entered the correct admin password.
    
    Returns True if authenticated, False otherwise.
    Stores auth state in session so the password only needs to be entered once.
    """
    if st.session_state.get("admin_authenticated"):
        return True
    
    with st.form("admin_auth"):
        password = st.text_input(
            "Admin password",
            type="password",
            help="Required to access ledger write operations (revoke)",
        )
        submitted = st.form_submit_button("Authenticate", use_container_width=True)
    
    if submitted:
        # In a real app, this would be read from environment variables or secrets
        # For the demo, you can set it in .streamlit/secrets.toml
        correct_password = st.secrets.get("admin", {}).get("password", "demo-password-change-me")
        
        if password == correct_password:
            st.session_state["admin_authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password")
            return False
    
    return False


def logout() -> None:
    """Clear authentication state."""
    st.session_state["admin_authenticated"] = False