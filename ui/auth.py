"""Simple session authentication for ledger write access."""

import streamlit as st


def require_admin_password() -> bool:
    """Check if the user has entered the correct admin password from the database.
    
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
        # Query the database for the correct password
        try:
            supabase_url = st.secrets.get("supabase", {}).get("url", "")
            supabase_key = st.secrets.get("supabase", {}).get("key", "")
            
            if not supabase_url or not supabase_key:
                st.error("Supabase credentials not configured")
                return False
            
            import requests
            
            response = requests.get(
                f"{supabase_url.rstrip('/')}/rest/v1/admin_credentials?username=eq.admin&select=password_hash",
                headers={
                    "apikey": supabase_key,
                    "Authorization": f"Bearer {supabase_key}",
                },
                timeout=6.0
            )
            
            if response.status_code != 200:
                st.error("Could not reach the database")
                return False
            
            data = response.json()
            if not data:
                st.error("Admin credentials not found in database")
                return False
            
            correct_password = data[0].get("password_hash", "")
            
            if password == correct_password:
                st.session_state["admin_authenticated"] = True
                st.rerun()
            else:
                st.error("Incorrect password")
                return False
                
        except Exception as exc:
            st.error(f"Authentication error: {exc}")
            return False
    
    return False


def logout() -> None:
    """Clear authentication state."""
    st.session_state["admin_authenticated"] = False