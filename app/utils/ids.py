from uuid import uuid4

def new_session_id() -> str:
    return str(uuid4())
