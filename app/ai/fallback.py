def fallback_answer(reason: str = "The indexed cybersecurity sources do not contain enough evidence.") -> str:
    # Safe fallback for empty retrieval or unavailable model responses.
    return f"I cannot provide a source-grounded answer yet. {reason}"
