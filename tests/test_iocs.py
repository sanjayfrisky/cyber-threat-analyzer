from app.routes.chat import extract_iocs

def test_extract_iocs_from_text():
    result=extract_iocs("visit https://example.com/a and IP 8.8.8.8 hash "+"a"*64)
    assert "8.8.8.8" in result["ipv4"]
    assert "https://example.com/a" in result["urls"]
    assert "a"*64 in result["sha256"]
