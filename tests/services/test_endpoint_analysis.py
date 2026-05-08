from __future__ import annotations

from va_mcp.services.endpoint_analysis import analyze_endpoint


def test_analyze_endpoint_success_minimal():
    result = analyze_endpoint(
        {
            "base_url": "https://api.example.com",
            "method": "GET",
            "path": "/health",
        }
    )
    assert result["status"] == "parsed"
    assert result["next_stage"] == "FeatureExtractor not implemented yet"
    ep = result["endpoint_profile"]
    assert ep["method"] == "GET"
    assert ep["path"] == "/health"
    assert ep["base_url"] == "https://api.example.com"


def test_analyze_endpoint_normalization():
    result = analyze_endpoint(
        {
            "base_url": "https://example.com/",
            "method": "post",
            "path": "api/v1/items",
        }
    )
    assert result["status"] == "parsed"
    ep = result["endpoint_profile"]
    assert ep["method"] == "POST"
    assert ep["path"] == "/api/v1/items"
    assert ep["base_url"] == "https://example.com"


def test_analyze_endpoint_invalid_input():
    result = analyze_endpoint(
        {
            "base_url": "",
            "method": "GET",
            "path": "/p",
        }
    )
    assert result["status"] == "invalid_input"
    assert "errors" in result
    assert len(result["errors"]) >= 1
    err0 = result["errors"][0]
    assert "code" in err0 and "field" in err0 and "message" in err0
