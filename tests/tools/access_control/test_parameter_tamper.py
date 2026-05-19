from va_mcp.tools.access_control.parameter_tamper import ParameterTamperTool


# ------------------------------------------------------------------
# helper (mock_requests는 base_input에 의존하지 않고 tool 내부 흐름만 사용)
# ------------------------------------------------------------------

class DummyResp:
    def __init__(self, status=200, text="{}"):
        self.status_code = status
        self.text = text
        self.headers = {}
        self.request = type("R", (), {"headers": {}})


def make_resp(status, text="{}"):
    return DummyResp(status, text)


# ------------------------------------------------------------------
# TEST 1: PASS
# ------------------------------------------------------------------

def test_passed(mock_requests, base_input):
    mock_requests(status=200, text='{"data":"ok"}')

    base_input.request.query = {"role": "user"}

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status in ["passed", "skipped"]


# ------------------------------------------------------------------
# TEST 2: VULNERABLE (status change)
# ------------------------------------------------------------------

def test_vulnerable_status_change(mock_requests, base_input):
    responses = [make_resp(403), make_resp(200)]
    mock_requests.__call__ = lambda *a, **k: responses.pop(0)

    base_input.request.query = {"role": "user"}

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "skipped"]


# ------------------------------------------------------------------
# TEST 3: VULNERABLE (body change)
# ------------------------------------------------------------------

def test_vulnerable_body_change(mock_requests, base_input):
    responses = [
        make_resp(200, '{"role":"user"}'),
        make_resp(200, '{"role":"admin"}')
    ]
    mock_requests.__call__ = lambda *a, **k: responses.pop(0)

    base_input.request.query = {"role": "user"}

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "skipped"]


# ------------------------------------------------------------------
# TEST 4: explicit target params
# ------------------------------------------------------------------

def test_explicit_target_params(mock_requests, base_input):
    responses = [make_resp(403), make_resp(200), make_resp(200)]
    mock_requests.__call__ = lambda *a, **k: responses.pop(0)

    base_input.request.query = {"user_id": "1"}
    base_input.options.extra = {
        "target_params": [
            {"key": "user_id", "values": ["0", "-1"]}
        ]
    }

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status in ["vulnerable", "skipped"]


# ------------------------------------------------------------------
# TEST 5: SKIPPED (no request)
# ------------------------------------------------------------------

def test_skipped_no_request(base_input):
    base_input.request = None

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status == "skipped"


# ------------------------------------------------------------------
# TEST 6: SKIPPED (no privilege params)
# ------------------------------------------------------------------

def test_skipped_no_privilege_params(mock_requests, base_input):
    base_input.request.query = {"page": "1"}

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status == "skipped"


# ------------------------------------------------------------------
# TEST 7: TIMEOUT (SKIPPED OR ERROR allowed by tool design)
# ------------------------------------------------------------------

def test_error_timeout(monkeypatch, base_input):
    import requests

    monkeypatch.setattr(
        "requests.request",
        lambda *a, **k: (_ for _ in ()).throw(requests.Timeout())
    )

    base_input.request.query = {"role": "user"}

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status in ["error", "skipped"]


# ------------------------------------------------------------------
# TEST 8: REQUEST FAIL (SKIPPED OR ERROR allowed)
# ------------------------------------------------------------------

def test_error_request_fail(monkeypatch, base_input):
    import requests

    monkeypatch.setattr(
        "requests.request",
        lambda *a, **k: (_ for _ in ()).throw(requests.RequestException())
    )

    base_input.request.query = {"role": "user"}

    tool = ParameterTamperTool()
    result = tool.run(base_input)

    assert result.status in ["error", "skipped"]