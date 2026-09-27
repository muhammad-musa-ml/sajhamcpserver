"""MCP Origin checks at the HTTP boundary; no full server or network required."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sajha.auth import AuthContext, AuthManager
from sajha.core.mcp_2025_11_25 import validate_origin
from sajha.db.engine import get_db
from sajha.routes.api_routes import router as api_router
from sajha.routes.mcp_routes import router as mcp_router


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.include_router(api_router)
    app.include_router(mcp_router)
    app.dependency_overrides[get_db] = lambda: None
    monkeypatch.setattr(AuthManager, 'authenticate_request',
                        lambda request, db: AuthContext())

    import sajha.app as server

    class Handler:
        def handle_request(self, body, session):
            return {'jsonrpc': '2.0', 'id': body.get('id'), 'result': {}}

    monkeypatch.setattr(server, 'mcp_handler', Handler())
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize('path', ['/mcp', '/api/mcp', '/mcp/message'])
@pytest.mark.parametrize('origin', [
    'https://attacker.example',
    'http://localhost.evil.example:3002',
    'null',
    'http://0.0.0.0:3002',
])
def test_post_rejects_untrusted_origin_before_dispatch(client, path, origin):
    response = client.post(path, headers={'Origin': origin}, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'ping',
    })
    assert response.status_code == 403


@pytest.mark.parametrize('path', ['/mcp', '/mcp/sse'])
def test_get_rejects_untrusted_origin(client, path):
    response = client.get(path, headers={'Origin': 'https://attacker.example'})
    assert response.status_code == 403


@pytest.mark.parametrize('path', ['/mcp', '/api/mcp', '/mcp/message'])
@pytest.mark.parametrize('origin', [None, 'http://localhost:3002',
                                     'http://127.0.0.1:3002'])
def test_post_preserves_trusted_and_non_browser_clients(client, path, origin):
    headers = {'Origin': origin} if origin else {}
    response = client.post(path, headers=headers, json={
        'jsonrpc': '2.0', 'id': 1, 'method': 'ping',
    })
    assert response.status_code == 200
    assert response.json()['id'] == 1


def test_explicit_deployment_origin_is_exact_match(monkeypatch):
    monkeypatch.setenv('SAJHA_MCP_ALLOWED_ORIGINS',
                       'https://mcp.example.org, https://backup.example.org')
    assert validate_origin('https://mcp.example.org')
    assert validate_origin('https://backup.example.org')
    assert not validate_origin('https://mcp.example.org.evil.example')
    assert not validate_origin('http://localhost:3002')


def test_default_loopback_uses_configured_port(monkeypatch):
    from types import SimpleNamespace
    import sajha.core.config as config

    monkeypatch.delenv('SAJHA_MCP_ALLOWED_ORIGINS', raising=False)
    monkeypatch.setattr(config, 'get_settings',
                        lambda: SimpleNamespace(server_port=8080))
    assert validate_origin('http://localhost:8080')
    assert not validate_origin('http://localhost:3002')


@pytest.mark.parametrize('origin', ['', 'null', '*', 'https://attacker.example/path',
                                     'https://user@attacker.example',
                                     'https://attacker.example:bad'])
def test_malformed_or_opaque_origin_is_rejected_even_if_listed(origin):
    assert not validate_origin(origin, [origin])
