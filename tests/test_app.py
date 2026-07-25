import sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from db import init_db, insert_row, TRAFFIC_COLUMNS


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    conn = sqlite3.connect(db_path)
    init_db(conn)

    row = {col: 0 for col in TRAFFIC_COLUMNS}
    row["src_ip"] = "1.2.3.4"
    row["dst_ip"] = "5.6.7.8"
    row["protocol"] = "TCP"
    row["tcp_flags"] = ""
    insert_row(conn, "traffic", row)
    conn.commit()
    conn.close()

    import app as app_module
    app_module.cfg["db_path"] = db_path
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


def test_index_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200


def test_summary_endpoint_returns_json(client):
    response = client.get("/api/summary")
    assert response.status_code == 200
    data = response.get_json()
    assert data["traffic_count"] == 1
    assert "alert_rate" in data


def test_alerts_endpoint_returns_list(client):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)


def test_blocklist_endpoint_returns_list(client):
    response = client.get("/api/blocklist")
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)


def test_traffic_timeline_endpoint_returns_list(client):
    response = client.get("/api/traffic-timeline")
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)
