import sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from status import format_ts
from db import init_db


def test_format_ts_handles_none():
    assert format_ts(None) == "-"


def test_format_ts_formats_timestamp():
    result = format_ts(1784810213.097522)
    assert len(result) == 19  # "YYYY-MM-DD HH:MM:SS"
    assert result.count("-") == 2
    assert result.count(":") == 2


def test_print_status_runs_without_error_on_empty_db(capsys):
    from status import print_status
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    print_status(conn, recent_n=5)
    output = capsys.readouterr().out
    assert "Traffic rows logged:   0" in output
    assert "(none)" in output


def test_print_status_shows_alert_rate(capsys):
    from status import print_status
    from db import insert_row, TRAFFIC_COLUMNS
    conn = sqlite3.connect(":memory:")
    init_db(conn)

    row = {col: 0 for col in TRAFFIC_COLUMNS}
    row["src_ip"] = "1.2.3.4"
    row["dst_ip"] = "5.6.7.8"
    row["protocol"] = "TCP"
    row["tcp_flags"] = ""
    insert_row(conn, "traffic", row)

    print_status(conn, recent_n=5)
    output = capsys.readouterr().out
    assert "Traffic rows logged:   1" in output
