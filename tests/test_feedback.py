import sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import init_db, insert_row, TRAFFIC_COLUMNS
from feedback import mark_alert, list_unlabeled, summary


def _insert_alert(conn, alert_id_hint="1.2.3.4"):
    row = {col: 0 for col in TRAFFIC_COLUMNS}
    row["src_ip"] = alert_id_hint
    row["dst_ip"] = "5.6.7.8"
    row["protocol"] = "TCP"
    row["tcp_flags"] = ""
    row["action"] = "BLOCK"
    row["score"] = -0.1
    row["top_reasons"] = "test reason"
    row["rule_reason"] = None
    row["feedback"] = None
    insert_row(conn, "alerts", row)
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def test_mark_alert_sets_feedback_column():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    alert_id = _insert_alert(conn)

    mark_alert(conn, alert_id, "false_positive")

    result = conn.execute("SELECT feedback FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert result[0] == "false_positive"


def test_mark_nonexistent_alert_does_not_crash(capsys):
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    mark_alert(conn, 9999, "false_positive")
    assert "No alert found" in capsys.readouterr().out


def test_list_unlabeled_excludes_labeled_alerts(capsys):
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    id1 = _insert_alert(conn, "1.1.1.1")
    id2 = _insert_alert(conn, "2.2.2.2")
    mark_alert(conn, id1, "false_positive")

    list_unlabeled(conn)
    output = capsys.readouterr().out
    assert "1.1.1.1" not in output
    assert "2.2.2.2" in output


def test_summary_counts_by_label(capsys):
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    id1 = _insert_alert(conn, "1.1.1.1")
    id2 = _insert_alert(conn, "2.2.2.2")
    id3 = _insert_alert(conn, "3.3.3.3")
    mark_alert(conn, id1, "false_positive")
    mark_alert(conn, id2, "confirmed_threat")
    # id3 left unlabeled

    summary(conn)
    output = capsys.readouterr().out
    assert "false_positive" in output
    assert "confirmed_threat" in output
    assert "unlabeled" in output
