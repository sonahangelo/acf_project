import sys, os, sqlite3, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import init_db, insert_row, TRAFFIC_COLUMNS
from retention import prune_table, archive_traffic


def _insert_traffic_row(conn, timestamp, src_ip="1.2.3.4"):
    row = {col: 0 for col in TRAFFIC_COLUMNS}
    row["timestamp"] = timestamp
    row["src_ip"] = src_ip
    row["dst_ip"] = "5.6.7.8"
    row["protocol"] = "TCP"
    row["tcp_flags"] = ""
    insert_row(conn, "traffic", row)


def test_dry_run_does_not_delete_anything():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    _insert_traffic_row(conn, timestamp=1000.0)

    count = prune_table(conn, "traffic", cutoff_ts=2000.0, dry_run=True)
    assert count == 1  # reports what WOULD be deleted

    remaining = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
    assert remaining == 1  # but nothing actually removed


def test_real_prune_deletes_old_rows_only():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    _insert_traffic_row(conn, timestamp=1000.0)   # old -- should be deleted
    _insert_traffic_row(conn, timestamp=9999999999.0)  # far future -- should survive

    prune_table(conn, "traffic", cutoff_ts=2000.0, dry_run=False)

    remaining = conn.execute("SELECT timestamp FROM traffic").fetchall()
    assert remaining == [(9999999999.0,)]


def test_prune_with_nothing_to_delete_returns_zero():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    _insert_traffic_row(conn, timestamp=9999999999.0)

    count = prune_table(conn, "traffic", cutoff_ts=1.0, dry_run=False)
    assert count == 0

    remaining = conn.execute("SELECT COUNT(*) FROM traffic").fetchone()[0]
    assert remaining == 1


def test_archive_writes_csv_and_returns_count(tmp_path):
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    _insert_traffic_row(conn, timestamp=1000.0)
    _insert_traffic_row(conn, timestamp=1001.0)

    archive_dir = str(tmp_path / "archive")
    count = archive_traffic(conn, cutoff_ts=2000.0, archive_dir=archive_dir)
    assert count == 2

    files = os.listdir(archive_dir)
    assert len(files) == 1
    assert files[0].startswith("traffic_archive_")


def test_archive_with_nothing_to_archive_creates_no_file(tmp_path):
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    _insert_traffic_row(conn, timestamp=9999999999.0)  # nothing older than cutoff

    archive_dir = str(tmp_path / "archive")
    count = archive_traffic(conn, cutoff_ts=1.0, archive_dir=archive_dir)
    assert count == 0
    assert not os.path.exists(archive_dir)
