import scripts.mine_pcaps as mine_pcaps


class DummyCursor:
    def __init__(self, rowcount):
        self.rowcount = rowcount
        self.executed = None

    def execute(self, query, params):
        self.executed = (query, params)


class DummyConn:
    def __init__(self, rowcount):
        self._cursor = DummyCursor(rowcount)

    def cursor(self):
        return self._cursor


def test_claim_file_success():
    conn = DummyConn(1)
    statuses = ("pending", "error")
    claimed = mine_pcaps._claim_file(conn, "/tmp/file.pcap", statuses)

    assert claimed is True
    query, params = conn._cursor.executed
    assert "UPDATE pcap_index" in query
    assert params[0] == "processing"
    assert params[1] == "/tmp/file.pcap"
    assert params[2:] == statuses


def test_claim_file_not_claimed():
    conn = DummyConn(0)
    statuses = ("pending",)
    claimed = mine_pcaps._claim_file(conn, "/tmp/file.pcap", statuses)

    assert claimed is False


def test_claim_file_empty_statuses():
    conn = DummyConn(1)
    claimed = mine_pcaps._claim_file(conn, "/tmp/file.pcap", ())

    assert claimed is False
    assert conn._cursor.executed is None


def test_claim_file_concurrent_only_one_wins():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    class ClaimState:
        def __init__(self):
            self.status = {"/tmp/file.pcap": "pending"}
            self.lock = threading.Lock()

    class ClaimCursor:
        def __init__(self, state):
            self.state = state
            self.rowcount = 0

        def execute(self, _query, params):
            filepath = params[1]
            allowed = set(params[2:])
            with self.state.lock:
                if self.state.status.get(filepath) in allowed:
                    self.state.status[filepath] = "processing"
                    self.rowcount = 1
                else:
                    self.rowcount = 0

    class ClaimConn:
        def __init__(self, state):
            self.state = state

        def cursor(self):
            return ClaimCursor(self.state)

    state = ClaimState()
    conn = ClaimConn(state)
    statuses = ("pending",)

    def attempt():
        return mine_pcaps._claim_file(conn, "/tmp/file.pcap", statuses)

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: attempt(), range(8)))

    assert results.count(True) == 1
