import os
from unittest.mock import patch

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_api_evidence_slice_success():
    # Mock evidence_collector.slice_pcap to return a fake file
    with patch('app.services.state.evidence_collector.slice_pcap') as mock_slice:
        # Prepare a dummy file
        dummy_path = "/tmp/test_ev_slice.pcap"
        with open(dummy_path, "wb") as f:
            f.write(b"dummy pcap content")

        mock_slice.return_value = dummy_path

        response = client.get("/api/evidence/slice?start_ts=100&end_ts=200")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/vnd.tcpdump.pcap"
        assert response.content == b"dummy pcap content"

        # Verify call
        mock_slice.assert_called_with(100.0, 200.0)

        # Cleanup
        if os.path.exists(dummy_path):
            os.remove(dummy_path)

def test_api_evidence_slice_not_found():
    with patch('app.services.state.evidence_collector.slice_pcap') as mock_slice:
        mock_slice.return_value = None

        response = client.get("/api/evidence/slice?start_ts=100&end_ts=200")

        assert response.status_code == 404
