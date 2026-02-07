from unittest.mock import MagicMock, patch

from scout import Scout


def test_scout_start_runs_main_loop_once_and_shutdowns():
    with (
        patch("scout.PidFile"),
        patch("scout.EventQueueWriter"),
        patch("scout.EventLogger"),
        patch("scout.get_capture_backend"),
        patch("scout.signal.signal"),
    ):
        scout = Scout()
        scout.pidfile.is_running.return_value = False
        scout.pidfile.write.return_value = None
        scout.event_logger.log_startup = MagicMock()
        scout._run_loop = MagicMock(side_effect=KeyboardInterrupt())
        scout._shutdown = MagicMock()

        scout.start()

        assert scout._run_loop.call_count == 1
        scout._shutdown.assert_called_once()
