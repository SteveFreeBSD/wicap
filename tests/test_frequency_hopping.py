
from unittest.mock import MagicMock, patch

import pytest

from scout import Scout, ScoutConfig


@pytest.fixture
def mock_scout_deps():
    """Mock dependencies for Scout to avoid hardware/root requirement."""
    with patch('scout.get_capture_backend') as mock_backend_cls, \
         patch('scout.subprocess.run') as mock_run, \
         patch('utils.wifi_capabilities.get_supported_channels') as mock_get_channels, \
         patch('scout.PidFile'), \
         patch('scout.EventLogger'), \
         patch('scout.EventQueueWriter'):

        # Setup mock channels (include 2.4/5/6GHz)
        mock_get_channels.return_value = [
            {'channel': 1, 'freq': 2412, 'band': '2.4ghz'},
            {'channel': 6, 'freq': 2437, 'band': '2.4ghz'},
            {'channel': 36, 'freq': 5180, 'band': '5ghz'},
            {'channel': 1, 'freq': 5955, 'band': '6ghz'},  # Collision with 2.4G Ch1
            {'channel': 5, 'freq': 5975, 'band': '6ghz'},
        ]

        # Setup run mock to succeed
        mock_run.return_value.returncode = 0

        yield {
            'run': mock_run,
            'get_channels': mock_get_channels,
            'backend': mock_backend_cls
        }

def test_hopping_sequence_generation(mock_scout_deps):
    """Verify hopping sequence includes all bands and prioritizes correctly."""
    config = ScoutConfig(interface="wlan0", bands=["all"])
    scout = Scout(config)

    # Access Hopper via scout.hopper
    seq = scout.hopper.hopping_sequence
    assert len(seq) > 0

    # Verify we have both Ch1s (2412 and 5955)
    # Hopper converts inputs to ChannelInfo objects
    freqs = [c.freq for c in seq]
    assert 2412 in freqs
    assert 5955 in freqs
    assert 5975 in freqs

    print(f"Hopping Sequence Plan: {[f'{c.channel}({c.band})' for c in seq]}")

def test_set_channel_uses_frequency(mock_scout_deps):
    """Verify _set_channel uses 'iw ... set freq ...' to avoid ambiguity."""
    config = ScoutConfig(interface="wlan0", bands=["all"])
    scout = Scout(config)

    # Test setting 6GHz Channel 1 (5955 MHz)
    # Use ChannelInfo object
    from src.wicap.core.capture.channel_hopper import ChannelInfo
    target = ChannelInfo(channel=1, freq=5955, band='6ghz')

    # Call hopper's set_channel, not private scout method
    scout.hopper.set_channel(target)

    # Check subprocess call via mock_run
    args, _ = mock_scout_deps['run'].call_args
    cmd = args[0]

    # Should be: ['iw', 'dev', 'wlan0', 'set', 'freq', '5955']
    assert "freq" in cmd
    assert "5955" in cmd
    assert "channel" not in cmd  # Should NOT use channel number

    # Test setting 2.4GHz Channel 1 (2412 MHz)
    target_24 = ChannelInfo(channel=1, freq=2412, band='2.4ghz')
    scout.hopper.set_channel(target_24)

    args, _ = mock_scout_deps['run'].call_args
    cmd = args[0]
    assert "freq" in cmd
    assert "2412" in cmd

def test_governor_tracks_by_frequency(mock_scout_deps):
    """Verify Neuro-Adaptive Governor tracks stats by frequency key."""
    config = ScoutConfig(interface="wlan0", bands=["all"])
    scout = Scout(config)

    # Simulate visiting 2.4GHz Ch1
    from src.wicap.core.capture.channel_hopper import ChannelInfo
    ch24 = ChannelInfo(channel=1, freq=2412, band='2.4ghz')

    # Mock hopper.get_next_channel
    scout.hopper.get_next_channel = MagicMock(return_value=ch24)
    scout.hopper.set_channel = MagicMock(return_value=True)
    scout._capture_backend = MagicMock()

    # Run cycle
    scout._run_scout_cycle()

    # Check reputation key
    assert 2412 in scout.channel_reputation
    assert 5955 not in scout.channel_reputation

    # Simulate visiting 6GHz Ch1
    ch6 = ChannelInfo(channel=1, freq=5955, band='6ghz')
    scout.hopper.get_next_channel = MagicMock(return_value=ch6)

    scout._run_scout_cycle()

    assert 5955 in scout.channel_reputation
    # Stats should be separate
    assert scout.channel_reputation[2412] is not scout.channel_reputation[5955]

def test_dynamic_dwell_calculation_uses_freq(mock_scout_deps):
    """Verify dwell calculation uses frequency key."""
    config = ScoutConfig(interface="wlan0", bands=["all"])
    scout = Scout(config)

    # Manually seed reputation
    # 2.4GHz Ch1 is DEAD (low yield)
    scout.channel_reputation[2412] = {'visits': 10, 'avg_yield': 0.05}
    # 6GHz Ch1 is ACTIVE (high yield)
    scout.channel_reputation[5955] = {'visits': 10, 'avg_yield': 50.0}

    # Calc dwell for 2.4G Ch1
    dwell_24 = scout._calculate_dynamic_dwell(1, freq=2412)

    # Calc dwell for 6G Ch1
    dwell_6 = scout._calculate_dynamic_dwell(1, freq=5955)

    print(f"Dwell 2412MHz: {dwell_24}s")
    print(f"Dwell 5955MHz: {dwell_6}s")

    # 2.4G should be penalized (short dwell)
    assert dwell_24 < (config.scout_dwell_ms / 1000.0)

    # 6G should be dilated (long dwell)
    assert dwell_6 > (config.scout_dwell_ms / 1000.0)
