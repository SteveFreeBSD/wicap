import pytest

from config import ScoutConfig, get_scout_config
from parser import FrameType, MgmtSubtype, ParsedFrame, SecurityInfo
from scorer import RuleScorer


def _make_frame(rssi, channel=1):
    return ParsedFrame(
        timestamp=123.0,
        channel=channel,
        rssi=rssi,
        frame_type=FrameType.MANAGEMENT,
        frame_subtype=MgmtSubtype.BEACON,
        security=SecurityInfo(is_open=False),
    )


@pytest.mark.unit
def test_strong_rssi_awards_points_above_threshold():
    config = ScoutConfig()
    config.rssi_strong_threshold = -80
    config.score_strong_rssi = 2
    scorer = RuleScorer(config)

    frame = _make_frame(-70, channel=6)
    result = scorer.score_frame(frame)

    assert result.is_strong_rssi is True
    assert result.points == 2
    assert any(reason.startswith("strong_rssi") for reason in result.reasons)
    assert scorer.get_channel_score(6, current_time=frame.timestamp) == 2


@pytest.mark.unit
def test_rssi_at_threshold_is_not_strong():
    config = ScoutConfig()
    config.rssi_strong_threshold = -80
    scorer = RuleScorer(config)

    frame = _make_frame(-80, channel=11)
    result = scorer.score_frame(frame)

    assert result.is_strong_rssi is False
    assert result.points == 0
    assert scorer.get_channel_score(11, current_time=frame.timestamp) == 0


@pytest.mark.unit
def test_rssi_none_is_not_scored():
    config = ScoutConfig()
    config.rssi_strong_threshold = -80
    scorer = RuleScorer(config)

    frame = _make_frame(None, channel=1)
    result = scorer.score_frame(frame)

    assert result.is_strong_rssi is False
    assert result.points == 0


@pytest.mark.unit
def test_env_overrides_rssi_threshold(monkeypatch):
    monkeypatch.setenv("WICAP_RSSI_STRONG_THRESHOLD", "-72")
    config = get_scout_config()
    assert config.rssi_strong_threshold == -72
