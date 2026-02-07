"""
Unit tests for NEXUS Risk Scorer.
"""

import pytest

from nexus.risk_scorer import RiskLevel, RiskScorer


class TestRiskScorer:
    """Tests for the RiskScorer class."""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_open_network_critical(self):
        """Open networks should have critical risk score."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='OpenCafe',
            is_open=True,
        )

        assert assessment.total_score >= 80
        assert assessment.level == RiskLevel.CRITICAL
        assert 'OPEN_NETWORK' in assessment.factor_names

    def test_wep_network_critical(self):
        """WEP networks should have critical risk score."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='OldRouter',
            has_wep=True,
        )

        assert assessment.total_score >= 80
        assert assessment.level == RiskLevel.CRITICAL
        assert 'WEP_ENCRYPTION' in assessment.factor_names

    def test_wpa2_psk_with_pmf(self):
        """WPA2-PSK with PMF should have low/medium risk score."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='HomeNetwork',
            has_wpa2=True,
            cipher='CCMP',
            akm='PSK',
            has_pmf=True,  # With PMF, score is 30-15=15
        )

        # WPA2_PSK (30) + PMF_ENABLED (-15) = 15 (LOW/INFO)
        assert assessment.total_score < 40
        assert 'WPA2_PSK' in assessment.factor_names
        assert 'PMF_ENABLED' in assessment.factor_names

    def test_wpa2_psk_without_pmf_high_risk(self):
        """WPA2-PSK without PMF should have high risk score."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='NoProtection',
            has_wpa2=True,
            cipher='CCMP',
            akm='PSK',
            has_pmf=False,
        )

        # WPA2_PSK (30) + NO_PMF (35) = 65 (HIGH)
        assert assessment.total_score >= 60
        assert 'WPA2_PSK' in assessment.factor_names
        assert 'NO_PMF' in assessment.factor_names

    def test_wpa3_sae_low_risk(self):
        """WPA3-SAE should have low/info risk score."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='SecureHome',
            has_wpa3=True,
            cipher='CCMP',
            akm='SAE',
            has_pmf=True,
        )

        assert assessment.total_score < 40
        assert 'WPA3_SAE' in assessment.factor_names
        assert 'PMF_ENABLED' in assessment.factor_names

    def test_tkip_only_high_risk(self):
        """TKIP-only cipher should flag as high risk."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='LegacyNet',
            has_wpa2=True,
            cipher='TKIP',
            akm='PSK',
        )

        assert 'TKIP_ONLY' in assessment.factor_names

    def test_no_pmf_flagged(self):
        """Lack of PMF should be flagged for WPA networks."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='NoPMF',
            has_wpa2=True,
            cipher='CCMP',
            akm='PSK',
            has_pmf=False,
        )

        assert 'NO_PMF' in assessment.factor_names

    def test_default_ssid_detection(self):
        """Default SSIDs should be flagged."""
        for ssid in ['NETGEAR45', 'linksys', 'TP-Link_Guest', 'default']:
            assessment = self.scorer.assess_network(
                bssid='00:11:22:33:44:55',
                ssid=ssid,
                has_wpa2=True,
            )
            assert 'DEFAULT_SSID' in assessment.factor_names, f"Failed for SSID: {ssid}"

    def test_handshake_captured_increases_risk(self):
        """Captured handshake should increase risk score."""
        without_hs = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='TestNet',
            has_wpa2=True,
            cipher='CCMP',
            akm='PSK',
        )

        with_hs = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='TestNet',
            has_wpa2=True,
            cipher='CCMP',
            akm='PSK',
            handshake_captured=True,
        )

        assert with_hs.total_score > without_hs.total_score
        assert 'HANDSHAKE_CAPTURED' in with_hs.factor_names

    def test_to_dict(self):
        """Assessment should serialize to dict properly."""
        assessment = self.scorer.assess_network(
            bssid='00:11:22:33:44:55',
            ssid='Test',
            is_open=True,
        )

        d = assessment.to_dict()
        assert d['bssid'] == '00:11:22:33:44:55'
        assert d['ssid'] == 'Test'
        assert isinstance(d['total_score'], int)
        assert isinstance(d['factors'], list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
