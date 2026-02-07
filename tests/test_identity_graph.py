import time

from nexus.intel.identity_graph import IdentityProfile, build_identity_graph


def test_identity_graph_fingerprint_link():
    profiles = [
        IdentityProfile(identifier="aa:bb:cc:dd:ee:01", protocol="wifi", fingerprint_hash="fp1"),
        IdentityProfile(identifier="aa:bb:cc:dd:ee:02", protocol="wifi", fingerprint_hash="fp1"),
    ]
    graph = build_identity_graph(profiles)
    assert len(graph.clusters) == 1
    cluster = graph.cluster_for("aa:bb:cc:dd:ee:01")
    assert cluster is not None
    assert set(cluster.members) == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}


def test_identity_graph_behavioral_link():
    now = time.time()
    profiles = [
        IdentityProfile(
            identifier="aa:bb:cc:dd:ee:03",
            protocol="wifi",
            probed_ssids={"HomeWiFi", "CafeNet"},
            channels={1, 6},
            avg_rssi=-50,
            first_seen=now - 60,
            last_seen=now,
            is_randomized=True,
        ),
        IdentityProfile(
            identifier="aa:bb:cc:dd:ee:04",
            protocol="wifi",
            probed_ssids={"HomeWiFi", "CafeNet", "Guest"},
            channels={1},
            avg_rssi=-52,
            first_seen=now - 50,
            last_seen=now - 10,
            is_randomized=True,
        ),
    ]
    graph = build_identity_graph(profiles, min_score=0.75, max_time_gap_sec=3600)
    cluster = graph.cluster_for("aa:bb:cc:dd:ee:03")
    assert cluster is not None
    assert len(cluster.members) == 2


def test_identity_graph_does_not_link_non_randomized_without_fingerprint():
    now = time.time()
    profiles = [
        IdentityProfile(
            identifier="aa:bb:cc:dd:ee:05",
            protocol="wifi",
            probed_ssids={"HomeWiFi"},
            channels={1},
            avg_rssi=-40,
            first_seen=now - 60,
            last_seen=now,
            is_randomized=False,
        ),
        IdentityProfile(
            identifier="aa:bb:cc:dd:ee:06",
            protocol="wifi",
            probed_ssids={"HomeWiFi"},
            channels={1},
            avg_rssi=-41,
            first_seen=now - 60,
            last_seen=now,
            is_randomized=False,
        ),
    ]
    graph = build_identity_graph(profiles, min_score=0.6, max_time_gap_sec=3600)
    cluster = graph.cluster_for("aa:bb:cc:dd:ee:05")
    assert cluster is not None
    assert len(cluster.members) == 1


def test_identity_graph_ble_fingerprint_group():
    profiles = [
        IdentityProfile(
            identifier="c0:ff:ee:00:00:01",
            protocol="bt",
            fingerprint_hash="blehash",
            is_randomized=True,
        ),
        IdentityProfile(
            identifier="c0:ff:ee:00:00:02",
            protocol="bt",
            fingerprint_hash="blehash",
            is_randomized=True,
        ),
    ]
    graph = build_identity_graph(profiles)
    cluster = graph.cluster_for("c0:ff:ee:00:00:01")
    assert cluster is not None
    assert len(cluster.members) == 2


def test_identity_graph_compact_profiles_clears_heavy_fields():
    profiles = [
        IdentityProfile(
            identifier="aa:bb:cc:dd:ee:ff",
            protocol="wifi",
            probed_ssids={"corp", "guest"},
            channels={1, 6, 11},
            services={"180d", "180f"},
        ),
        IdentityProfile(
            identifier="11:22:33:44:55:66",
            protocol="bt",
            probed_ssids={"ignored"},
            channels={37, 38},
            services={"180a"},
        ),
    ]
    graph = build_identity_graph(profiles, min_score=0.99)
    graph.compact_profiles()
    for profile in graph.profile_map.values():
        assert profile.probed_ssids == set()
        assert profile.channels == set()
        assert profile.services == set()
