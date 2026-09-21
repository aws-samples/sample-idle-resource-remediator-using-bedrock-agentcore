# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Basic tests for idle-resource-remediator MCP server tools."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone


def test_get_regions_from_env():
    """Test region discovery from environment variable."""
    with patch.dict("os.environ", {"SCAN_REGIONS": "us-east-1,eu-west-2"}):
        from src.mcp_server import _get_regions
        regions = _get_regions()
        assert regions == ["us-east-1", "eu-west-2"]


def test_excluded_regions():
    """Test that GovCloud and China regions are excluded."""
    from src.mcp_server import EXCLUDED_REGIONS
    assert "us-gov-west-1" in EXCLUDED_REGIONS
    assert "cn-north-1" in EXCLUDED_REGIONS


def test_non_commercial_partitions_never_scannable():
    """GovCloud, China, and ISO partitions must never be scannable, on any path."""
    from src.mcp_server import _is_scannable
    for r in ["cn-north-1", "cn-northwest-1", "us-gov-west-1", "us-gov-east-1",
              "us-iso-east-1", "us-isob-east-1", "us-isof-south-1", "eu-isoe-west-1"]:
        assert _is_scannable(r) is False, r
    for r in ["us-east-1", "eu-west-2", "ap-southeast-2"]:
        assert _is_scannable(r) is True, r


def test_default_scope_is_important_commercial_regions():
    """With no region arg and no env override, default to curated commercial regions only."""
    with patch.dict("os.environ", {}, clear=False):
        import os
        os.environ.pop("SCAN_REGIONS", None)
        from src.mcp_server import _get_regions
        regions = _get_regions()
        assert "us-east-1" in regions
        assert all(not r.startswith(("us-gov-", "cn-", "us-iso", "eu-isoe")) for r in regions)


def test_named_region_scopes_to_one():
    """A single region named in the prompt scopes to only that region."""
    from src.mcp_server import _get_regions
    assert _get_regions("us-east-1") == ["us-east-1"]


def test_named_non_commercial_region_returns_empty():
    """A China/GovCloud region named in the prompt is still refused."""
    from src.mcp_server import _get_regions
    assert _get_regions("cn-north-1") == []
    assert _get_regions("us-gov-west-1") == []


def test_ec2_idle_helper_matches_compute_optimizer_criteria():
    """_is_ec2_idle mirrors Compute Optimizer: peak CPU < 5% AND network < 5 MB/day."""
    from src.agent import _is_ec2_idle, EC2_IDLE_NETWORK_BYTES_PER_DAY
    days = 14
    mb = 1024 * 1024
    # Idle: 0.8% peak CPU, 1 MB total network over 14 days (well under 5 MB/day)
    assert _is_ec2_idle(0.8, 1 * mb, days) is True
    # Not idle: high peak CPU
    assert _is_ec2_idle(72.0, 1 * mb, days) is False
    # Not idle: network over the 5 MB/day budget (100 MB > 70 MB threshold)
    assert _is_ec2_idle(1.0, 100 * mb, days) is False
    # Exactly at the daily budget is not "under" the threshold
    assert _is_ec2_idle(1.0, EC2_IDLE_NETWORK_BYTES_PER_DAY * days, days) is False
    # Guard: non-positive lookback never idle
    assert _is_ec2_idle(0.0, 0.0, 0) is False


def test_check_safety_blocked_by_asg():
    """Test that ASG members get BLOCKED verdict."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-test123",
                "Tags": [{"Key": "aws:autoscaling:groupName", "Value": "my-asg"}],
                "IamInstanceProfile": None,
            }]
        }]
    }
    mock_cw = MagicMock()
    mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

    with patch("boto3.client") as mock_client:
        mock_client.side_effect = lambda service, **kwargs: mock_ec2 if service == "ec2" else mock_cw
        from src.mcp_server import check_safety
        result = check_safety("i-test123", "us-east-1")
        assert result["verdict"] == "BLOCKED"
        assert any("ASG" in s["signal"] for s in result["signals"])


def test_snapshot_required_before_delete():
    """Test that volume deletion always creates a snapshot first."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_snapshots.return_value = {"Snapshots": []}
    mock_ec2.create_snapshot.return_value = {"SnapshotId": "snap-test123"}
    mock_ec2.get_waiter.return_value.wait.return_value = None
    mock_ec2.delete_volume.return_value = {}

    mock_cw = MagicMock()
    mock_cw.get_metric_statistics.return_value = {"Datapoints": []}

    with patch("boto3.client") as mock_client:
        mock_client.side_effect = lambda service, **kwargs: mock_ec2 if service == "ec2" else mock_cw
        from src.mcp_server import snapshot_and_delete_volume
        result = snapshot_and_delete_volume("vol-test123", "us-east-1", "test cleanup")
        assert result["snapshot_id"] == "snap-test123"
        assert result["result"] == "success"
        mock_ec2.create_snapshot.assert_called_once()


def test_release_eip_blocked_if_associated():
    """Test that associated EIPs cannot be released."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_addresses.return_value = {
        "Addresses": [{"AllocationId": "eipalloc-test", "AssociationId": "eipassoc-123", "PublicIp": "1.2.3.4"}]
    }

    with patch("boto3.client", return_value=mock_ec2):
        from src.mcp_server import release_elastic_ip
        result = release_elastic_ip("eipalloc-test", "us-east-1", "test")
        assert "error" in result
        assert "still associated" in result["error"]
