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
