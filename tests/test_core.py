# -*- coding: utf-8 -*-
"""Tests for AgentReach core class."""

import pytest

from agent_reach.config import Config
from agent_reach.core import AgentReach


@pytest.fixture
def eyes(tmp_path):
    config = Config(config_path=tmp_path / "config.yaml")
    return AgentReach(config=config)


class TestAgentReach:
    def test_init(self, eyes):
        assert eyes.config is not None

    def test_doctor(self, eyes):
        results = eyes.doctor()
        assert isinstance(results, dict)
        assert "web" in results
        assert "github" in results

    def test_doctor_report(self, eyes):
        report = eyes.doctor_report()
        assert isinstance(report, str)
        assert "Agent Reach" in report

    def test_does_not_dispatch_can_handle_into_fetch(self):
        """RSS/web matchers are unused by the public class; it is doctor-only."""
        public = {
            name
            for name in dir(AgentReach)
            if not name.startswith("_")
        }
        assert "doctor" in public
        assert "doctor_report" in public
        assert "read" not in public
        assert "search" not in public
        assert not hasattr(AgentReach, "read")
        assert not hasattr(AgentReach, "search")
