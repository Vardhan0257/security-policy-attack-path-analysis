"""Tests for threat scoring module (CVSS, NVD integration, threat assessment)."""

import pytest
from src.threat_scoring import (
    CVSSCalculator,
    CVSSScore,
    ThreatAssessment,
    PathThreatScorer,
    PathThreatScore,
    ThreatLevel,
)


class TestCVSSCalculator:
    """Test CVSS v3.1 score calculation."""

    def test_cvss_calculate_base_score_critial(self):
        """Test calculating critical vulnerability (RCE with no privileges required)."""
        calculator = CVSSCalculator()

        # Remote Code Execution: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        score = calculator.calculate_base_score(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        assert score.base_score >= 8.5
        assert score.severity in ["High", "Critical"]
        assert "AV:N" in score.vector_string
        assert "CVSS" not in score.vector_string  # Don't include prefix in string

    def test_cvss_calculate_base_score_low(self):
        """Test calculating low-severity vulnerability."""
        calculator = CVSSCalculator()

        # Low severity: Limited impact, requires authentication
        score = calculator.calculate_base_score(
            attack_vector="L",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        )

        assert score.base_score < 4.0
        assert score.severity == "Low"

    def test_cvss_calculate_no_impact(self):
        """Test vulnerability with no impact."""
        calculator = CVSSCalculator()

        score = calculator.calculate_base_score(
            confidentiality="N",
            integrity="N",
            availability="N",
        )

        assert score.base_score == 0.0
        assert score.severity == "None"

    def test_cvss_parse_vector_string(self):
        """Test parsing CVSS vector string."""
        calculator = CVSSCalculator()

        # Parse vector string
        score = calculator.calculate_from_vector(
            "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        )

        assert score.base_score >= 8.5
        assert score.severity in ["High", "Critical"]
        assert "S:C" in score.vector_string

    def test_cvss_parse_vector_with_prefix(self):
        """Test parsing CVSS vector with CVSS:3.1 prefix."""
        calculator = CVSSCalculator()

        score = calculator.calculate_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )

        assert score.base_score >= 8.5

    def test_cvss_invalid_vector(self):
        """Test handling of invalid vector string."""
        calculator = CVSSCalculator()

        # Partial vectors should still parse (partial data allowed)
        score = calculator.calculate_from_vector("AV:N/AC:L/PR:N")
        assert score is not None  # Should not raise

    def test_cvss_score_color(self):
        """Test severity color mapping."""
        calculator = CVSSCalculator()

        # High/Critical
        critical = calculator.calculate_base_score(
            confidentiality="H", integrity="H", availability="H"
        )
        assert critical.severity_color in ["red", "darkred"]

        # High
        high = calculator.calculate_base_score(
            attack_vector="N",
            confidentiality="H",
            integrity="H",
            availability="N",
        )
        assert high.severity_color in ["red", "darkred", "orange"]

        # Low
        low = calculator.calculate_base_score(
            attack_vector="L",
            privileges_required="H",
            confidentiality="L",
        )
        assert low.severity_color in ["yellow", "orange"]

        # None
        none_score = calculator.calculate_base_score(
            confidentiality="N", integrity="N", availability="N"
        )
        assert none_score.severity_color == "gray"


class TestThreatAssessment:
    """Test threat assessment from attack path characteristics."""

    def test_threat_assessment_exploitable_path(self):
        """Test threat assessment of exploitable path."""
        assessor = ThreatAssessment()

        threat_score, severity, details = assessor.assess_attack_path(
            path=["internet", "web_server", "database"],
            is_exploitable=True,
            requires_authentication=False,
            requires_user_interaction=False,
            network_proximity_required=False,
        )

        assert threat_score > 0.0
        assert severity in ["Low", "Medium", "High", "Critical"]
        assert "cvss_vector" in details
        assert details["path_length"] == 3

    def test_threat_assessment_blocked_path(self):
        """Test threat assessment of non-exploitable path."""
        assessor = ThreatAssessment()

        threat_score, severity, details = assessor.assess_attack_path(
            path=["internet", "database"],
            is_exploitable=False,
        )

        assert threat_score == 0.0
        assert severity == "None"
        assert "not exploitable" in details.get("reason", "").lower()

    def test_threat_assessment_with_auth(self):
        """Test threat assessment with authentication required."""
        assessor = ThreatAssessment()

        threat_score, severity, details = assessor.assess_attack_path(
            path=["internal_network", "admin_system"],
            is_exploitable=True,
            requires_authentication=True,
            requires_user_interaction=True,
            network_proximity_required=True,
        )

        assert threat_score > 0.0
        assert "L" in details["cvss_vector"]  # Local attack vector
        assert details["access_requirements"]["authentication_required"] is True


class TestPathThreatScorer:
    """Test path threat scoring."""

    def test_score_simple_exploitable_path(self):
        """Test scoring a simple exploitable path."""
        scorer = PathThreatScorer()

        result = scorer.score_path(
            path=["internet", "app", "database"],
            is_exploitable=True,
            cvss_base_score=8.0,
            z3_confidence=1.0,
            cve_count=2,
        )

        assert isinstance(result, PathThreatScore)
        assert result.overall_score > 0.0
        assert result.threat_level != ThreatLevel.INFORMATIONAL
        assert result.path_id == "internet|app|database"
        assert len(result.components) == 4

    def test_score_blocked_path(self):
        """Test scoring a blocked/non-exploitable path."""
        scorer = PathThreatScorer()

        result = scorer.score_path(
            path=["external", "protected_resource"],
            is_exploitable=False,
        )

        # Non-exploitable paths still get scored based on potential impact
        # but exploitability is 0
        assert result.exploitability_score == 0.0
        assert result.threat_level == ThreatLevel.INFORMATIONAL or result.threat_level == ThreatLevel.LOW
        assert len(result.recommendations) > 0

    def test_score_privesc_path(self):
        """Test scoring path with privilege escalation."""
        scorer = PathThreatScorer()

        result = scorer.score_path(
            path=["user_app", "admin_service"],
            is_exploitable=True,
            has_privilege_escalation=True,
            has_authentication_bypass=False,
        )

        # Privesc should increase exploitability
        assert result.exploitability_score > 3.5

    def test_score_long_path_vs_short_path(self):
        """Test that short paths score higher than long paths."""
        scorer = PathThreatScorer()

        short = scorer.score_path(
            path=["source", "destination"],
            is_exploitable=True,
            cvss_base_score=5.0,
        )

        long = scorer.score_path(
            path=["source", "mid1", "mid2", "mid3", "mid4", "destination"],
            is_exploitable=True,
            cvss_base_score=5.0,
        )

        # Short path should have higher lineage score
        assert short.lineage_score > long.lineage_score
        # And overall score should be higher (if all else equal)
        assert short.overall_score > long.overall_score

    def test_score_multiple_paths(self):
        """Test scoring multiple paths."""
        scorer = PathThreatScorer()

        paths = [
            {
                "path": ["internet", "web", "db"],
                "is_exploitable": True,
                "cvss_base_score": 8.0,
                "cve_count": 1,
            },
            {
                "path": ["internal", "admin"],
                "is_exploitable": True,
                "cvss_base_score": 6.0,
                "cve_count": 0,
            },
            {
                "path": ["external", "locked"],
                "is_exploitable": False,
            },
        ]

        results = scorer.score_multiple_paths(paths)

        # Should return sorted by score (highest first)
        assert len(results) == 3
        assert results[0].overall_score >= results[1].overall_score
        assert results[0].overall_score >= results[2].overall_score

    def test_threat_level_mapping(self):
        """Test threat level to score mapping."""
        scorer = PathThreatScorer()

        # High (weighted average of impact 9.5 + other factors)
        high = scorer.score_path(
            path=["source", "target"],
            is_exploitable=True,
            cvss_base_score=9.5,
        )
        assert high.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]

        # Medium-High
        medium_high = scorer.score_path(
            path=["source", "target"],
            is_exploitable=True,
            cvss_base_score=7.5,
        )
        assert medium_high.threat_level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM]

        # Medium
        medium = scorer.score_path(
            path=["source", "target"],
            is_exploitable=True,
            cvss_base_score=5.0,
        )
        assert medium.threat_level in [ThreatLevel.MEDIUM, ThreatLevel.LOW]

    def test_path_threat_score_json_serialization(self):
        """Test that threat score can be converted to JSON-serializable dict."""
        scorer = PathThreatScorer()

        result = scorer.score_path(
            path=["a", "b", "c"],
            is_exploitable=True,
            cvss_base_score=7.0,
            cve_count=2,
            max_cve_score=8.5,
        )

        # Convert to dict (should be JSON-serializable)
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        # Score is rounded to 1 decimal in dict
        assert abs(round(result_dict["overall_score"], 1) - round(result.overall_score, 1)) < 0.1
        assert result_dict["threat_level"] in ["High", "Medium", "Low"]
        assert len(result_dict["components"]) == 4
        assert "recommendations" in result_dict

    def test_recommendations_generated(self):
        """Test that recommendations are generated based on threat."""
        scorer = PathThreatScorer()

        result = scorer.score_path(
            path=["external", "mid1", "mid2", "mid3", "database"],
            is_exploitable=True,
            cvss_base_score=8.0,
            cve_count=3,
        )

        assert len(result.recommendations) > 0
        # Should include CVE recommendation
        assert any("CVE" in r or "cve" in r for r in result.recommendations)

    def test_confidence_score_from_z3(self):
        """Test confidence score includes Z3 verification confidence."""
        scorer = PathThreatScorer()

        high_confidence = scorer.score_path(
            path=["a", "b"],
            is_exploitable=True,
            z3_confidence=0.99,
        )

        low_confidence = scorer.score_path(
            path=["a", "b"],
            is_exploitable=True,
            z3_confidence=0.50,
        )

        # Higher Z3 confidence should increase confidence score component
        assert high_confidence.confidence_score > low_confidence.confidence_score


class TestIntegrationScenarios:
    """Integration tests combining multiple components."""

    def test_end_to_end_threat_assessment(self):
        """Test complete threat assessment workflow."""
        calculator = CVSSCalculator()
        scorer = PathThreatScorer()

        # Simulate real attack path discovery
        cvss_score = calculator.calculate_base_score(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H",
        )

        path_threat = scorer.score_path(
            path=["internet", "web_app", "api_server", "database"],
            is_exploitable=True,
            cvss_base_score=cvss_score.base_score,
            z3_confidence=1.0,
            cve_count=1,
            max_cve_score=cvss_score.base_score,
        )

        assert path_threat.overall_score > 6.0
        assert path_threat.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        assert len(path_threat.components) == 4

    def test_multiple_path_prioritization(self):
        """Test prioritization of multiple discovered paths."""
        scorer = PathThreatScorer()

        # Multiple paths with different characteristics
        paths = [
            {
                "path": ["internet", "web", "app", "secrets"],
                "is_exploitable": True,
                "cvss_base_score": 9.5,
                "cve_count": 2,
                "max_cve_score": 9.2,
                "has_privilege_escalation": True,
            },
            {
                "path": ["internal", "admin_panel"],
                "is_exploitable": True,
                "cvss_base_score": 7.0,
                "cve_count": 0,
            },
            {
                "path": ["external", "api"],
                "is_exploitable": False,
            },
        ]

        results = scorer.score_multiple_paths(paths)

        # First should be high or higher threat
        assert results[0].threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]

        # Should be sorted by risk
        for i in range(len(results) - 1):
            assert results[i].overall_score >= results[i + 1].overall_score
