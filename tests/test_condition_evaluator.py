import pytest
from src.analysis.condition_evaluator import ConditionEvaluator


def test_no_condition():
    evaluator = ConditionEvaluator({"source_ip": "internal"})
    assert evaluator.is_satisfied(None) == True
    assert evaluator.is_satisfied({}) == True


def test_single_condition_satisfied():
    evaluator = ConditionEvaluator({"source_ip": "internal"})
    condition = {"source_ip": "internal"}
    assert evaluator.is_satisfied(condition) == True


def test_single_condition_not_satisfied():
    evaluator = ConditionEvaluator({"source_ip": "external"})
    condition = {"source_ip": "internal"}
    assert evaluator.is_satisfied(condition) == False


def test_multiple_conditions_all_satisfied():
    evaluator = ConditionEvaluator({"source_ip": "internal", "time_of_day": "business_hours"})
    condition = {"source_ip": "internal", "time_of_day": "business_hours"}
    assert evaluator.is_satisfied(condition) == True


def test_multiple_conditions_one_not_satisfied():
    evaluator = ConditionEvaluator({"source_ip": "internal", "time_of_day": "off_hours"})
    condition = {"source_ip": "internal", "time_of_day": "business_hours"}
    assert evaluator.is_satisfied(condition) == False


def test_unknown_condition():
    evaluator = ConditionEvaluator({"source_ip": "internal"})
    condition = {"unknown_key": "value"}
    assert evaluator.is_satisfied(condition) == False