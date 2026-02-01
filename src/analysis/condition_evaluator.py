class ConditionEvaluator:
    """
    Evaluates whether an IAM policy condition is satisfied
    under a given execution context.
    """

    def __init__(self, context):
        """
        context: dict describing the current execution environment
        Example:
            {
                "source_ip": "external"
            }
        """
        self.context = context

    def is_satisfied(self, condition):
        """
        condition: dict from IAM policy
        Returns True if condition holds, else False
        """

        if not condition:
            return True

        # Only one condition type supported intentionally
        if "source_ip" in condition:
            return self.context.get("source_ip") == condition["source_ip"]

        # Unknown conditions default to False
        return False