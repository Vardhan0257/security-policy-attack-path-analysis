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
        Returns True if ALL conditions hold, else False
        """
        if not condition:
            return True

        for key, value in condition.items():
            if key == "source_ip":
                if self.context.get("source_ip") != value:
                    return False
            elif key == "time_of_day":
                if self.context.get("time_of_day") != value:
                    return False
            else:
                # Unknown conditions default to False
                return False

        return True