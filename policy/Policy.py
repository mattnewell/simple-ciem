from policyuniverse import expand_policy
from itertools import chain


class Policy:
    def __init__(self, policy):
        self.json = expand_policy(policy=policy, expand_deny=True)
        self.statements = []
        for statement in self.json.get('Statement', []):
            self.statements.append(statement)

    def net_effective_actions(self):
        # Although the label 'Action' is singular, in the spec it is actually a JSON array
        # So we need to flatten statements to actions to action.
        # TODO: This probably isn't efficient
        allowed_actions = []
        for statement in self.statements:
            if statement['Effect'] == 'Allow':
                allowed_actions.extend(statement['Action'])

        denied_actions = []
        for statement in self.statements:
            if statement['Effect'] == 'Deny':
                denied_actions.extend(statement['Action'])

        result = []
        for action in allowed_actions:
            if action not in denied_actions:
                result.append(action)

        return result
