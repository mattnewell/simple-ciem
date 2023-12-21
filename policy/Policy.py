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
        allowed_actions = [action for actions in
                           [statement['Action'] for statement in self.statements if statement['Effect'] == 'Allow']
                           for action in actions]
        denied_actions = [action for actions in
                          [statement['Action'] for statement in self.statements if statement['Effect'] == 'Deny']
                          for action in actions]
        return [action for action in allowed_actions if action not in denied_actions]
