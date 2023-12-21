class Policy:
    def __init__(self, policy):
        self.policy = policy
        self.statements = []
        for statement in policy.get('Statement', []):
            self.statements.append(statement)

    def net_effect_actions(self):
        actions = []
        for statement in self.statements:
            deny = False
            for inner in self.statements:
                if statement['Action'] == inner['Action'] and inner['Effect'] == 'Deny':
                    deny = True
                    break
            if not deny:
                actions.append(statement['Action'])
        return actions
