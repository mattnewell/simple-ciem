from policy.Policy import Policy


# The policyuniverse library forces all actions to lowercase, which is fine, but need to be aware of it --
# there is a very real risk of false positives in assert not in statements
def test_single_action():
    policy = Policy({
        'Statement': [
            {
                'Action': ['s3:putobject'],
                'Effect': 'Allow',
                'Resource': '*',
            }
        ]
    })
    assert policy.net_effective_actions() == ['s3:putobject']


def test_two_allow_actions():
    policy = Policy({
        'Statement': [
            {
                'Action': 's3:putobject',
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:getobject',
                'Effect': 'Allow',
                'Resource': '*',
            }
        ]
    })
    # TODO: Deal with case sensitivity
    assert 's3:putobject' in policy.net_effective_actions()
    assert 's3:getobject' in policy.net_effective_actions()


def test_net_empty_same_action():
    policy = Policy({
        'Statement': [
            {
                'Action': 's3:putobject',
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:putobject',
                'Effect': 'Deny',
                'Resource': '*',
            }
        ]
    })
    assert len(policy.net_effective_actions()) == 0


def test_net_two_actions():
    policy = Policy({
        'Statement': [
            {
                'Action': ['s3:putobject', 's3:deleteobject'],
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:putobject',
                'Effect': 'Deny',
                'Resource': '*',
            }
        ]
    })
    assert len(policy.net_effective_actions()) == 1


def test_allow_star_deny_specific():
    policy = Policy({
        'Statement': [
            {
                'Action': 's3:*',
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:putobject',
                'Effect': 'Deny',
                'Resource': '*',
            }
        ]
    })
    net_actions = policy.net_effective_actions()
    assert 's3:putobject' not in net_actions
    assert 's3:getobject' in net_actions
