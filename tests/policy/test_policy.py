from policy.Policy import Policy


def test_single_action():
    policy = Policy({
        'Statement': [
            {
                'Action': ['s3:PutObject'],
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
                'Action': 's3:PutObject',
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:GetObject',
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
                'Action': 's3:PutObject',
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:PutObject',
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
                'Action': ['s3:PutObject', 's3:DeleteObject'],
                'Effect': 'Allow',
                'Resource': '*',
            },
            {
                'Action': 's3:PutObject',
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
                'Action': 's3:PutObject',
                'Effect': 'Deny',
                'Resource': '*',
            }
        ]
    })
    net_actions = policy.net_effective_actions()
    assert 's3:putobject' not in net_actions
    assert 's3:getobject' in net_actions
