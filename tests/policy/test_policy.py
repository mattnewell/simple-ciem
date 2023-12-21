from policy.Policy import Policy


def test_single_action():
    policy = Policy({
        'Statement': [
            {
                'Action': 's3:PutObject',
                'Effect': 'Allow',
                'Resource': '*',
                'Principal': '*'
            }
        ]
    })
    assert policy.net_effect_actions() == ['s3:PutObject']


def test_two_allow_actions():
    policy = Policy({
        'Statement': [
            {
                'Action': 's3:PutObject',
                'Effect': 'Allow',
                'Resource': '*',
                'Principal': '*'
            },
            {
                'Action': 's3:GetObject',
                'Effect': 'Allow',
                'Resource': '*',
                'Principal': '*'
            }
        ]
    })
    assert 's3:PutObject' in policy.net_effect_actions() and 's3:GetObject' in policy.net_effect_actions()



def test_net_empty_same_action():
    policy = Policy({
        'Statement': [
            {
                'Action': 's3:PutObject',
                'Effect': 'Allow',
                'Resource': '*',
                'Principal': '*'
            },
            {
                'Action': 's3:PutObject',
                'Effect': 'Deny',
                'Resource': '*',
                'Principal': '*'
            }
        ]
    })
    assert len(policy.net_effect_actions()) == 0

