def test_get_hosts(webapp):
    message = 'some message'
    assert webapp.get('/rest/hosts') is None
