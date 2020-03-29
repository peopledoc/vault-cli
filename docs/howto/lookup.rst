Get information on your current token
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Request information on your current token as YAML, including policies, expire_time etc.
This will not work if the token is already expired.

.. code:: console

   $ vault-cli lookup-token
    ---
    auth: null
    data:
    accessor: 8Wset9ZCnnsFINCSmcUlezNY
    creation_time: 1584904024
    creation_ttl: 0
    display_name: token
    entity_id: ''
    expire_time: null
    explicit_max_ttl: 0
    id: some-token
    issue_time: '2020-03-22T19:07:04.4995906Z'
    meta: null
    num_uses: 0
    orphan: true
    path: auth/token/create
    policies:
    - root
    renewable: false
    ttl: 0
    type: service
    lease_duration: 0
    lease_id: ''
    renewable: false
    request_id: 72af6b1d-b268-76ca-0e2c-65a134be5c03
    warnings: null
    wrap_info: null
