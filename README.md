PostMan:

Token endpoint:
- URI: http://localhost:8901/api/v1/oauth2/token
- Request method: POST
- Authorization Type: Basic Auth
  test_client
  test_secret
- Body (form-data)
  username
  password
  grant_type:client_credentials
  scope:test.read
