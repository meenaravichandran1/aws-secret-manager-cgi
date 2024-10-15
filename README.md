# aws-secret-manager-cgi

Handler for AWS secret manager

Sample json input:

```json
{
    "task": {
        "id": "your-task-id",
        "driver": "cgi",
        "config": {
            "repository": {
                "clone": "https:github.com/meenaravichandran1/aws-secret-manager-cgi",
                "ref": "main"
            }
            "version":"1.0.0"
        },
        "type": "cgi_task",
        "data": {
            "secret_params" : {
                "secret_operation": "connect",
                "store_config": {
                    "region": "us-east-1",
                    "access_key": "yourAccessKey",
                    "secret_key": "yourSecretKey"
                },
                // primary secret to act on; used in create, read, delete, update, rename flows
                "secret": {
                    "name": "your-secret-name"
                }
                // used only in update, rename flows
                 "existing_secret": {
                    "name": "your-secret-name"
                }
            }
        }
    }
}
