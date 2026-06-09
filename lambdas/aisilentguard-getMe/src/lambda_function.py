# Feature 1: User Authentication
# This Lambda connects the authenticated Cognito user to the Users table.
# It allows the frontend to check if the logged-in user already exists
# and to create or update the user's profile after login.

import json
import os
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")

USERS_TABLE = os.environ["USERS_TABLE"]
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

table = dynamodb.Table(USERS_TABLE)


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body),
    }


# Feature 1: User Authentication
# Extract the Cognito claims from the API Gateway request.
# The claims contain the authenticated user's unique id and email.
def get_claims(event):
    return (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("claims", {})
    )


def lambda_handler(event, context):
    method = event.get("httpMethod")

    if method == "OPTIONS":
        return response(200, {"ok": True})

    claims = get_claims(event)
    user_id = claims.get("sub")
    email = claims.get("email")

    # Feature 1: User Authentication
    # Reject the request if the user is not authenticated by Cognito.
    if not user_id:
        return response(401, {
            "error": "Unauthorized: missing Cognito sub claim"
        })

    # Feature 2: Personal Dashboard
    # Return the current user's profile so the dashboard can load
    # the correct personal information.
    if method == "GET":
        result = table.get_item(
            Key={
                "userId": user_id
            }
        )

        item = result.get("Item")

        if not item:
            return response(200, {
                "exists": False,
                "user": {
                    "userId": user_id,
                    "email": email
                }
            })

        return response(200, {
            "exists": True,
            "user": item
        })

    # Feature 1: User Authentication
    # Feature 2: Personal Dashboard
    # Create or update the user record after login/registration.
    # The user profile is stored in DynamoDB and later used by the dashboard.
    if method == "POST":
        try:
            body = json.loads(event.get("body") or "{}")
        except json.JSONDecodeError:
            return response(400, {
                "error": "Invalid JSON body"
            })

        now = datetime.now(timezone.utc).isoformat()

        name = body.get("name") or email or "New User"
        role = body.get("role") or "user"

        result = table.update_item(
            Key={
                "userId": user_id
            },
            UpdateExpression="""
                SET email = :email,
                    #name = :name,
                    #role = :role,
                    updatedAt = :updatedAt,
                    createdAt = if_not_exists(createdAt, :createdAt)
            """,
            ExpressionAttributeNames={
                "#name": "name",
                "#role": "role",
            },
            ExpressionAttributeValues={
                ":email": email or body.get("email", ""),
                ":name": name,
                ":role": role,
                ":updatedAt": now,
                ":createdAt": now,
            },
            ReturnValues="ALL_NEW",
        )

        return response(200, {
            "exists": True,
            "user": result.get("Attributes", {})
        })

    return response(405, {
        "error": f"Method {method} not allowed"
    })