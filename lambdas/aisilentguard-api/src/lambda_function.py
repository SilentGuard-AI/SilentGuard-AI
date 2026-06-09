import json
import os
import uuid
import re
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
USERS_TABLE = os.environ.get("USERS_TABLE", "AISilentGuardUsers")
GUARDIANS_TABLE = os.environ.get("GUARDIANS_TABLE", "AISilentGuardGuardians")
CALL_RECORDS_TABLE = os.environ.get("CALL_RECORDS_TABLE", "SilentGuardCallRecords")
SETTINGS_TABLE = os.environ.get("SETTINGS_TABLE", "AISilentGuardSettings")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://d3fxslbm1g4ngs.cloudfront.net")

# Feature 11: User Settings
# Default protection settings used when no settings record exists in DynamoDB.
DEFAULT_SETTINGS = {
    "settingId": "global",
    "alertThreshold": 25,
    "disconnectThreshold": 70,
    "suspiciousKeywords": [
        "verification code", "bank account", "urgent", "police",
        "transfer money", "do not tell anyone", "gift card",
        "password", "credit card", "otp", "pin security code"
    ],
}

dynamodb = boto3.resource("dynamodb", region_name=REGION)
users_table = dynamodb.Table(USERS_TABLE)
guardians_table = dynamodb.Table(GUARDIANS_TABLE)
call_records_table = dynamodb.Table(CALL_RECORDS_TABLE)
settings_table = dynamodb.Table(SETTINGS_TABLE)
ses_client = boto3.client("ses", region_name=REGION)


def json_default(value):
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    raise TypeError(f"Object of type {type(value)} is not JSON serializable")


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        },
        "body": json.dumps(body, default=json_default),
    }


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_israeli_phone(raw):
    return "".join(ch for ch in str(raw or "") if ch not in " -()")


def validate_guardian_phone(raw):
    phone = normalize_israeli_phone(raw)
    if not phone:
        raise ValueError("guardianPhone/phone is required")
    if phone.startswith("0"):
        raise ValueError("Use international format +972..., not local 050/052 format")
    if not phone.startswith("+972"):
        raise ValueError("Guardian phone must start with +972")
    digits = phone[1:]
    if not digits.isdigit():
        raise ValueError("Guardian phone may contain only digits after +")
    local = phone[4:]
    if len(local) not in (8, 9) or local[0] not in "23456789":
        raise ValueError("Guardian phone must be a valid Israeli E.164 number, for example +972507776403")
    if len(set(digits)) == 1 or "123123" in digits or "123456" in digits or "000000" in digits or "111111" in digits:
        raise ValueError("Guardian phone looks fake. Use a real phone number")
    return phone

def normalize_email(raw):
    return str(raw or "").strip().lower()


def validate_guardian_email(raw):
    email = normalize_email(raw)

    if not email:
        return ""

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("Guardian email is not valid")

    return email


def get_ses_email_status(email):
    email = normalize_email(email)

    if not email:
        return "none"

    try:
        result = ses_client.get_identity_verification_attributes(
            Identities=[email]
        )

        attrs = result.get("VerificationAttributes", {}).get(email)

        if not attrs:
            return "not_started"

        status = str(attrs.get("VerificationStatus", "")).lower()

        if status == "success":
            return "verified"

        if status == "pending":
            return "pending"

        if status == "failed":
            return "failed"

        return status or "unknown"

    except ClientError as exc:
        print("SES get identity status failed:", str(exc))
        return "unknown"


def request_ses_email_verification(email):
    email = validate_guardian_email(email)

    if not email:
        return "none", ""

    current_status = get_ses_email_status(email)

    if current_status == "verified":
        return "verified", ""

    try:
        ses_client.verify_email_identity(
            EmailAddress=email
        )

        return "pending", ""

    except ClientError as exc:
        print("SES verify email identity failed:", str(exc))
        return "failed", str(exc)


def refresh_guardian_email_status(guardian):
    email = normalize_email(
        guardian.get("guardianEmail")
        or guardian.get("email")
        or guardian.get("Email")
    )

    guardian_id = guardian.get("guardianId")

    if not guardian_id:
        return guardian

    if not email:
        new_status = "none"
    else:
        new_status = get_ses_email_status(email)

    email_verified = new_status == "verified"

    try:
        guardians_table.update_item(
            Key={"guardianId": guardian_id},
            UpdateExpression="""
                SET guardianEmailStatus = :status,
                    emailVerified = :verified,
                    emailNotificationEnabled = :enabled,
                    updatedAt = :updatedAt
            """,
            ExpressionAttributeValues={
                ":status": new_status,
                ":verified": email_verified,
                ":enabled": email_verified,
                ":updatedAt": now_iso(),
            },
        )
    except ClientError as exc:
        print("Failed to update guardian email status:", str(exc))

    guardian["guardianEmailStatus"] = new_status
    guardian["emailVerified"] = email_verified
    guardian["emailNotificationEnabled"] = email_verified

    return guardian


def refreshed_guardians_for_user(user_id):
    guardians = guardians_for_user(user_id)
    return [refresh_guardian_email_status(g) for g in guardians]

def parse_body(event):
    raw = event.get("body") or "{}"
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON body")

# Feature 1: User Authentication
# Extract Cognito claims from the API Gateway event.
def get_claims(event):
    authorizer = event.get("requestContext", {}).get("authorizer", {})
    return authorizer.get("claims") or authorizer.get("jwt", {}).get("claims") or {}


def get_user_id_and_email(event):
    claims = get_claims(event)
    return claims.get("sub"), claims.get("email"), claims


def is_admin_claims(claims):
    groups = claims.get("cognito:groups") or claims.get("groups") or ""
    if isinstance(groups, list):
        return "Admin" in groups or "admin" in groups
    return "Admin" in str(groups).split(",") or "admin" in str(groups).split(",")

# Feature 1: User Authentication
# Require a valid logged-in Cognito user before accessing protected routes.
def require_auth(event):
    user_id, email, claims = get_user_id_and_email(event)
    if not user_id:
        return None, None, None, response(401, {"message": "Unauthorized: missing Cognito user claim"})
    return user_id, email, claims, None

# Feature 1: User Authentication
# Require admin permissions for admin-only routes.
def require_admin(event):
    user_id, email, claims, err = require_auth(event)
    if err:
        return None, None, None, err
    if not is_admin_claims(claims):
        return None, None, None, response(403, {"message": "Admin access required"})
    return user_id, email, claims, None


def route_path(event):
    # REST API uses path. HTTP API may use rawPath.
    return event.get("path") or event.get("rawPath") or "/"


def route_method(event):
    return event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method") or "GET"


def scan_all(table, **kwargs):
    items = []
    last_key = None
    while True:
        params = dict(kwargs)
        if last_key:
            params["ExclusiveStartKey"] = last_key
        result = table.scan(**params)
        items.extend(result.get("Items", []))
        last_key = result.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def get_user_item(user_id):
    result = users_table.get_item(Key={"userId": user_id})
    return result.get("Item")

# Feature 2: Personal Dashboard
# Feature 3: Monitoring Control
# Feature 4: SilentGuard Protection Number
# Normalize the user object returned to the frontend dashboard.
def normalize_user(item, email=None):
    item = item or {}
    return {
        **item,
        "userId": item.get("userId"),
        "email": item.get("email") or email or "",
        "name": item.get("name") or item.get("email") or email or "New User",
        "phone": item.get("phone") or item.get("phone_number") or "",
        "role": item.get("role", "user"),
        "monitoringEnabled": item.get("monitoringEnabled", True),
        "connectNumber": item.get("connectNumber") or item.get("phone") or "Provisioning...",
    }

# Feature 1: User Authentication
# Feature 2: Personal Dashboard
# Create the user record on first login if it does not already exist.
def ensure_user(user_id, email):
    item = get_user_item(user_id)
    if item:
        return normalize_user(item, email)

    timestamp = now_iso()
    item = {
        "userId": user_id,
        "email": email or "",
        "name": email or "New User",
        "role": "user",
        "monitoringEnabled": True,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    users_table.put_item(Item=item)
    return item

# Feature 8: Guardian Management
# Load only active guardians that belong to the logged-in user.
def guardians_for_user(user_id):
    try:
        result = guardians_table.query(
            IndexName="userId-index",
            KeyConditionExpression=Key("userId").eq(user_id),
        )
        items = result.get("Items", [])
    except ClientError as exc:
        # Fallback for MVP if the userId GSI was not created yet.
        print("Guardian query by GSI failed, falling back to scan:", str(exc))
        items = scan_all(
            guardians_table,
            FilterExpression=Attr("userId").eq(user_id),
        )

    return [g for g in items if g.get("status", "active") == "active"]

# Feature 10: Call History
# Load previous call/risk records for the logged-in user.
def call_records_for_user(user_id, limit=20, risk_level=None):
    try:
        result = call_records_table.query(
            IndexName="userId-createdAt-index",
            KeyConditionExpression=Key("userId").eq(user_id),
            ScanIndexForward=False,
            Limit=limit,
        )
        items = result.get("Items", [])
        if risk_level:
            items = [e for e in items if str(e.get("riskLevel", "")).upper() == str(risk_level).upper()]
    except ClientError as exc:
        print("Call record query by GSI failed, falling back to scan:", str(exc))
        filter_expr = Attr("userId").eq(user_id)
        if risk_level:
            filter_expr = filter_expr & Attr("riskLevel").eq(str(risk_level).upper())
        items = scan_all(call_records_table, FilterExpression=filter_expr)
        items.sort(key=lambda x: x.get("createdAt") or x.get("timestamp") or "", reverse=True)
    return items[:limit]


def all_call_records(limit=100):
    items = scan_all(call_records_table)
    items.sort(key=lambda x: x.get("createdAt") or x.get("timestamp") or "", reverse=True)
    return items[:limit]

# Feature 6: Scam Risk Classification
# Feature 7: Risk Event Storage
# Feature 9: Guardian Alerts
# Feature 10: Call History
# Normalize a saved call/risk event before returning it to the dashboard/history UI.
def normalize_event(item):
    if not item:
        return None
    call_id = item.get("callId") or item.get("contactId") or item.get("eventId")
    risk_level = item.get("riskLevel") or item.get("status") or "LOW"
    action = item.get("action")
    if not action:
        action = "alert_sent" if item.get("shouldAlert") else "none"
    return {
        **item,
        "eventId": call_id,
        "callId": call_id,
        "timestamp": item.get("timestamp") or item.get("createdAt") or item.get("startedAt"),
        "riskLevel": str(risk_level).lower(),
        "action": action,
        "guardianNotified": bool(item.get("guardianNotified") or (item.get("smsResult", {}).get("sentCount", 0) > 0)),
    }

# Feature 2: Personal Dashboard
# Return the logged-in user, active guardians, and recent events for the dashboard.
def handle_get_me(event):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err

    user = ensure_user(user_id, email)
    user["guardians"] = refreshed_guardians_for_user(user_id)
    user["recentEvents"] = [normalize_event(e) for e in call_records_for_user(user_id, limit=5)]

    return response(200, {"user": user})

# Feature 3: Monitoring Control
# Feature 4: SilentGuard Protection Number
# Feature 11: User Settings
# Update user profile, monitoring status, and protection number.
def handle_update_me(event):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err
    body = parse_body(event)

    allowed = ["name", "phone", "monitoringEnabled", "connectNumber"]
    update_parts = ["updatedAt = :updatedAt", "email = :email"]
    names = {}
    values = {":updatedAt": now_iso(), ":email": email or body.get("email", "")}

    for key in allowed:
        if key in body:
            placeholder_name = f"#{key}"
            placeholder_value = f":{key}"
            update_parts.append(f"{placeholder_name} = {placeholder_value}")
            names[placeholder_name] = key
            values[placeholder_value] = body[key]

    users_table.update_item(
        Key={"userId": user_id},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=names or None,
        ExpressionAttributeValues=values,
    )
    user = ensure_user(user_id, email)
    user["guardians"] = refreshed_guardians_for_user(user_id)
    return response(200, {"user": user})

# Feature 8: Guardian Management
# Return all active guardians for the logged-in user.
def handle_get_guardians(event):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err

    return response(200, {
        "guardians": refreshed_guardians_for_user(user_id)
    })

# Feature 8: Guardian Management
# Add a new active guardian for the logged-in user.
def handle_create_guardian(event):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err

    body = parse_body(event)

    guardian_name = body.get("guardianName") or body.get("name")
    guardian_phone = validate_guardian_phone(body.get("guardianPhone") or body.get("phone"))
    guardian_email = validate_guardian_email(body.get("guardianEmail") or body.get("email") or "")
    relationship = body.get("relationship") or "Family member"

    if not guardian_name:
        return response(400, {"message": "guardianName/name is required"})

    timestamp = now_iso()

    email_status = "none"
    email_error = ""

    if guardian_email:
        email_status, email_error = request_ses_email_verification(guardian_email)

    email_verified = email_status == "verified"

    item = {
        "guardianId": str(uuid.uuid4()),
        "userId": user_id,
        "userEmail": email or "",

        "guardianName": guardian_name,
        "name": guardian_name,

        "guardianPhone": guardian_phone,
        "phone": guardian_phone,

        "guardianEmail": guardian_email,
        "email": guardian_email,

        "relationship": relationship,
        "status": "active",

        "guardianEmailStatus": email_status,
        "emailVerified": email_verified,
        "emailNotificationEnabled": email_verified,
        "emailVerificationRequestedAt": timestamp if guardian_email else "",
        "lastEmailError": email_error,

        "createdAt": timestamp,
        "updatedAt": timestamp,
    }

    guardians_table.put_item(Item=item)

    message = "Guardian added."

    if guardian_email and email_status == "pending":
        message = "Guardian added. Verification email was sent. The guardian must click the verification link before email alerts can be sent."

    if guardian_email and email_status == "verified":
        message = "Guardian added. Email is already verified and ready for alerts."

    if guardian_email and email_status == "failed":
        message = "Guardian added, but email verification request failed. SMS alerts can still work."

    return response(201, {
        "guardian": item,
        "message": message
    })
def get_guardian_for_request(event, guardian_id):
    user_id, email, claims, err = require_auth(event)
    if err:
        return None, None, None, err

    result = guardians_table.get_item(Key={"guardianId": guardian_id})
    guardian = result.get("Item")

    if not guardian:
        return None, None, None, response(404, {"message": "Guardian not found"})

    if guardian.get("userId") != user_id and not is_admin_claims(claims):
        return None, None, None, response(403, {"message": "Cannot access another user's guardian"})

    return user_id, claims, guardian, None


def handle_request_guardian_email_verification(event, guardian_id):
    user_id, claims, guardian, err = get_guardian_for_request(event, guardian_id)
    if err:
        return err

    email = validate_guardian_email(
        guardian.get("guardianEmail") or guardian.get("email") or ""
    )

    if not email:
        return response(400, {"message": "Guardian has no email address"})

    status, error_message = request_ses_email_verification(email)
    email_verified = status == "verified"
    timestamp = now_iso()

    guardians_table.update_item(
        Key={"guardianId": guardian_id},
        UpdateExpression="""
            SET guardianEmailStatus = :status,
                emailVerified = :verified,
                emailNotificationEnabled = :enabled,
                emailVerificationRequestedAt = :requestedAt,
                lastEmailError = :error,
                updatedAt = :updatedAt
        """,
        ExpressionAttributeValues={
            ":status": status,
            ":verified": email_verified,
            ":enabled": email_verified,
            ":requestedAt": timestamp,
            ":error": error_message,
            ":updatedAt": timestamp,
        },
    )

    guardian["guardianEmailStatus"] = status
    guardian["emailVerified"] = email_verified
    guardian["emailNotificationEnabled"] = email_verified
    guardian["lastEmailError"] = error_message

    return response(200, {
        "guardian": guardian,
        "message": "Verification email requested" if status == "pending" else f"Email status: {status}"
    })


def handle_check_guardian_email_verification(event, guardian_id):
    user_id, claims, guardian, err = get_guardian_for_request(event, guardian_id)
    if err:
        return err

    guardian = refresh_guardian_email_status(guardian)

    return response(200, {
        "guardian": guardian,
        "emailStatus": guardian.get("guardianEmailStatus")
    })

# Feature 8: Guardian Management
# Soft-delete a guardian by changing its status to deleted.
def handle_delete_guardian(event, guardian_id):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err

    result = guardians_table.get_item(Key={"guardianId": guardian_id})
    item = result.get("Item")
    if not item:
        return response(404, {"message": "Guardian not found"})

    if item.get("userId") != user_id and not is_admin_claims(claims):
        return response(403, {"message": "Cannot delete another user's guardian"})

    guardians_table.update_item(
        Key={"guardianId": guardian_id},
        UpdateExpression="SET #status = :status, updatedAt = :updatedAt",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":status": "deleted", ":updatedAt": now_iso()},
    )
    return response(200, {"message": "Guardian deleted", "guardianId": guardian_id})

# Feature 10: Call History
# Return previous analyzed calls and risk events for the logged-in user.
def handle_get_events(event):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err
    params = event.get("queryStringParameters") or {}
    limit = int(params.get("limit") or 20)
    risk_level = params.get("riskLevel")
    events = [normalize_event(e) for e in call_records_for_user(user_id, limit=limit, risk_level=risk_level)]
    return response(200, {"events": events})

# Feature 10: Call History
# Return one saved call/risk event, only if it belongs to the logged-in user.
def handle_get_event(event, event_id):
    user_id, email, claims, err = require_auth(event)
    if err:
        return err

    result = call_records_table.get_item(Key={"callId": event_id})
    item = result.get("Item")
    if not item:
        return response(404, {"message": "Event not found"})

    if item.get("userId") != user_id and not is_admin_claims(claims):
        return response(403, {"message": "Cannot view another user's event"})

    return response(200, {"event": normalize_event(item)})

# Feature 1: User Authentication
# Admin-only statistics endpoint.
def handle_admin_stats(event):
    admin_id, email, claims, err = require_admin(event)
    if err:
        return err
    users = scan_all(users_table)
    events = all_call_records(limit=1000)
    today = datetime.now(timezone.utc).date().isoformat()
    today_events = [e for e in events if str(e.get("createdAt") or e.get("timestamp") or "").startswith(today)]
    return response(200, {
        "totalUsers": len(users),
        "activeMonitoring": sum(1 for u in users if u.get("monitoringEnabled", True)),
        "eventsToday": len(today_events),
        "highRiskToday": sum(1 for e in today_events if str(e.get("riskLevel", "")).upper() == "HIGH"),
        "disconnectedToday": sum(1 for e in today_events if e.get("action") == "disconnected"),
    })


# Feature 10: Call History
# Admin-only endpoint for reviewing stored risk/call events.
def handle_admin_events(event):
    admin_id, email, claims, err = require_admin(event)
    if err:
        return err
    params = event.get("queryStringParameters") or {}
    try:
        limit = int(params.get("limit") or 50)
    except ValueError:
        limit = 50
    risk_level = params.get("riskLevel")
    date = params.get("date")

    items = all_call_records(limit=500)
    if risk_level:
        items = [e for e in items if str(e.get("riskLevel", "")).lower() == str(risk_level).lower()]
    if date:
        items = [e for e in items if str(e.get("createdAt") or e.get("timestamp") or "").startswith(date)]

    # Add user email where possible so the admin dashboard can show which account each event belongs to.
    enriched = []
    user_cache = {}
    for item in items[:limit]:
        event = normalize_event(item)
        uid = event.get("userId")
        if uid and uid not in user_cache:
            user_cache[uid] = get_user_item(uid) or {}
        if uid:
            event["userEmail"] = (user_cache.get(uid) or {}).get("email") or event.get("userEmail") or ""
        enriched.append(event)

    return response(200, {"events": enriched})

# Feature 1: User Authentication
# Admin-only endpoint for listing users.
def handle_admin_users(event):
    admin_id, email, claims, err = require_admin(event)
    if err:
        return err
    users = [normalize_user(u) for u in scan_all(users_table)]
    users.sort(key=lambda u: u.get("createdAt", ""), reverse=True)
    return response(200, {"users": users})

# Feature 2: Personal Dashboard
# Admin-only endpoint for viewing a specific user dashboard summary.
def handle_admin_user(event, target_user_id):
    admin_id, email, claims, err = require_admin(event)
    if err:
        return err
    user = get_user_item(target_user_id)
    if not user:
        return response(404, {"message": "User not found"})
    user = normalize_user(user)
    user["guardians"] = guardians_for_user(target_user_id)
    user["recentEvents"] = [normalize_event(e) for e in call_records_for_user(target_user_id, limit=10)]
    return response(200, {"user": user})

# Feature 3: Monitoring Control
# Feature 11: User Settings
# Admin-only endpoint for updating user profile/protection settings.
def handle_admin_update_user(event, target_user_id):
    admin_id, email, claims, err = require_admin(event)
    if err:
        return err
    body = parse_body(event)
    allowed = ["name", "phone", "monitoringEnabled", "connectNumber", "role", "status"]
    update_parts = ["updatedAt = :updatedAt"]
    names = {}
    values = {":updatedAt": now_iso()}
    for key in allowed:
        if key in body:
            names[f"#{key}"] = key
            values[f":{key}"] = body[key]
            update_parts.append(f"#{key} = :{key}")
    users_table.update_item(
        Key={"userId": target_user_id},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeNames=names or None,
        ExpressionAttributeValues=values,
    )
    return handle_admin_user(event, target_user_id)

# Feature 11: User Settings
# Return global protection settings for the admin settings page.
def handle_get_settings(event):
    _, _, _, err = require_admin(event)
    if err:
        return err
    try:
        result = settings_table.get_item(Key={"settingId": "global"})
        return response(200, result.get("Item") or DEFAULT_SETTINGS)
    except ClientError as exc:
        print("Settings table read failed, returning defaults:", str(exc))
        return response(200, DEFAULT_SETTINGS)

# Feature 11: User Settings
# Update global protection settings used by the system.
def handle_update_settings(event):
    _, _, _, err = require_admin(event)
    if err:
        return err
    body = parse_body(event)
    item = {
        **DEFAULT_SETTINGS,
        **body,
        "settingId": "global",
        "updatedAt": now_iso(),
    }
    settings_table.put_item(Item=item)
    return response(200, item)

# Main API Router
# Routes API Gateway requests to the relevant feature handler.
def lambda_handler(event, context):
    method = route_method(event)
    path = route_path(event).rstrip("/") or "/"
    print(json.dumps({"method": method, "path": path, "requestId": getattr(context, "aws_request_id", None)}))

    if method == "OPTIONS":
        return response(200, {"ok": True})

    try:
        # Backward compatible old route
        if path == "/me" and method == "GET":
            result = handle_get_me(event)
            body = json.loads(result["body"])
            return response(200, {"exists": True, "user": body.get("user")})
        if path == "/me" and method == "POST":
            return handle_update_me(event)

        # React app routes
        if path == "/users/me" and method == "GET":
            return handle_get_me(event)
        if path == "/users/me" and method == "PUT":
            return handle_update_me(event)

        if path == "/guardians" and method == "GET":
            return handle_get_guardians(event)
        if path == "/guardians" and method == "POST":
            return handle_create_guardian(event)

        if path.startswith("/guardians/") and path.endswith("/email-verification"):
            guardian_id = path.strip("/").split("/")[1]

            if method == "POST":
                return handle_request_guardian_email_verification(event, guardian_id)

            if method == "GET":
                return handle_check_guardian_email_verification(event, guardian_id)
                
        if path.startswith("/guardians/") and method == "DELETE":
            return handle_delete_guardian(event, path.split("/")[-1])

        if path == "/events" and method == "GET":
            return handle_get_events(event)
        if path.startswith("/events/") and method == "GET":
            return handle_get_event(event, path.split("/")[-1])

        if path == "/admin/stats" and method == "GET":
            return handle_admin_stats(event)
        if path == "/admin/events" and method == "GET":
            return handle_admin_events(event)
        if path == "/admin/users" and method == "GET":
            return handle_admin_users(event)
        if path.startswith("/admin/users/") and method == "GET":
            return handle_admin_user(event, path.split("/")[-1])
        if path.startswith("/admin/users/") and method == "PUT":
            return handle_admin_update_user(event, path.split("/")[-1])

        if path == "/settings" and method == "GET":
            return handle_get_settings(event)
        if path == "/settings" and method == "PUT":
            return handle_update_settings(event)

        return response(404, {"message": f"No route for {method} {path}"})
    except ValueError as exc:
        return response(400, {"message": str(exc)})
    except Exception as exc:
        print("Unhandled error:", repr(exc))
        return response(500, {"message": "Internal server error", "error": str(exc)})

# Lambda console default handler wrapper if the handler is set to lambda_function.lambda_handler.
handler = lambda_handler
