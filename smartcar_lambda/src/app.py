import os
import boto3
import requests
import base64
import time
from botocore.exceptions import ClientError

# Constants
SMARTCAR_API_BASE_URL = os.environ.get("SMARTCAR_API_BASE_URL")
PARAMETER_STORE_PREFIX = os.environ.get("PARAMETER_STORE_PREFIX")

# AWS Clients
ssm_client = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')
battery_table = dynamodb.Table('BatteryLevelData')

def get_parameter(name):
    try:
        response = ssm_client.get_parameter(Name=name, WithDecryption=True)
        print(f"Fetched parameter {name}: {response['Parameter']['Value']}")
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Error fetching parameter {name}: {e}")
        return None

def set_parameter(name, value):
    try:
        print(f"Setting parameter {name} to {value}")
        ssm_client.put_parameter(Name=name, Value=value, Type='SecureString', Overwrite=True)
    except ClientError as e:
        print(f"Error setting parameter {name}: {e}")

def refresh_access_token():
    refresh_token = get_parameter(f"{PARAMETER_STORE_PREFIX}refresh_token")
    print(f"Using refresh token: {refresh_token}")
    if not refresh_token:
        raise ValueError("Refresh token not found in Parameter Store.")

    client_id = get_parameter(f"{PARAMETER_STORE_PREFIX}client_id")
    print(f"Using client ID: {client_id}")
    client_secret = get_parameter(f"{PARAMETER_STORE_PREFIX}client_secret")
    print
    auth_header = f"Basic {base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()}"
    print(f"Using auth header: {auth_header}")

    response = requests.post(
        os.environ.get("SMARTCAR_AUTH_URL"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": auth_header
        },
        data={
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "redirect_uri": "http://localhost:8000/callback"
        }
    )

    if response.status_code == 200:
        tokens = response.json()
        print(tokens)
        set_parameter(f"{PARAMETER_STORE_PREFIX}access_token", tokens['access_token'])
        set_parameter(f"{PARAMETER_STORE_PREFIX}refresh_token", tokens['refresh_token'])
    else:
        print(f"Failed to refresh access token: {response.text}")
        response.raise_for_status()

def construct_endpoint(endpoint):
    VEHICLE_ID = get_parameter(f"{PARAMETER_STORE_PREFIX}vehicle_id")
    return f"{SMARTCAR_API_BASE_URL}/{VEHICLE_ID}/{endpoint}"

def store_battery_level(battery_level):
    from datetime import datetime
    timestamp = datetime.utcnow().isoformat()
    try:
        battery_table.put_item(
            Item={
                'timestamp': timestamp,
                'battery_level': battery_level
            }
        )
        print(f"Stored battery level {battery_level}% at {timestamp}")
    except ClientError as e:
        print(f"Error storing battery level: {e}")

def get_battery_level():
    access_token = get_parameter(f"{PARAMETER_STORE_PREFIX}access_token")
    if not access_token:
        refresh_access_token()
        access_token = get_parameter(f"{PARAMETER_STORE_PREFIX}access_token")

    headers = {"Authorization": f"Bearer {access_token}"}
    endpoint = construct_endpoint("battery")
    print(f"Fetching battery level from {endpoint} with headers: {headers}")

    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        battery_data = response.json()
        print(f"Battery level response: {battery_data}")
        # Store battery level in DynamoDB
        store_battery_level(int(battery_data['percentRemaining'] * 100))
        return battery_data
    elif response.status_code == 401:  # Token expired
        print("Access token expired, refreshing...")
        refresh_access_token()
        return get_battery_level()
    elif response.status_code == 429:  # Rate limit exceeded
        retry_after = int(response.headers.get("retry-after", 1)) + 5  # Add 5 seconds buffer
        print(f"Rate limit exceeded. Retrying after {retry_after} seconds...")
        time.sleep(retry_after)
        return get_battery_level()
    else:
        print(f"Failed to fetch battery level: {response.text}")
        response.raise_for_status()

def lambda_handler(event, context):
    if event.get("action") == "get_battery_level":
        return get_battery_level()
    else:
        return {"message": "Unsupported action."}