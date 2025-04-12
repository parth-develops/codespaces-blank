# hubspot.py

from dotenv import load_dotenv
import os
from datetime import datetime
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import hashlib

import requests
from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

load_dotenv()

CLIENT_ID = os.getenv('HUBSPOT_CLIENT_ID')
CLIENT_SECRET = os.getenv('HUBSPOT_CLIENT_SECRET')
REDIRECT_URI = os.getenv('HUBSPOT_REDIRECT_URI')

authorization_url = f'https://app-na2.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}'
encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()
scope = 'crm.objects.contacts.read crm.objects.contacts.write oauth'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    print(f"CLIENT_ID: {CLIENT_ID}")
    print(f"CLIENT_SECRET: {CLIENT_SECRET}")

    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')

    auth_url = f'{authorization_url}&state={encoded_state}&code_challenge={code_challenge}&code_challenge_method=S256&scope={scope}'
    
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )

    return auth_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'code_verifier': code_verifier.decode('utf-8'),
                },
                headers={
                    'Authorization': f'Basic {encoded_client_id_secret}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

async def create_integration_item_metadata_object(response_json):
    # TODO
    pass

async def get_items_hubspot(credentials: dict) -> list[IntegrationItem]:
    access_token = credentials.get("access_token")

    if not access_token:
        raise Exception("No access token found in credentials.")

    url = "https://api.hubapi.com/crm/v3/objects/contacts"
    params = {
        "limit": 25,
        "properties": "firstname,lastname,email,createdate,lastmodifieddate"
    }

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=params)
        response.raise_for_status()

    contacts = response.json().get("results", [])
    items = []

    for contact in contacts:
        props = contact.get("properties", {})
        name = f"{props.get('firstname', '')} {props.get('lastname', '')}".strip()
        created = props.get("createdate")
        modified = props.get("lastmodifieddate")

        item = IntegrationItem(
            id=contact.get("id"),
            type="hubspot_contact",
            name=name or props.get("email"),
            creation_time=datetime.fromisoformat(created[:-1]) if created else None,
            last_modified_time=datetime.fromisoformat(modified[:-1]) if modified else None,
            url=f"https://app.hubspot.com/contacts/{contact.get('id')}",
            visibility=True
        )

        items.append(item)

    return items