import urllib.request
import urllib.parse
import json
import base64
import hashlib
import secrets
import webbrowser
import threading
import sys
import os
import time
from datetime import datetime
from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import logging

def fetch_public_key():
    url = "https://api.kick.com/public/v1/public-key"
    req = urllib.request.Request(url, method='GET')
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data['data']['public_key']
    except urllib.error.HTTPError as e:
        print("Failed to fetch public key:", e.code, e.reason)
        print(e.read().decode('utf-8'))
        sys.exit(1)

PUBLIC_KEY = fetch_public_key()
kick_public_key = serialization.load_pem_public_key(PUBLIC_KEY.encode('utf-8'))

def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)  # 86 chars, within 43-128
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('ascii')).digest()
    ).decode('ascii').rstrip('=')
    return code_verifier, code_challenge

def load_credentials(file_path='kick_credentials.json'):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            creds = json.load(f)
            return creds.get('client_id'), creds.get('client_secret'), creds.get('refresh_token')
    return None, None, None

def save_credentials(client_id, client_secret, refresh_token=None, file_path='kick_credentials.json'):
    creds = {'client_id': client_id, 'client_secret': client_secret}
    if refresh_token:
        creds['refresh_token'] = refresh_token
    with open(file_path, 'w') as f:
        json.dump(creds, f)

def send_chat_message(access_token, broadcaster_user_id, content, msg_type):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chat_url = "https://api.kick.com/public/v1/chat"
    if msg_type == "user":
        body = json.dumps({
            "broadcaster_user_id": broadcaster_user_id,
            "content": content,
            "type": "user"
        })
    elif msg_type == "bot":
        body = json.dumps({
            "content": content,
            "type": "bot"
        })
    else:
        raise ValueError("Invalid message type. Must be 'user' or 'bot'.")

    req = urllib.request.Request(chat_url, data=body.encode('utf-8'), method='POST')
    req.add_header('Authorization', f'Bearer {access_token}')
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req) as response:
            print(f"Time: {current_time} - Sent: Yes")
            print(f"Message (as {msg_type}): {content}")
    except urllib.error.HTTPError as e:
        print(f"Time: {current_time} - Sent: No")
        print(f"Message (as {msg_type}): {content}")
        print(f"{msg_type.capitalize()} Message Send Error:", e.code, e.reason)
        print(e.read().decode('utf-8'))

def validate_webhook_signature(headers, body):
    message_id = headers.get('Kick-Event-Message-Id')
    timestamp = headers.get('Kick-Event-Message-Timestamp')
    signature_b64 = headers.get('Kick-Event-Signature')

    if not message_id or not timestamp or not signature_b64:
        return False, "Missing required headers"

    concatenated = f"{message_id}.{timestamp}.{body.decode('utf-8')}"

    try:
        signature = base64.b64decode(signature_b64)
        kick_public_key.verify(
            signature,
            concatenated.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True, None
    except Exception as e:
        print(f"Validation error: {e}")
        return False, f"Invalid signature: {str(e)}"

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/webhook', methods=['POST'])
def webhook():
    body = request.data
    headers = request.headers
    valid, reason = validate_webhook_signature(headers, body)
    if valid:
        event_type = headers.get('Kick-Event-Type')
        data = json.loads(body)
        if event_type == 'chat.message.sent':
            print(f"{event_type} - {data.get('created_at')} - {data.get('sender', {}).get('username')}:")
            print(data.get('content'))
            messages.append({
                'created_at': data.get('created_at'),
                'username': data.get('sender', {}).get('username'),
                'content': data.get('content'),
                'color': data.get('sender', {}).get('identity', {}).get('color')
            })
            if len(messages) > 100:
                messages.pop(0)
        elif event_type == 'channel.followed':
            print(f"{event_type} - {data.get('follower', {}).get('username')}")
        elif event_type == 'channel.subscription.new':
            print(f"{event_type} - {data.get('subscriber', {}).get('username')} - {data.get('duration')}")
        elif event_type == 'channel.subscription.renewal':
            print(f"{event_type} - {data.get('subscriber', {}).get('username')} - {data.get('duration')}")
        elif event_type == 'channel.subscription.gifts':
            print(f"{event_type} - {data.get('gifter', {}).get('username')} - {len(data.get('giftees', []))}")
        return '', 200
    else:
        print(f"Webhook validation failed: {reason}")
        return '', 401

messages = []

@app.route('/get_messages', methods=['GET'])
def get_messages():
    return json.dumps(messages)

@app.route('/browser', methods=['GET'])
def browser():
    html = '''
    <html>
    <body style="color: white;">
    <div id="chat"></div>
    <script>
    function updateChat() {
        fetch('/get_messages')
            .then(response => response.json())
            .then(data => {
                let chatDiv = document.getElementById('chat');
                let html = '';
                for (let i = data.length - 1; i >= 0; i--) {
                    let msg = data[i];
                    let color = msg.color || '#FFFFFF';
                    html += `<p><span style="color: ${color};">${msg.username}</span>: ${msg.content}</p>`;
                }
                chatDiv.innerHTML = html;
            });
    }
    setInterval(updateChat, 1000);
    updateChat(); // initial call
    </script>
    </body>
    </html>
    '''
    return html

def main():
    client_id, client_secret, stored_refresh_token = load_credentials()
    if not client_id or not client_secret:
        client_id = input("Enter your Kick client ID: ").strip()
        client_secret = input("Enter your Kick client secret: ").strip()
        save_credentials(client_id, client_secret)

    scopes = "user:read channel:read chat:write events:subscribe"

    redirect_uri = "http://localhost:5000/callback"
    authorize_url_base = "https://id.kick.com/oauth/authorize"
    token_url = "https://id.kick.com/oauth/token"

    access_token = None
    refresh_token = stored_refresh_token
    expires_in = None
    scope = None

    server_started = False
    code_received = [None]
    server_shutdown = threading.Event()
    state = secrets.token_urlsafe(16)
    expected_state = state

    def run_server():
        app.run(host='localhost', port=5000, debug=False, use_reloader=False)

    if refresh_token:
        token_params = {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token
        }
        data = urllib.parse.urlencode(token_params).encode('ascii')
        req = urllib.request.Request(token_url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')

        try:
            with urllib.request.urlopen(req) as response:
                token_response = json.loads(response.read().decode('utf-8'))
                access_token = token_response.get('access_token')
                new_refresh_token = token_response.get('refresh_token')
                if new_refresh_token:
                    refresh_token = new_refresh_token
                save_credentials(client_id, client_secret, refresh_token)
                expires_in = token_response.get('expires_in')
                scope = token_response.get('scope')
                print("Refreshed Access Token:", access_token)
                print("Refresh Token:", refresh_token)
                print("Expires In:", expires_in)
                print("Scope:", scope)
        except urllib.error.HTTPError as e:
            print("Refresh failed:", e.code, e.reason)
            print(e.read().decode('utf-8'))
            access_token = None

    if not access_token:
        @app.route('/callback')
        def callback_route():
            code = request.args.get('code')
            received_state = request.args.get('state')

            if received_state != expected_state:
                return 'Invalid state', 400

            if code:
                code_received[0] = code
                server_shutdown.set()
                return 'Authorization successful. You can close this window.'
            else:
                return 'No code provided', 400

        code_verifier, code_challenge = generate_pkce()

        auth_params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scopes,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'state': state
        }
        authorize_url = authorize_url_base + '?' + urllib.parse.urlencode(auth_params)

        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        server_started = True

        print("Opening browser for authorization...")
        webbrowser.open(authorize_url)

        server_shutdown.wait()  

        if not code_received[0]:
            print("Failed to receive authorization code.")
            sys.exit(1)

        code = code_received[0]

        token_params = {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'code_verifier': code_verifier,
            'code': code
        }
        data = urllib.parse.urlencode(token_params).encode('ascii')
        req = urllib.request.Request(token_url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')

        try:
            with urllib.request.urlopen(req) as response:
                token_response = json.loads(response.read().decode('utf-8'))
                access_token = token_response.get('access_token')
                refresh_token = token_response.get('refresh_token')
                save_credentials(client_id, client_secret, refresh_token)
                print("Access Token:", access_token)
                print("Refresh Token:", refresh_token)
                print("Expires In:", token_response.get('expires_in'))
                print("Scope:", token_response.get('scope'))
        except urllib.error.HTTPError as e:
            print("Error:", e.code, e.reason)
            print(e.read().decode('utf-8'))
            sys.exit(1)

    if access_token and not server_started:
        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        server_started = True

    channels_info = []
    if access_token:
        api_url = "https://api.kick.com/public/v1/channels"
        req = urllib.request.Request(api_url, method='GET')
        req.add_header('Authorization', f'Bearer {access_token}')
        try:
            with urllib.request.urlopen(req) as response:
                api_response = json.loads(response.read().decode('utf-8'))
                if 'data' in api_response:
                    for channel in api_response['data']:
                        broadcaster_user_id = channel.get('broadcaster_user_id')
                        slug = channel.get('slug')
                        if broadcaster_user_id is not None and slug is not None:
                            print(f"Broadcaster User ID: {broadcaster_user_id}, Slug: {slug}")
                            channels_info.append({
                                'broadcaster_user_id': broadcaster_user_id,
                                'slug': slug
                            })
                else:
                    print("No 'data' key in API response.")
        except urllib.error.HTTPError as e:
            print("API Error:", e.code, e.reason)
            print(e.read().decode('utf-8'))

    if access_token:
        events_url = "https://api.kick.com/public/v1/events/subscriptions"
        req = urllib.request.Request(events_url, method='GET')
        req.add_header('Authorization', f'Bearer {access_token}')
        try:
            with urllib.request.urlopen(req) as response:
                events_response = json.loads(response.read().decode('utf-8'))
                subscribed_events = [sub['event'] for sub in events_response.get('data', [])]
                print("Currently subscribed events:", ", ".join(subscribed_events))

                required_events = ['chat.message.sent', 'channel.subscription.renewal', 'channel.subscription.new', 'channel.subscription.gifts', 'channel.followed']
                missing_events = [event for event in required_events if event not in subscribed_events]
                if missing_events:
                    for event in missing_events:
                        sub_body = json.dumps({"event": event})
                        sub_req = urllib.request.Request(events_url, data=sub_body.encode('utf-8'), method='POST')
                        sub_req.add_header('Authorization', f'Bearer {access_token}')
                        sub_req.add_header('Content-Type', 'application/json')
                        try:
                            with urllib.request.urlopen(sub_req) as sub_response:
                                print(f"Subscribed to {event}")
                        except urllib.error.HTTPError as sub_e:
                            print(f"Subscription Error for {event}:", sub_e.code, sub_e.reason)
                            print(sub_e.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            print("Events Subscriptions API Error:", e.code, e.reason)
            print(e.read().decode('utf-8'))

    print("Listening for webhooks...")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
