# Kick Viewer

## Overview

Kick Viewer is a Python application designed to integrate with the Kick streaming platform's API. It handles authentication, webhook events (such as chat messages, follows, and subscriptions), and provides a simple browser-based interface to display live chat messages with username colors. The app uses Flask for the web server and supports OAuth2 authentication with PKCE for secure access.

This tool is useful for developers building bots, monitoring tools, or custom overlays for Kick streams.

## Features

- **OAuth Authentication**: Supports authorization code flow with PKCE and token refresh for secure API access.
- **Webhook Handling**: Validates and processes Kick webhooks for events like chat messages, new follows, subscriptions, renewals, and gifts.
- **Chat Message Sending**: Send messages to channels as a user or bot.
- **Live Chat Display**: A browser endpoint (`/browser`) that polls for new messages and displays them with colored usernames.
- **Event Subscription Management**: Automatically subscribes to required Kick events if not already subscribed.
- **Credential Management**: Stores client ID, secret, and refresh token in a JSON file for persistent sessions.

## Requirements

- Python 3.8+
- Required libraries (install via `pip`):
  - `flask`
  - `cryptography`
  - `urllib3` (usually included in standard library, but ensure it's up-to-date)

Install dependencies:
```
pip install flask cryptography
```

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/kick-viewer.git
   cd kick-viewer
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```
   (Create a `requirements.txt` file with `flask` and `cryptography` if not present.)

3. Run the script:
   ```
   python kick_api_integration.py
   ```

## Usage

1. **Initial Setup**:
   - Run the script. It will prompt for your Kick Client ID and Client Secret if not already stored in `kick_credentials.json`.
   - The app will open a browser for OAuth authorization. Grant access and it will handle token retrieval.

2. **Webhook Configuration**:
   - Configure your Kick developer dashboard to send webhooks to `http://your-server:5000/webhook`.
   - The app validates signatures using Kick's public key.

3. **Viewing Chat**:
   - Open `http://localhost:5000/browser` in your browser to see live chat messages.
   - Messages are polled every second and displayed with username colors.

4. **Sending Messages**:
   - Use the `send_chat_message` function in your code extensions to send messages.
   - Example: `send_chat_message(access_token, broadcaster_user_id, "Hello!", "user")`

5. **Event Handling**:
   - The app prints incoming events to the console.
   - Extend the `webhook` route to add custom logic for events.

## Configuration

- **Credentials**: Stored in `kick_credentials.json`. Delete this file to re-enter credentials.
- **Scopes**: Defaults to `"user:read channel:read chat:write events:subscribe"`. Modify in the `main` function if needed.
- **Redirect URI**: Set to `http://localhost:5000/callback`. Update if hosting elsewhere.
- **Message Limit**: Keeps the last 100 chat messages in memory. Adjust in the `webhook` route.

## Troubleshooting

- **Authorization Issues**: Ensure your Client ID and Secret are correct. Check console for HTTP errors.
- **Webhook Validation Fails**: Verify the public key fetch and signature verification logic.
- **No Events Received**: Confirm subscriptions in the Kick dashboard and that webhooks are pointed to the correct endpoint.

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests. For major changes, open an issue first to discuss.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Last updated: August 13, 2025*
