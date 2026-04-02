"""
Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
WSO2 LLC. licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
"""

"""
On-Behalf-Of (OBO) token flow using CIBA.

This example shows how an AI agent can obtain tokens on behalf of a user
using CIBA. The agent initiates a backchannel authentication request for
the user, and the user authenticates on a separate device (via email, SMS,
or an external link).
"""

import asyncio
import itertools
import sys

from asgardeo import AsgardeoConfig, CIBAResponse
from asgardeo_ai import AgentAuthManager, AgentConfig


async def _spinner(message: str, stop_event: asyncio.Event) -> None:
    """Display a spinning animation until stop_event is set."""
    frames = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
    while not stop_event.is_set():
        sys.stdout.write(f"\r{next(frames)} {message}")
        sys.stdout.flush()
        await asyncio.sleep(0.1)
    sys.stdout.write(f"\r{' ' * (len(message) + 2)}\r")
    sys.stdout.flush()


async def main():
    """On-Behalf-Of (OBO) CIBA flow example."""

    # Asgardeo configuration - Replace with your actual values
    config = AsgardeoConfig(
        base_url="https://api.asgardeo.io/t/<tenant>",
        client_id="<client_id>",
        redirect_uri="<redirect_uri>",
        client_secret="<client_secret>",
    )

    # AI Agent configuration - Replace with your actual agent credentials
    agent_config = AgentConfig(
        agent_id="<agent_id>",
        agent_secret="<agent_secret>"
    )

    try:
        async with AgentAuthManager(config, agent_config) as auth_manager:
            print("Starting On-Behalf-Of (OBO) CIBA flow...")

            # Step 1: Get agent token
            print("\nStep 1: Getting agent token...")
            agent_scopes = ["openid", "profile"]
            agent_token = await auth_manager.get_agent_token(agent_scopes)
            print(f"Agent authenticated: {agent_token.access_token[:20]}...")

            # Step 2: Get OBO token via CIBA
            print("\nStep 2: Initiating CIBA request for user...")
            user_scopes = ["openid", "profile", "email"]

            stop_spinner = asyncio.Event()
            spinner_task = None

            def on_ciba_initiated(ciba_response: CIBAResponse) -> None:
                nonlocal spinner_task
                print(f"\nCIBA request accepted. auth_req_id: {ciba_response.auth_req_id}")

                if ciba_response.auth_url:
                    print(f"Open this URL to authenticate: {ciba_response.auth_url}")
                else:
                    print("Notification sent! Check your email/SMS inbox to approve the request.")

                print(f"(expires in {ciba_response.expires_in}s)\n")

                spinner_task = asyncio.ensure_future(
                    _spinner("Waiting for user to complete authentication...", stop_spinner)
                )

            try:
                _, user_token = await auth_manager.get_obo_token_with_ciba(
                    login_hint="<username>",  # Replace with actual username
                    agent_token=agent_token,
                    scopes=user_scopes,
                    binding_message="AI Agent requests access to your account",
                    on_initiated=on_ciba_initiated,
                )
            finally:
                stop_spinner.set()
                if spinner_task:
                    await spinner_task

            print("OBO token obtained successfully!")
            print(f"User Access Token: {user_token.access_token[:30]}...")
            if user_token.id_token:
                print(f"User ID Token:     {user_token.id_token[:30]}...")
            if user_token.refresh_token:
                print(f"Refresh Token:     {user_token.refresh_token[:30]}...")
            print(f"Expires in:        {user_token.expires_in}s")
            print(f"Scope:             {user_token.scope}")
            print("\nThe AI agent can now act on behalf of the user.")

    except Exception as e:
        print(f"\nCIBA OBO flow failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("Asgardeo AI On-Behalf-Of (OBO) CIBA Flow Example")
    print("=" * 55)
    asyncio.run(main())
