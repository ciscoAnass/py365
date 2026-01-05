from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from typing import Dict, List, Set, Union
import asyncio
import logging
import uuid
import json
from datetime import datetime

# Strictly necessary 3rd party libraries:
# - fastapi
# - uvicorn (for running the server, not directly imported in code but used to launch it)
# - websockets (dependency of fastapi for websockets, usually installed with fastapi)

# --- Logging Configuration ---
# Setting up comprehensive logging for the application. This helps in debugging,
# monitoring server activities, and understanding the flow of connections and messages.
# Logs are directed to both a file and the console for easy access and persistence.
logging.basicConfig(
    level=logging.INFO,  # Set the default logging level to INFO
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    handlers=[
        logging.FileHandler("chat_server.log", encoding="utf-8"),  # Log all messages to a file
        logging.StreamHandler()                                    # Display messages in the console
    ]
)
# Create a logger instance for this module.
logger = logging.getLogger(__name__)

# --- FastAPI Application Instance ---
# Initialize the FastAPI application.
# This object serves as the main entry point for defining HTTP routes and WebSocket endpoints.
app = FastAPI(
    title="Real-Time Chat API with WebSockets",
    description="A robust backend service using FastAPI-WebSockets that manages persistent "
                "WebSocket connections, allowing users to join 'rooms' and broadcast/receive "
                "JSON messages in real-time. Includes detailed logging and connection management.",
    version="1.0.0",
    docs_url="/docs",       # Expose Swagger UI documentation
    redoc_url="/redoc"      # Expose ReDoc documentation
)

# --- Connection Manager Class ---
# This class is the core component responsible for handling all active WebSocket connections.
# It manages connections grouped by rooms, enables broadcasting messages, and tracks connection states.
class ConnectionManager:
    def __init__(self):
        # A dictionary to store active WebSocket connections.
        # Structure: {room_id: {user_id: WebSocket_object}}
        # This allows quick lookup of connections based on room and user IDs.
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        logger.info("ConnectionManager initialized. Ready to manage all WebSocket connections across rooms.")

    async def connect(self, room_id: str, user_id: str, websocket: WebSocket):
        """
        Establishes a new WebSocket connection for a user in a specific room.
        It accepts the WebSocket, adds it to the appropriate room, and handles room creation if necessary.
        """
        try:
            # First, accept the WebSocket connection. This completes the WebSocket handshake.
            await websocket.accept()
            logger.info(f"WebSocket accepted for user '{user_id}' in room '{room_id}'.")

            # Check if the room already exists. If not, create a new entry for it.
            if room_id not in self.active_connections:
                self.active_connections[room_id] = {}
                logger.info(f"Room '{room_id}' created as it did not exist previously.")

            # Check if the user ID is already present in the room.
            # This can happen if a user reconnects, or if there's a unique ID conflict.
            if user_id in self.active_connections[room_id]:
                logger.warning(f"User '{user_id}' already has an active connection in room '{room_id}'. "
                               f"The old connection will be replaced by the new one.")
                # Optionally, send a message to the old connection before replacing it.
                try:
                    old_ws = self.active_connections[room_id][user_id]
                    await self.send_personal_message(
                        {"type": "info", "message": "You have reconnected. Your previous connection was terminated.", "timestamp": datetime.now().isoformat()},
                        old_ws
                    )
                    # Attempt to gracefully close the old connection.
                    await old_ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="New connection established.")
                    logger.info(f"Closed old connection for user '{user_id}' in room '{room_id}'.")
                except Exception as e:
                    logger.error(f"Failed to gracefully close old connection for '{user_id}' in '{room_id}': {e}")
            
            # Add the new WebSocket connection to the manager.
            self.active_connections[room_id][user_id] = websocket
            logger.info(f"User '{user_id}' successfully connected to room '{room_id}'. "
                        f"Current connections in room: {len(self.active_connections[room_id])}.")
            
            # Broadcast a system message to the entire room informing about the new user.
            await self.broadcast_message(
                room_id,
                {"type": "system", "sender": "server", "message": f"User '{user_id}' has joined the room."},
                exclude_user_id=None # The new user should also receive this message
            )

        except Exception as e:
            logger.error(f"Failed to establish connection for user '{user_id}' in room '{room_id}': {e}", exc_info=True)
            # Ensure the WebSocket is closed if an error occurs during acceptance.
            if not websocket.client_state.closed:
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Server error during connection setup.")

    async def disconnect(self, room_id: str, user_id: str):
        """
        Removes a WebSocket connection from the manager upon disconnection.
        Also cleans up empty rooms and broadcasts a departure message.
        """
        # Check if the room and user exist before attempting to remove.
        if room_id in self.active_connections and user_id in self.active_connections[room_id]:
            # Remove the connection from the room's dictionary.
            del self.active_connections[room_id][user_id]
            logger.info(f"User '{user_id}' disconnected from room '{room_id}'. "
                        f"Remaining connections: {len(self.active_connections[room_id])}.")
            
            # If the room becomes empty after disconnection, remove the room entry to clean up resources.
            if not self.active_connections[room_id]:
                del self.active_connections[room_id]
                logger.info(f"Room '{room_id}' is now empty and has been removed from active rooms.")

            # Broadcast a system message to inform others in the room that a user has left.
            await self.broadcast_message(
                room_id,
                {"type": "system", "sender": "server", "message": f"User '{user_id}' has left the room."},
                exclude_user_id=None # Everyone in the room should know
            )
        else:
            logger.warning(f"Attempted to disconnect non-existent user '{user_id}' from room '{room_id}'. "
                           f"This might indicate a race condition or incorrect state management.")

    async def send_personal_message(self, message: Union[str, dict], websocket: WebSocket):
        """
        Sends a JSON message to a single, specific WebSocket connection.
        This is useful for sending direct acknowledgements, error messages, or private data.
        """
        try:
            # FastAPI's WebSocket object has convenient `send_json` and `send_text` methods.
            if isinstance(message, dict):
                await websocket.send_json(message)
            else: # Fallback to text if not a dict, though JSON is preferred for chat.
                await websocket.send_text(str(message))
            logger.debug(f"Successfully sent personal message: {json.dumps(message)} to a client.")
        except RuntimeError as e:
            logger.warning(f"RuntimeError when sending personal message, likely client disconnected: {e}")
        except Exception as e:
            logger.error(f"Failed to send personal message to a client: {e}", exc_info=True)
            # In a real-world scenario, you might want to mark this connection as broken
            # and initiate a disconnect, but for a single send, FastAPI handles cleanup
            # on the next receive attempt.

    async def broadcast_message(self, room_id: str, message: dict, exclude_user_id: str = None):
        """
        Broadcasts a JSON message to all active connections within a specified room.
        An option `exclude_user_id` is provided to prevent sending the message back to the sender.
        Messages are timestamped before broadcasting.
        """
        if room_id not in self.active_connections or not self.active_connections[room_id]:
            logger.warning(f"Attempted to broadcast to non-existent or empty room '{room_id}'. No recipients.")
            return

        # Add a server-side timestamp to the message for consistency and record-keeping.
        message_with_timestamp = {**message, "timestamp": datetime.now().isoformat()}

        # Create a list of send tasks to be executed concurrently.
        # This is more efficient than awaiting each send sequentially.
        send_tasks = []
        # Iterate over a copy of the items to avoid "dictionary changed size during iteration" errors
        # if a disconnection occurs concurrently.
        current_room_connections = list(self.active_connections[room_id].items())
        
        for user_id, connection in current_room_connections:
            if user_id == exclude_user_id:
                # Skip sending the message to the user who sent it if `exclude_user_id` is specified.
                continue
            
            # Each send operation is wrapped in a safe helper function to handle individual errors.
            send_tasks.append(
                self._send_safe(connection, message_with_timestamp, room_id, user_id)
            )
        
        # Execute all send tasks concurrently. `return_exceptions=True` ensures that even if some
        # sends fail, others can complete, and we can inspect individual errors.
        results = await asyncio.gather(*send_tasks, return_exceptions=True)

        # Process the results of the concurrent send operations.
        # Note: `zip` works here because `current_room_connections` was created before `send_tasks`.
        for (user_id, _), result in zip(current_room_connections, results):
            if isinstance(result, Exception):
                logger.error(f"Failed to broadcast message to user '{user_id}' in room '{room_id}': {type(result).__name__} - {result}")
                # Depending on the error (e.g., persistent connection issues), one might
                # consider proactively disconnecting the user here, but often the WebSocketDisconnect
                # handler will catch this on the next receive attempt.
            else:
                logger.debug(f"Broadcasted message to user '{user_id}' in room '{room_id}'.")
        
        logger.info(f"Broadcast completed for room '{room_id}'. Message type: {message.get('type', 'N/A')}. "
                    f"Sent to {len(send_tasks)} recipients (excluding {exclude_user_id if exclude_user_id else 'none'}).")

    async def _send_safe(self, websocket: WebSocket, message: dict, room_id: str, user_id: str):
        """
        A private helper method to safely send a JSON message to a single WebSocket.
        It catches common exceptions that occur when a client disconnects unexpectedly.
        """
        try:
            await websocket.send_json(message)
            return True # Indicate success
        except RuntimeError as e:
            # This exception often occurs if the client has disconnected but the server hasn't
            # yet processed the WebSocketDisconnect event, or if the connection is already closing.
            logger.warning(f"RuntimeError when sending to user '{user_id}' in room '{room_id}', likely already disconnected: {e}")
            raise # Re-raise to be caught by asyncio.gather, allowing central error handling.
        except Exception as e:
            # Catch any other unexpected errors during the send operation.
            logger.error(f"Unexpected error when sending to user '{user_id}' in room '{room_id}': {e}", exc_info=True)
            raise # Re-raise for centralized handling.

    def get_room_occupants(self, room_id: str) -> List[str]:
        """Returns a list of user_ids currently connected to the specified room."""
        return list(self.active_connections.get(room_id, {}).keys())

    def get_active_rooms(self) -> List[str]:
        """Returns a list of all room_ids that currently have active connections."""
        return list(self.active_connections.keys())

    def get_total_connections_count(self) -> int:
        """Returns the total number of active WebSocket connections across all rooms."""
        return sum(len(room_connections) for room_connections in self.active_connections.values())

# Instantiate the Connection Manager as a global object.
# This ensures a single, centralized state for all WebSocket connections throughout the application.
manager = ConnectionManager()

# --- Utility Functions for Input Validation ---
# These functions enforce basic rules for room and user IDs to maintain data integrity
# and prevent common issues like empty or overly long identifiers.

def validate_room_id(room_id: str) -> bool:
    """
    Performs basic validation on a room ID.
    - Must not be empty.
    - Length between 3 and 50 characters.
    - Must be alphanumeric (contains only letters and numbers).
    """
    if not isinstance(room_id, str):
        logger.warning(f"Room ID '{room_id}' is not a string.")
        return False
    if not room_id.strip():
        logger.warning("Room ID cannot be empty or just whitespace.")
        return False
    if len(room_id) < 3 or len(room_id) > 50:
        logger.warning(f"Invalid room_id length: '{room_id}'. Must be between 3 and 50 characters.")
        return False
    if not room_id.isalnum():
        logger.warning(f"Invalid room_id format: '{room_id}'. Must be alphanumeric (letters and numbers only).")
        return False
    return True

def validate_user_id(user_id: str) -> bool:
    """
    Performs basic validation on a user ID.
    - Must not be empty.
    - Length between 3 and 50 characters.
    - Must be alphanumeric.
    """
    if not isinstance(user_id, str):
        logger.warning(f"User ID '{user_id}' is not a string.")
        return False
    if not user_id.strip():
        logger.warning("User ID cannot be empty or just whitespace.")
        return False
    if len(user_id) < 3 or len(user_id) > 50:
        logger.warning(f"Invalid user_id length: '{user_id}'. Must be between 3 and 50 characters.")
        return False
    if not user_id.isalnum():
        logger.warning(f"Invalid user_id format: '{user_id}'. Must be alphanumeric (letters and numbers only).")
        return False
    return True

# --- API Endpoints for Server Status and Monitoring ---
# These HTTP GET endpoints provide ways to check the server's health and view the state
# of active rooms and connections, which is useful for debugging and administrative purposes.

@app.get("/health", status_code=status.HTTP_200_OK, summary="Health Check Endpoint")
async def health_check():
    """
    Provides a simple health check endpoint.
    Returns a success status if the server is running and responsive.
    This is essential for load balancers and container orchestration systems (e.g., Kubernetes).
    """
    logger.info("Health check endpoint accessed. Server is operational.")
    return {"status": "ok", "message": "Chat server is running smoothly."}

@app.get("/status/rooms", summary="List All Active Rooms and Their Occupants")
async def get_rooms_status():
    """
    Retrieves a comprehensive list of all currently active chat rooms,
    along with the user IDs of their respective occupants.
    Also provides a total count of rooms and connections across the server.
    """
    active_rooms_info = {}
    # Iterate through all active rooms managed by the ConnectionManager.
    for room_id in manager.get_active_rooms():
        # For each room, get the list of connected users.
        active_rooms_info[room_id] = manager.get_room_occupants(room_id)
    
    total_connections = manager.get_total_connections_count()
    
    logger.info(f"Accessed room status. Total rooms: {len(active_rooms_info)}, Total connections: {total_connections}.")
    return {
        "status": "success",
        "total_rooms": len(active_rooms_info),
        "total_connections": total_connections,
        "rooms": active_rooms_info
    }

@app.get("/status/room/{room_id}", summary="Get Occupants of a Specific Room")
async def get_room_details(room_id: str):
    """
    Retrieves the list of user IDs connected to a specified room.
    Performs validation on the `room_id` and handles cases where the room does not exist.
    """
    # Validate the incoming room_id parameter.
    if not validate_room_id(room_id):
        logger.warning(f"API request for room details with invalid room ID format: '{room_id}'.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Room ID format provided.")

    occupants = manager.get_room_occupants(room_id)
    if not occupants:
        logger.info(f"Requested details for non-existent or empty room '{room_id}'.")
        # If the room has no occupants or doesn't exist, return a 404 Not Found.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Room '{room_id}' not found or is currently empty.")
    
    logger.info(f"Accessed details for room '{room_id}'. Occupants: {len(occupants)}.")
    return {
        "status": "success",
        "room_id": room_id,
        "occupants": occupants,
        "occupant_count": len(occupants)
    }

# --- Main WebSocket Endpoint for Real-Time Chat ---

@app.websocket("/ws/{room_id}/{user_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, user_id: str):
    """
    This is the primary WebSocket endpoint where clients connect to participate in chat rooms.
    Clients must provide a `room_id` and a `user_id` in the URL path parameters.
    The endpoint manages the entire lifecycle of a WebSocket connection:
    1. Input Validation: Ensures `room_id` and `user_id` are valid.
    2. Connection Establishment: Accepts the WebSocket and registers it with the ConnectionManager.
    3. Message Listening Loop: Continuously receives and processes JSON messages from the client.
    4. Message Handling: Dispatches messages based on their 'type' (e.g., chat, ping, private, user list request).
    5. Error Management: Gracefully handles disconnects, invalid JSON, and other runtime errors.
    6. Cleanup: Ensures the connection is properly removed from the manager upon disconnect.
    """
    
    # 1. Initial Input Validation for path parameters
    # Before accepting the WebSocket connection, validate the room_id and user_id.
    # If validation fails, close the connection with an appropriate error code.
    if not validate_room_id(room_id):
        logger.error(f"WebSocket connection denied: Invalid room_id '{room_id}' provided for user '{user_id}'.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid room ID format. Check docs for rules.")
        return # Exit the endpoint handler
    if not validate_user_id(user_id):
        logger.error(f"WebSocket connection denied: Invalid user_id '{user_id}' provided for room '{room_id}'.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid user ID format. Check docs for rules.")
        return # Exit the endpoint handler

    # A unique connection ID for this specific WebSocket instance.
    # While user_id is unique per room for active connections, this UUID
    # could be useful for logging or tracking specific session instances if user_id
    # were allowed to be non-unique (e.g., multiple connections from the same user).
    # For now, it's primarily for detailed logging.
    connection_instance_id = str(uuid.uuid4())[:8] # Shorten for readability in logs

    logger.info(f"Attempting to connect user '{user_id}' (Conn ID: {connection_instance_id}) to room '{room_id}'.")

    try:
        # 2. Connection Establishment
        # Add the WebSocket to the manager, which also calls `websocket.accept()`.
        await manager.connect(room_id, user_id, websocket)
        logger.info(f"User '{user_id}' (Conn ID: {connection_instance_id}) successfully established WebSocket connection to room '{room_id}'.")

        # Send a welcome message directly to the newly connected user.
        await manager.send_personal_message(
            {"type": "welcome", "sender": "server", "message": f"Welcome to room '{room_id}', {user_id}!", "timestamp": datetime.now().isoformat()},
            websocket
        )
        logger.debug(f"Sent welcome message to '{user_id}' (Conn ID: {connection_instance_id}).")

        # 3. Message Listening Loop
        # This loop continuously waits for incoming messages from the client.
        while True:
            try:
                # Receive a JSON message from the client. This call blocks until a message is received.
                data = await websocket.receive_json()
                logger.info(f"Received message from '{user_id}' (Conn ID: {connection_instance_id}) in room '{room_id}': {json.dumps(data)}.")

                # Basic validation for the received message structure.
                if not isinstance(data, dict):
                    await manager.send_personal_message({"type": "error", "message": "Invalid message format. Expected a JSON object.", "timestamp": datetime.now().isoformat()}, websocket)
                    logger.warning(f"User '{user_id}' sent non-JSON object to room '{room_id}'.")
                    continue # Continue to the next iteration to receive more messages

                # Extract message type and content. Default to 'chat_message' if not specified.
                message_type = data.get("type", "chat_message").lower()
                message_content = data.get("message")
                # Allow client to specify sender, but default to the connected user's ID for accountability.
                sender = data.get("sender", user_id) 

                # Prepare the message structure for broadcasting/sending.
                processed_message = {
                    "type": message_type,
                    "sender": sender,
                    "message": message_content,
                    # Optionally include original data for comprehensive logging or future extensions.
                    "original_payload": data 
                }

                # 4. Message Handling - Dispatch based on message type
                if message_type == "chat_message":
                    # Validate content for actual chat messages.
                    if not message_content or not isinstance(message_content, str) or not message_content.strip():
                        await manager.send_personal_message({"type": "error", "message": "Chat message content cannot be empty or invalid.", "timestamp": datetime.now().isoformat()}, websocket)
                        logger.warning(f"User '{user_id}' in room '{room_id}' sent invalid or empty chat message.")
                        continue
                    
                    # Broadcast the chat message to all users in the room.
                    # Setting exclude_user_id=None means the sender also receives their own message,
                    # which is common for confirming successful send in chat UIs.
                    await manager.broadcast_message(room_id, processed_message, exclude_user_id=None)
                    logger.debug(f"Broadcasted chat message from '{user_id}' to room '{room_id}'.")
                
                elif message_type == "ping":
                    # Respond to a 'ping' message with a 'pong'. This can be used for heartbeat mechanisms.
                    await manager.send_personal_message({"type": "pong", "timestamp": datetime.now().isoformat()}, websocket)
                    logger.debug(f"Responded to 'ping' from '{user_id}' in room '{room_id}'.")

                elif message_type == "private_message":
                    recipient_id = data.get("recipient")
                    # Validate recipient and ensure they are connected in the same room.
                    if not recipient_id or recipient_id not in manager.active_connections.get(room_id, {}):
                        await manager.send_personal_message(
                            {"type": "error", "message": f"Recipient '{recipient_id}' not found or not in room '{room_id}'.", "timestamp": datetime.now().isoformat()},
                            websocket
                        )
                        logger.warning(f"User '{user_id}' in room '{room_id}' tried to send private message to unknown/absent recipient '{recipient_id}'.")
                        continue
                    if not message_content or not isinstance(message_content, str) or not message_content.strip():
                         await manager.send_personal_message({"type": "error", "message": "Private message content cannot be empty or invalid.", "timestamp": datetime.now().isoformat()}, websocket)
                         logger.warning(f"User '{user_id}' in room '{room_id}' sent invalid or empty private message.")
                         continue

                    private_msg_payload = {
                        "type": "private_message",
                        "sender": sender,
                        "recipient": recipient_id,
                        "message": message_content,
                        "timestamp": datetime.now().isoformat()
                    }
                    # Send the private message to the recipient's WebSocket.
                    await manager.send_personal_message(private_msg_payload, manager.active_connections[room_id][recipient_id])
                    # Optionally, send a confirmation back to the sender.
                    await manager.send_personal_message({**private_msg_payload, "status_info": "message delivered"}, websocket) 
                    logger.info(f"Private message from '{user_id}' to '{recipient_id}' in room '{room_id}'.")

                elif message_type == "user_list_request":
                    # Client requested the list of users in the current room.
                    users_in_room = manager.get_room_occupants(room_id)
                    await manager.send_personal_message(
                        {"type": "user_list", "room_id": room_id, "users": users_in_room, "timestamp": datetime.now().isoformat()},
                        websocket
                    )
                    logger.debug(f"Sent user list to '{user_id}' in room '{room_id}'. Users: {users_in_room}.")
                
                else:
                    # Handle any unknown message types.
                    await manager.send_personal_message({"type": "error", "message": f"Unknown message type received: '{message_type}'.", "timestamp": datetime.now().isoformat()}, websocket)
                    logger.warning(f"User '{user_id}' in room '{room_id}' sent an unknown message type: '{message_type}'.")

            except json.JSONDecodeError:
                # 5. Error Management - Handle invalid JSON input.
                await manager.send_personal_message({"type": "error", "message": "Invalid JSON format received. Please send valid JSON.", "timestamp": datetime.now().isoformat()}, websocket)
                logger.error(f"User '{user_id}' in room '{room_id}' sent invalid JSON data.")
            
            except RuntimeError as e:
                # This often occurs when the client's connection is abruptly closed (e.g., browser tab closed)
                # while `receive_json` is waiting, leading to a disconnect.
                logger.warning(f"RuntimeError during message reception for '{user_id}' (Conn ID: {connection_instance_id}) in room '{room_id}': {e}. "
                               f"Client likely disconnected unexpectedly.")
                break # Exit the loop, which will trigger the finally block.
            
            except WebSocketDisconnect:
                # This specific exception is raised by FastAPI when a WebSocket client disconnects gracefully.
                logger.info(f"WebSocketDisconnect event for user '{user_id}' (Conn ID: {connection_instance_id}) from room '{room_id}'.")
                break # Exit the message listening loop.
            
            except Exception as e:
                # Catch any other unexpected exceptions during message processing.
                logger.critical(f"Unhandled critical error processing message from '{user_id}' (Conn ID: {connection_instance_id}) "
                                f"in room '{room_id}': {e}", exc_info=True)
                await manager.send_personal_message({"type": "error", "message": "An unexpected server error occurred while processing your message. Please try again.", "timestamp": datetime.now().isoformat()}, websocket)
                # For severe unhandled errors, it might be safer to close the connection proactively.
                # await websocket.close(code=status.WS_1011_INTERNAL_ERROR) 
                break # Exit the loop to trigger cleanup.

    except WebSocketDisconnect:
        # This block catches `WebSocketDisconnect` if it occurs immediately after `manager.connect`
        # but before entering the `while True` loop, or if the loop breaks and this is the first
        # handler encountered.
        logger.info(f"User '{user_id}' (Conn ID: {connection_instance_id}) disconnected from room '{room_id}' during initial connection or after message loop exit.")
    
    except HTTPException as e:
        # If an HTTPException was raised during connection setup (e.g., from initial validation
        # if it were moved outside the `if not validate_...` block), it would be caught here.
        logger.error(f"HTTPException during WebSocket connection for '{user_id}' (Conn ID: {connection_instance_id}) in room '{room_id}': {e.detail}")
    
    except Exception as e:
        # This broad exception handler catches any unforeseen issues during the initial connection phase
        # (e.g., before `websocket.accept()` or `manager.connect` completes successfully).
        logger.critical(f"A severe, unhandled error occurred during initial WebSocket connection setup for '{user_id}' "
                        f"(Conn ID: {connection_instance_id}) in room '{room_id}': {e}", exc_info=True)
        # Attempt to send an error message and close the WebSocket if it's still open.
        try:
            if not websocket.client_state.closed:
                await websocket.send_json({"type": "error", "message": f"Server encountered a critical error during connection setup: {e}", "timestamp": datetime.now().isoformat()})
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Critical server error during connection setup.")
        except Exception as close_e:
            logger.error(f"Error while trying to send error message or close WebSocket during critical error handling: {close_e}")
    
    finally:
        # 6. Cleanup on Disconnection
        # This `finally` block guarantees that the `disconnect` method is called,
        # ensuring the connection is removed from the manager's active connections
        # regardless of how the WebSocket lifecycle ends (graceful disconnect, error, etc.).
        await manager.disconnect(room_id, user_id)
        logger.info(f"Connection cleanup complete for user '{user_id}' (Conn ID: {connection_instance_id}) from room '{room_id}'.")

# --- Instructions for Running the Application ---
# To run this FastAPI application, you'll need `uvicorn`.
# 1. Save the code: Save this entire script as a Python file, for example, `main.py`.
# 2. Install dependencies: If you haven't already, install FastAPI and Uvicorn:
#    `pip install fastapi uvicorn`
#    (FastAPI automatically handles the `websockets` library dependency)
# 3. Run the server: Open your terminal or command prompt in the directory where you saved `main.py`
#    and execute the following command:
#    `uvicorn main:app --host 0.0.0.0 --port 8000 --reload`
#    - `main:app`: Refers to the `app` object within the `main.py` file.
#    - `--host 0.0.0.0`: Makes the server accessible from external machines (useful in Docker/network).
#    - `--port 8000`: Specifies the port for the server to listen on.
#    - `--reload`: Enables hot-reloading, so the server restarts automatically when code changes.

# Example Client-side JavaScript for testing (in a browser's developer console):
#
# // Connect to a room 'myroom' as user 'john_doe'
# let ws = new WebSocket("ws://localhost:8000/ws/myroom/john_doe");
#
# ws.onopen = (event) => {
#     console.log("WebSocket connection opened:", event);
#     // Send a regular chat message
#     ws.send(JSON.stringify({ type: "chat_message", message: "Hello everyone in myroom!" }));
#     // Request the list of users in the room
#     ws.send(JSON.stringify({ type: "user_list_request" }));
#     // Send a private message to another user (if 'jane_doe' is also connected to 'myroom')
#     setTimeout(() => {
#         ws.send(JSON.stringify({ type: "private_message", message: "Hey Jane, this is a private chat!", recipient: "jane_doe" }));
#     }, 2000); // Send after 2 seconds
# };
#
# ws.onmessage = (event) => {
#     console.log("Message from server:", JSON.parse(event.data));
# };
#
# ws.onclose = (event) => {
#     console.log("WebSocket connection closed:", event.code, event.reason);
# };
#
# ws.onerror = (event) => {
#     console.error("WebSocket Error:", event);
# };
#
# // To connect another user (e.g., 'jane_doe'):
# // let ws2 = new WebSocket("ws://localhost:8000/ws/myroom/jane_doe");
# // ws2.onopen = (event) => { console.log("WS2 Connected!"); };
# // ws2.onmessage = (event) => { console.log("WS2 Message:", JSON.parse(event.data)); };