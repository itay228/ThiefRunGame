__author__ = 'Itay Belogorodsky'

import socket
import threading
import base64
import json
import time
import random
from users_db import IsUserExist, IsPasswordOK, StartRegister, VerifyRegister, StartReset, VerifyReset, ChangePassword, load_users, save_users
from crypto import aes_encrypt, aes_decrypt, rsa_generate_keys, rsa_decrypt, rsa_keys_exist, save_rsa_keys, load_rsa_keys

# ── Settings ──────────────────────────────────────────────────────────────────
HOST = "0.0.0.0"   # listen on all network interfaces
PORT = 5555
PEPPER = "P3P3P3ER"

MAX_PER_SIDE   = 5   # max 5 thieves or 5 cops
MAX_TEAM_DIFF  = 2   # team sizes can differ by at most 2

# ── RSA Keys ──────────────────────────────────────────────────────────────────
print("Loading RSA keys...")
if rsa_keys_exist():
    rsa_public_key, rsa_private_key = load_rsa_keys()
    print("RSA keys loaded.")
else:
    print("Generating RSA keys...")
    rsa_public_key, rsa_private_key = rsa_generate_keys(bits=512)
    save_rsa_keys(rsa_public_key, rsa_private_key)
    print("RSA keys generated and saved.")

# ── Shared State ──────────────────────────────────────────────────────────────
#
# Think of these like whiteboards the server can read/write.
# "lock" is like a rule: only one thread can write at a time (no chaos).
#
lock = threading.Lock()

# Every logged-in player lives here:
# { username: { "socket": sock, "aes_key": key, "role": None/"thief"/"cop" } }
players = {}

# Players waiting to play: [ { "username": ..., "role": "thief"/"cop" } ]
queue = []

# Active game rooms: [ GameRoom, GameRoom, ... ]
active_games = []


# ── Send / Receive Helpers ────────────────────────────────────────────────────
#
# These two functions handle sending and receiving messages over the network.
# Every message is encrypted with AES so nobody can snoop on it.
#

def send_msg(sock, msg, aes_key):
    """Encrypt msg with AES, encode to base64, send over socket."""
    try:
        encrypted = aes_encrypt(msg, aes_key)        # lock the message in a box
        encoded   = base64.b64encode(encrypted)       # convert box to text-safe format
        sock.sendall(encoded)
    except OSError:
        pass


def recv_msg(sock, aes_key, buf=4096):
    """Receive bytes, base64-decode, AES-decrypt, return string."""
    try:
        raw = sock.recv(buf)
        if not raw:
            return None
        decrypted = aes_decrypt(base64.b64decode(raw), aes_key)  # open the box
        return decrypted
    except Exception:
        return None


# ── Maze Definition ───────────────────────────────────────────────────────────
#
# The maze is a 2D grid.
# 1 = wall (you can't walk through it)
# 0 = floor (you can walk here)
#
# Think of it like graph paper: 1s are the black squares, 0s are the white ones.
#

MAZE = [
    [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
    [1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1],
    [1,0,1,0,1,0,1,1,1,0,1,1,1,0,1,0,1,1,0,1],
    [1,0,1,0,0,0,1,0,0,0,0,0,1,0,0,0,1,0,0,1],
    [1,0,1,1,1,1,1,0,1,1,1,0,1,1,1,1,1,0,1,1],
    [1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1],
    [1,1,1,0,1,1,1,1,1,0,1,1,1,1,1,0,1,1,1,1],
    [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],
    [1,0,1,1,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1],
    [1,0,0,0,1,0,0,0,1,0,1,0,0,0,1,0,0,0,0,1],
    [1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,1,1,1],
    [1,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,1],
    [1,0,1,1,1,0,1,1,1,1,1,1,1,0,1,1,1,1,0,1],
    [1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1],
    [1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,0,1,0,1],
    [1,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1],
    [1,1,1,0,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1],
    [1,0,0,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,0,1],
    [1,0,1,1,1,1,1,0,1,1,1,0,1,1,1,1,1,1,0,1],
    [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
]

MAZE_ROWS = len(MAZE)
MAZE_COLS = len(MAZE[0])

# Spawn points: where thieves and cops start
THIEF_SPAWNS = [(1,1), (1,3), (3,1), (3,3)]   # (row, col) positions
COP_SPAWNS   = [(1,17),(1,15),(3,17),(3,15),(5,17)]


def get_floor_cells():
    """Return list of all (row,col) that are walkable floor (value=0)."""
    floors = []
    for r in range(MAZE_ROWS):
        for c in range(MAZE_COLS):
            if MAZE[r][c] == 0:
                floors.append((r, c))
    return floors


def place_coins(count=30):
    """Pick `count` random floor cells to place coins on (not on spawn points)."""
    floors  = get_floor_cells()
    blocked = set(THIEF_SPAWNS + COP_SPAWNS)
    choices = [f for f in floors if f not in blocked]
    random.shuffle(choices)
    return set(choices[:count])


# ── Game Room ─────────────────────────────────────────────────────────────────
#
# A GameRoom holds everything about ONE match:
# - who is playing (thieves and cops)
# - where everyone is on the map
# - where the coins are
# - is the game still running?
#

class GameRoom:
    def __init__(self, thieves, cops):
        # thieves and cops are lists of usernames
        self.thieves = thieves
        self.cops    = cops
        self.running = True

        # Give each player a starting position
        self.positions = {}
        for i, name in enumerate(thieves):
            self.positions[name] = list(THIEF_SPAWNS[i % len(THIEF_SPAWNS)])
        for i, name in enumerate(cops):
            self.positions[name] = list(COP_SPAWNS[i % len(COP_SPAWNS)])

        # Place coins randomly on the maze
        self.coins = place_coins(30)

        # Start the game loop in its own thread
        t = threading.Thread(target=self.game_loop, daemon=True)
        t.start()

    def all_players(self):
        return self.thieves + self.cops

    def get_state(self):
        """
        Build a snapshot of the game right now.
        This gets sent to every player so their screen can update.
        """
        return json.dumps({
            "positions": {name: pos for name, pos in self.positions.items()},
            "coins":     [list(c) for c in self.coins],
            "thieves":   self.thieves,
            "cops":      self.cops,
        })

    def move_player(self, username, direction):
        """
        Try to move a player one step in a direction.
        Only move if the destination is a floor tile (not a wall).
        """
        if username not in self.positions:
            return
        r, c = self.positions[username]

        # Figure out where they want to go
        dr, dc = {"UP": (-1,0), "DOWN": (1,0), "LEFT": (0,-1), "RIGHT": (0,1)}.get(direction, (0,0))
        nr, nc = r + dr, c + dc

        # Check bounds and wall
        if 0 <= nr < MAZE_ROWS and 0 <= nc < MAZE_COLS and MAZE[nr][nc] == 0:
            self.positions[username] = [nr, nc]

            # If a thief steps on a coin, collect it
            if username in self.thieves:
                self.coins.discard((nr, nc))

    def check_win(self):
        """
        Check if the game is over.
        Returns "thieves", "cops", or None (game still going).
        """
        # Cops win if any cop touches any thief
        for cop in self.cops:
            for thief in self.thieves:
                if self.positions[cop] == self.positions[thief]:
                    return "cops"

        # Thieves win if all coins are collected
        if len(self.coins) == 0:
            return "thieves"

        return None  # game continues

    def broadcast(self, msg):
        """Send a message to every player in this game room."""
        with lock:
            for name in self.all_players():
                if name in players:
                    p = players[name]
                    send_msg(p["socket"], msg, p["aes_key"])

    def end_game(self, winner):
        """
        Game is over! Tell everyone who won, update win/loss records.
        """
        self.running = False
        winners = self.thieves if winner == "thieves" else self.cops
        losers  = self.cops    if winner == "thieves" else self.thieves

        # Update win/loss counts in the database
        db = load_users()
        for name in winners:
            if name in db:
                db[name]["wins"]   = db[name].get("wins",   0) + 1
        for name in losers:
            if name in db:
                db[name]["losses"] = db[name].get("losses", 0) + 1
        save_users(db)

        # Tell every player the result
        self.broadcast(f"GAME_OVER|{winner}")

        # Remove this game from active list
        with lock:
            if self in active_games:
                active_games.remove(self)

    def game_loop(self):
        """
        The heartbeat of the game — runs 20 times per second.
        Each tick: check win condition, send game state to all players.
        """
        while self.running:
            winner = self.check_win()
            if winner:
                self.end_game(winner)
                return

            # Send current state to all players
            state_msg = f"GAME_STATE|{self.get_state()}"
            self.broadcast(state_msg)

            time.sleep(0.05)   # 50ms = 20 ticks per second


# ── Matchmaking ───────────────────────────────────────────────────────────────
#
# When a player clicks "Play" and chooses a role, they join the queue.
# This function checks if we can start a game with the people waiting.
#

def _launch_game(chosen_thieves, chosen_cops):
    """Remove chosen players from queue and start a GameRoom."""
    for p in list(queue):
        if p["username"] in chosen_thieves + chosen_cops:
            queue.remove(p)

    room = GameRoom(chosen_thieves, chosen_cops)
    active_games.append(room)

    for name in chosen_thieves + chosen_cops:
        role = "thief" if name in chosen_thieves else "cop"
        if name in players:
            p = players[name]
            send_msg(p["socket"], f"GAME_START|{role}", p["aes_key"])


def try_start_game():
    """
    Start a game if:
    - 5 players on EACH side → auto-start all of them, or
    - At least 1 READY thief AND 1 READY cop → start with ready players only
    """
    thieves = [p for p in queue if p["role"] == "thief"]
    cops    = [p for p in queue if p["role"] == "cop"]

    # Auto-start: 5 on each side
    if len(thieves) >= MAX_PER_SIDE and len(cops) >= MAX_PER_SIDE:
        _launch_game(
            [p["username"] for p in thieves[:MAX_PER_SIDE]],
            [p["username"] for p in cops[:MAX_PER_SIDE]],
        )
        return

    # Ready-start: at least 1 ready on each side
    t_ready = [p for p in thieves if p.get("ready")]
    c_ready = [p for p in cops    if p.get("ready")]
    if t_ready and c_ready:
        _launch_game(
            [p["username"] for p in t_ready],
            [p["username"] for p in c_ready],
        )


def get_lobby_data(username):
    """
    Build the lobby info for a player: their wins and losses.
    """
    db = load_users()
    user = db.get(username, {})
    wins   = user.get("wins",   0)
    losses = user.get("losses", 0)
    return f"LOBBY_DATA|{wins}|{losses}"


def get_queue_update():
    """
    Build a message describing who is in the queue and who is ready.
    Each player is sent as {"name": ..., "ready": true/false}.
    """
    thieves = [{"name": p["username"], "ready": p.get("ready", False)} for p in queue if p["role"] == "thief"]
    cops    = [{"name": p["username"], "ready": p.get("ready", False)} for p in queue if p["role"] == "cop"]
    return f"QUEUE_UPDATE|{json.dumps({'thieves': thieves, 'cops': cops})}"


def broadcast_queue_update():
    """Send the current queue state to every player in the queue."""
    update = get_queue_update()
    for p in queue:
        if p["username"] in players:
            pp = players[p["username"]]
            send_msg(pp["socket"], update, pp["aes_key"])


# ── Client Handler ────────────────────────────────────────────────────────────
#
# This function runs in its own thread for EACH connected player.
# It's like a personal assistant: it reads what the player sends
# and responds accordingly.
#

def handle_client(client_socket):
    username = None
    aes_key  = None
    game_room = None   # which game this player is currently in

    try:
        # ── Step 1: RSA Key Exchange ──────────────────────────────────────────
        #
        # Before anything else, client and server agree on a secret AES key.
        # RSA is like a padlock: server gives client the open padlock (public key),
        # client puts the secret AES key inside and locks it.
        # Only the server can open it (with the private key).
        #

        # Client sends "KEY_EXCHANGE|RSA"
        raw = client_socket.recv(1024).decode()
        if raw != "KEY_EXCHANGE|RSA":
            client_socket.close()
            return

        client_socket.send("SUPPORTED".encode())

        # Client asks for public key
        req = client_socket.recv(1024).decode()
        if req != "GET_PUBLIC_KEY":
            client_socket.close()
            return

        n, e = rsa_public_key
        client_socket.send(f"RSA_PUBLIC_KEY|{n}|{e}".encode())

        # Client sends AES key encrypted with our RSA public key
        aes_msg = client_socket.recv(4096).decode()
        if not aes_msg.startswith("AES_KEY|"):
            client_socket.close()
            return

        enc_hex = aes_msg.split("|", 1)[1]
        aes_key = rsa_decrypt(bytes.fromhex(enc_hex), rsa_private_key)
        client_socket.send("KEY_OK".encode())

        # ── Step 2: Main Message Loop ─────────────────────────────────────────
        #
        # Now all messages are encrypted with AES.
        # We keep reading messages from this client forever (until they disconnect).
        #

        while True:
            data = recv_msg(client_socket, aes_key)
            if not data:
                break

            parts   = data.split("|")
            command = parts[0]

            # ── AUTH ──────────────────────────────────────────────────────────

            if command == "LOGIN":
                user, password = parts[1], parts[2]
                if IsPasswordOK(user, password, PEPPER):
                    username = user
                    with lock:
                        players[username] = {"socket": client_socket, "aes_key": aes_key, "role": None}
                    send_msg(client_socket, "OK", aes_key)
                    # Send lobby data right after login
                    send_msg(client_socket, get_lobby_data(username), aes_key)
                else:
                    send_msg(client_socket, "ERROR|Wrong username or password", aes_key)

            elif command == "SIGNUP":
                user, password, email = parts[1], parts[2], parts[3]
                if IsUserExist(user):
                    send_msg(client_socket, "ERROR|Username already taken", aes_key)
                else:
                    if StartRegister(user, password, email):
                        send_msg(client_socket, "CODE_SENT", aes_key)
                    else:
                        send_msg(client_socket, "ERROR|Email already used", aes_key)

            elif command == "VERIFY_SIGNUP":
                email, code = parts[1], parts[2]
                if VerifyRegister(email, code):
                    send_msg(client_socket, "REGISTER_OK", aes_key)
                else:
                    send_msg(client_socket, "ERROR|Wrong or expired code", aes_key)

            elif command == "FORGOT_PASSWORD":
                email = parts[1]
                if StartReset(email):
                    send_msg(client_socket, "CODE_SENT", aes_key)
                else:
                    send_msg(client_socket, "ERROR|Email not found", aes_key)

            elif command == "VERIFY_RESET":
                email, code = parts[1], parts[2]
                result = VerifyReset(email, code)
                if result:
                    send_msg(client_socket, f"RESET_OK|{result}", aes_key)
                else:
                    send_msg(client_socket, "ERROR|Wrong or expired code", aes_key)

            elif command == "CHANGE_PASSWORD":
                uname, new_password = parts[1], parts[2]
                ChangePassword(uname, new_password, PEPPER)
                send_msg(client_socket, "OK", aes_key)

            # ── LOBBY / QUEUE ─────────────────────────────────────────────────

            elif command == "JOIN_QUEUE":
                # Player picked a role and pressed Play
                role = parts[1]   # "thief" or "cop"

                if role not in ("thief", "cop"):
                    send_msg(client_socket, "ERROR|Invalid role", aes_key)
                    continue

                # Count how many of this role are already waiting
                with lock:
                    same_role_count = sum(1 for p in queue if p["role"] == role)

                if same_role_count >= MAX_PER_SIDE:
                    send_msg(client_socket, "ERROR|That side is full", aes_key)
                    continue

                with lock:
                    for p in list(queue):
                        if p["username"] == username:
                            queue.remove(p)
                    queue.append({"username": username, "role": role, "ready": False})

                send_msg(client_socket, "QUEUE_JOINED", aes_key)

                with lock:
                    broadcast_queue_update()
                    try_start_game()

            elif command == "READY":
                # Player clicked the Ready button
                with lock:
                    for p in queue:
                        if p["username"] == username:
                            p["ready"] = True
                            break
                    broadcast_queue_update()
                    try_start_game()

            elif command == "LEAVE_QUEUE":
                with lock:
                    for p in list(queue):
                        if p["username"] == username:
                            queue.remove(p)
                    broadcast_queue_update()
                send_msg(client_socket, "QUEUE_LEFT", aes_key)

            # ── IN-GAME ───────────────────────────────────────────────────────

            elif command == "MOVE":
                direction = parts[1]   # "UP", "DOWN", "LEFT", "RIGHT"
                # Find which game room this player is in
                found_room = None
                with lock:
                    for room in active_games:
                        if username in room.all_players():
                            found_room = room
                            break
                if found_room:
                    found_room.move_player(username, direction)

    except Exception as e:
        print(f"[!] Error for {username}: {e}")
    finally:
        # Cleanup when player disconnects
        if username:
            with lock:
                players.pop(username, None)
                for p in list(queue):
                    if p["username"] == username:
                        queue.remove(p)
        client_socket.close()
        print(f"[-] {username or 'unknown'} disconnected")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"[+] New connection from {addr}")
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
