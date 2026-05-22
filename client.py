__author__ = 'Itay Belogorodsky'

import socket
import threading
import tkinter as tk
from tkinter import ttk
import base64
import os
import queue as Queue
import json
import time
import sys
import pygame

from crypto import aes_encrypt, aes_decrypt, rsa_encrypt

# ── Network ───────────────────────────────────────────────────────────────────
SERVER_IP   = "127.0.0.1"
SERVER_PORT = 5555

sock = socket.socket()
aes_key = None
msg_queue = Queue.Queue()


def send_msg(msg):
    try:
        sock.sendall(base64.b64encode(aes_encrypt(msg, aes_key)))
    except OSError:
        pass


def recv_msg_raw(buf=4096):
    try:
        raw = sock.recv(buf)
        if not raw:
            return None
        return aes_decrypt(base64.b64decode(raw), aes_key)
    except Exception:
        return None


def network_listener():
    """Background thread: reads all server messages and puts them in msg_queue."""
    while True:
        msg = recv_msg_raw()
        if msg is None:
            msg_queue.put("DISCONNECTED")
            break
        msg_queue.put(msg)


# ── RSA Key Exchange ──────────────────────────────────────────────────────────
def do_key_exchange():
    global aes_key
    sock.connect((SERVER_IP, SERVER_PORT))
    sock.send("KEY_EXCHANGE|RSA".encode())
    if sock.recv(1024).decode() != "SUPPORTED":
        raise ConnectionError("Server rejected RSA")
    sock.send("GET_PUBLIC_KEY".encode())
    _, n_str, e_str = sock.recv(4096).decode().split("|")
    n, e    = int(n_str), int(e_str)
    new_key = os.urandom(16)
    sock.send(f"AES_KEY|{rsa_encrypt(new_key, (n, e)).hex()}".encode())
    if sock.recv(1024).decode() != "KEY_OK":
        raise ConnectionError("Key exchange failed")
    aes_key = new_key


# ── Colors & constants ────────────────────────────────────────────────────────
BG_DARK    = (13,  13,  25)
BG_CARD    = (22,  22,  45)
BG_CARD2   = (30,  30,  62)
GOLD       = (255, 210,  0)
RED        = (210,  55,  55)
BLUE       = ( 55, 110, 225)
GREEN      = ( 50, 195, 105)
GRAY_WALL  = ( 45,  45,  72)
GRAY_FLOOR = ( 26,  26,  48)
WHITE      = (235, 235, 255)
TEXT_DIM   = (120, 120, 155)
TILE       = 32

_MAZE = [
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
MAZE_ROWS = 20
MAZE_COLS = 20


# ── pygame helpers ────────────────────────────────────────────────────────────
def drect(surf, color, rect, r=0):
    pygame.draw.rect(surf, color, rect, border_radius=r)

def dtxt(surf, text, font, color, cx, cy):
    s = font.render(str(text), True, color)
    surf.blit(s, s.get_rect(center=(cx, cy)))


# ── Tkinter Auth ──────────────────────────────────────────────────────────────
logged_in_username = None


def run_auth():
    global logged_in_username
    root = tk.Tk()
    root.title("Thief & Cop")
    root.geometry("420x520")
    root.configure(bg="#0d0d19")
    root.resizable(False, False)

    frames = []

    def show(f):
        for fr in frames:
            fr.pack_forget()
        f.pack(fill="both", expand=True, padx=30, pady=15)

    style = ttk.Style()
    style.theme_use("default")
    style.configure("TEntry",  fieldbackground="#16162d", foreground="white", insertcolor="white")
    style.configure("TButton", background="#3c3c7a", foreground="white", font=("Arial", 11))
    style.map("TButton", background=[("active", "#5555aa")])

    def lbl(p, text, size=11, color="white", bold=False):
        return tk.Label(p, text=text, bg="#0d0d19", fg=color,
                        font=("Arial", size, "bold" if bold else "normal"))

    # ── Main menu ──
    mf = tk.Frame(root, bg="#0d0d19")
    lbl(mf, "THIEF & COP", 28, "#ffd200", bold=True).pack(pady=(40, 5))
    lbl(mf, "Multiplayer Heist Game", 12, "#8888aa").pack(pady=(0, 40))
    btn_login  = ttk.Button(mf, text="Login",   width=22)
    btn_signup = ttk.Button(mf, text="Sign Up", width=22)
    btn_login.pack(pady=8)
    btn_signup.pack(pady=8)
    frames.append(mf)

    # ── Login ──
    lf = tk.Frame(root, bg="#0d0d19")
    lbl(lf, "Login", 22, bold=True).pack(pady=(15, 20))
    lbl(lf, "Username").pack(anchor="w")
    eu = ttk.Entry(lf, width=32); eu.pack(pady=4, fill="x")
    lbl(lf, "Password").pack(anchor="w")
    ep = ttk.Entry(lf, width=32, show="*"); ep.pack(pady=4, fill="x")
    ls = lbl(lf, "", 10, "#ff6060"); ls.pack(pady=4)

    def do_login():
        global logged_in_username
        u, p = eu.get().strip(), ep.get()
        if not u or not p:
            ls.config(text="Fill in all fields")
            return
        send_msg(f"LOGIN|{u}|{p}")
        r = recv_msg_raw()
        if r == "OK":
            lobby_data = recv_msg_raw()   # LOBBY_DATA|wins|losses
            logged_in_username = u
            msg_queue.put(lobby_data)
            root.destroy()
        else:
            ls.config(text="Wrong username or password")

    ttk.Button(lf, text="Login",           command=do_login).pack(pady=10)
    ttk.Button(lf, text="Forgot Password", command=lambda: show(ff)).pack(pady=3)
    ttk.Button(lf, text="Back",            command=lambda: show(mf)).pack(pady=3)
    frames.append(lf)
    btn_login.config(command=lambda: show(lf))

    # ── Sign Up ──
    sf = tk.Frame(root, bg="#0d0d19")
    lbl(sf, "Sign Up", 22, bold=True).pack(pady=(10, 15))
    lbl(sf, "Username").pack(anchor="w")
    su_u = ttk.Entry(sf, width=32); su_u.pack(pady=3, fill="x")
    lbl(sf, "Password").pack(anchor="w")
    su_p = ttk.Entry(sf, width=32, show="*"); su_p.pack(pady=3, fill="x")
    lbl(sf, "Email").pack(anchor="w")
    su_e = ttk.Entry(sf, width=32); su_e.pack(pady=3, fill="x")
    lbl(sf, "Verification Code").pack(anchor="w")
    su_c = ttk.Entry(sf, width=32); su_c.pack(pady=3, fill="x")
    ss = lbl(sf, "", 10, "#ff6060"); ss.pack(pady=3)

    def do_signup():
        u, p, e = su_u.get().strip(), su_p.get(), su_e.get().strip()
        if not u or not p or not e:
            ss.config(text="Fill username, password and email first")
            return
        send_msg(f"SIGNUP|{u}|{p}|{e}")
        r = recv_msg_raw()
        if r == "CODE_SENT":
            ss.config(text="Code sent to your email!", fg="#50c878")
        else:
            ss.config(text=r.split("|", 1)[-1] if r and "|" in r else "Error", fg="#ff6060")

    def do_verify_signup():
        global logged_in_username
        u, p = su_u.get().strip(), su_p.get()
        e, c = su_e.get().strip(), su_c.get().strip()
        send_msg(f"VERIFY_SIGNUP|{e}|{c}")
        r = recv_msg_raw()
        if r == "REGISTER_OK":
            send_msg(f"LOGIN|{u}|{p}")
            if recv_msg_raw() == "OK":
                lobby_data = recv_msg_raw()
                logged_in_username = u
                msg_queue.put(lobby_data)
                root.destroy()
        else:
            ss.config(text="Wrong or expired code", fg="#ff6060")

    ttk.Button(sf, text="Send Code",     command=do_signup).pack(pady=4)
    ttk.Button(sf, text="Verify & Play", command=do_verify_signup).pack(pady=4)
    ttk.Button(sf, text="Back",          command=lambda: show(mf)).pack(pady=4)
    frames.append(sf)
    btn_signup.config(command=lambda: show(sf))

    # ── Forgot Password ──
    ff = tk.Frame(root, bg="#0d0d19")
    lbl(ff, "Reset Password", 20, bold=True).pack(pady=(10, 15))
    lbl(ff, "Email").pack(anchor="w")
    fp_e = ttk.Entry(ff, width=32); fp_e.pack(pady=3, fill="x")
    lbl(ff, "Code").pack(anchor="w")
    fp_c = ttk.Entry(ff, width=32); fp_c.pack(pady=3, fill="x")
    lbl(ff, "New Password").pack(anchor="w")
    fp_n = ttk.Entry(ff, width=32, show="*"); fp_n.pack(pady=3, fill="x")
    fs = lbl(ff, "", 10, "#ff6060"); fs.pack(pady=3)
    reset_user = [None]

    def do_forgot():
        send_msg(f"FORGOT_PASSWORD|{fp_e.get().strip()}")
        r = recv_msg_raw()
        ok = r == "CODE_SENT"
        fs.config(text="Code sent!" if ok else "Email not found",
                  fg="#50c878" if ok else "#ff6060")

    def do_verify_reset():
        send_msg(f"VERIFY_RESET|{fp_e.get().strip()}|{fp_c.get().strip()}")
        r = recv_msg_raw()
        if r and r.startswith("RESET_OK"):
            reset_user[0] = r.split("|")[1]
            fs.config(text="Verified! Enter new password.", fg="#50c878")
        else:
            fs.config(text="Wrong or expired code", fg="#ff6060")

    def do_change_pw():
        if not reset_user[0]:
            fs.config(text="Verify code first", fg="#ff6060")
            return
        send_msg(f"CHANGE_PASSWORD|{reset_user[0]}|{fp_n.get()}")
        recv_msg_raw()
        fs.config(text="Password changed! You can login.", fg="#50c878")

    ttk.Button(ff, text="Send Code",       command=do_forgot).pack(pady=3)
    ttk.Button(ff, text="Verify Code",     command=do_verify_reset).pack(pady=3)
    ttk.Button(ff, text="Change Password", command=do_change_pw).pack(pady=3)
    ttk.Button(ff, text="Back",            command=lambda: show(lf)).pack(pady=3)
    frames.append(ff)

    show(mf)
    root.mainloop()
    return logged_in_username


# ── LOBBY ─────────────────────────────────────────────────────────────────────
def run_lobby(username, wins, losses):
    W, H = 620, 500
    screen = pygame.display.set_mode((W, H))
    pygame.display.set_caption("Thief & Cop — Lobby")
    clock  = pygame.time.Clock()

    F_BIG  = pygame.font.SysFont("Arial", 38, bold=True)
    F_MED  = pygame.font.SysFont("Arial", 22, bold=True)
    F_SM   = pygame.font.SysFont("Arial", 16)
    F_TINY = pygame.font.SysFont("Arial", 13)

    role       = [None]
    thief_card = pygame.Rect(55,  235, 220, 140)
    cop_card   = pygame.Rect(345, 235, 220, 140)
    play_btn   = pygame.Rect(210, 410, 200, 52)

    while True:
        screen.fill(BG_DARK)

        # subtle grid lines in background
        for i in range(0, W, 40):
            pygame.draw.line(screen, (18, 18, 38), (i, 0), (i, H))

        dtxt(screen, "THIEF  &  COP", F_BIG, GOLD, W // 2, 48)

        # Player card
        drect(screen, BG_CARD, pygame.Rect(55, 100, W - 110, 108), r=14)
        pygame.draw.rect(screen, GRAY_WALL, pygame.Rect(55, 100, W - 110, 108), 2, border_radius=14)
        dtxt(screen, username, F_MED, WHITE, W // 2, 128)
        drect(screen, (20, 60, 30), pygame.Rect(128, 150, 130, 40), r=8)
        dtxt(screen, f"Wins  {wins}", F_SM, GREEN, 193, 170)
        drect(screen, (60, 20, 20), pygame.Rect(362, 150, 130, 40), r=8)
        dtxt(screen, f"Losses  {losses}", F_SM, RED, 427, 170)

        dtxt(screen, "Choose your side", F_SM, TEXT_DIM, W // 2, 215)

        # Thief card
        tc = BLUE if role[0] == "thief" else BG_CARD2
        drect(screen, tc, thief_card, r=14)
        pygame.draw.rect(screen, BLUE if role[0] == "thief" else GRAY_WALL, thief_card, 2, border_radius=14)
        dtxt(screen, "THIEF",          F_MED,  WHITE,    thief_card.centerx, thief_card.centery - 30)
        dtxt(screen, "Collect coins",  F_TINY, TEXT_DIM, thief_card.centerx, thief_card.centery + 5)
        dtxt(screen, "Avoid the cops", F_TINY, TEXT_DIM, thief_card.centerx, thief_card.centery + 23)
        pygame.draw.circle(screen, GOLD, (thief_card.centerx, thief_card.bottom - 20), 9)

        # Cop card
        cc = RED if role[0] == "cop" else BG_CARD2
        drect(screen, cc, cop_card, r=14)
        pygame.draw.rect(screen, RED if role[0] == "cop" else GRAY_WALL, cop_card, 2, border_radius=14)
        dtxt(screen, "COP",               F_MED,  WHITE,    cop_card.centerx, cop_card.centery - 30)
        dtxt(screen, "Catch all thieves", F_TINY, TEXT_DIM, cop_card.centerx, cop_card.centery + 5)
        dtxt(screen, "Stop the heist",    F_TINY, TEXT_DIM, cop_card.centerx, cop_card.centery + 23)
        pygame.draw.circle(screen, (150, 150, 200), (cop_card.centerx, cop_card.bottom - 20), 9)

        # Play button
        pb = GREEN if role[0] else GRAY_WALL
        drect(screen, pb, play_btn, r=14)
        dtxt(screen, "PLAY", F_MED, WHITE if role[0] else TEXT_DIM, play_btn.centerx, play_btn.centery)

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit(); sys.exit()
            if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                mx, my = event.pos
                if thief_card.collidepoint(mx, my):   role[0] = "thief"
                elif cop_card.collidepoint(mx, my):   role[0] = "cop"
                elif play_btn.collidepoint(mx, my) and role[0]:
                    return role[0]

        pygame.display.flip()
        clock.tick(60)


# ── WAITING ROOM ──────────────────────────────────────────────────────────────
def run_waiting_room(my_role):
    W, H = 620, 460
    screen = pygame.display.set_mode((W, H))
    pygame.display.set_caption("Thief & Cop — Waiting Room")
    clock  = pygame.time.Clock()

    F_BIG = pygame.font.SysFont("Arial", 30, bold=True)
    F_MED = pygame.font.SysFont("Arial", 20, bold=True)
    F_SM  = pygame.font.SysFont("Arial", 15)

    ready_btn  = pygame.Rect(180, 385, 120, 44)
    cancel_btn = pygame.Rect(320, 385, 120, 44)

    # Each entry: {"name": str, "ready": bool}
    thieves_list = []
    cops_list    = []
    i_am_ready   = False
    dots         = 0
    dot_timer    = 0
    err          = ""

    while True:
        screen.fill(BG_DARK)

        dot_timer += 1
        if dot_timer % 25 == 0:
            dots = (dots + 1) % 4

        dtxt(screen, "Waiting for players" + "." * dots, F_BIG, GOLD, W // 2, 42)

        rc = BLUE if my_role == "thief" else RED
        dtxt(screen, f"You are:  {my_role.upper()}", F_SM, rc, W // 2, 80)

        # Column headers
        dtxt(screen, "THIEVES", F_MED, BLUE, W // 4,     115)
        dtxt(screen, "COPS",    F_MED, RED,  3 * W // 4, 115)
        pygame.draw.line(screen, GRAY_WALL, (W // 2, 100), (W // 2, 370), 2)

        # Draw player names — green if ready, white if not
        for i, p in enumerate(thieves_list):
            col  = GREEN if p["ready"] else WHITE
            mark = " READY" if p["ready"] else ""
            dtxt(screen, p["name"] + mark, F_SM, col, W // 4, 148 + i * 30)

        for i, p in enumerate(cops_list):
            col  = GREEN if p["ready"] else WHITE
            mark = " READY" if p["ready"] else ""
            dtxt(screen, p["name"] + mark, F_SM, col, 3 * W // 4, 148 + i * 30)

        if err:
            dtxt(screen, err, F_SM, RED, W // 2, 370)

        # Ready button (grayed out once clicked)
        rb_col = (40, 100, 40) if i_am_ready else GREEN
        drect(screen, rb_col, ready_btn, r=10)
        dtxt(screen, "READY" if not i_am_ready else "WAITING...", F_SM, WHITE,
             ready_btn.centerx, ready_btn.centery)

        # Cancel button
        drect(screen, (120, 30, 30), cancel_btn, r=10)
        dtxt(screen, "Cancel", F_SM, WHITE, cancel_btn.centerx, cancel_btn.centery)

        # Hint text
        dtxt(screen, "Click READY when your team is set!", F_SM, TEXT_DIM, W // 2, 440)

        # Server messages
        while not msg_queue.empty():
            msg = msg_queue.get()
            if msg.startswith("QUEUE_UPDATE|"):
                d = json.loads(msg.split("|", 1)[1])
                thieves_list = d.get("thieves", [])
                cops_list    = d.get("cops",    [])
            elif msg.startswith("GAME_START|"):
                return msg.split("|")[1]
            elif msg.startswith("ERROR|"):
                err = msg.split("|", 1)[1]
            elif msg == "DISCONNECTED":
                pygame.quit(); sys.exit()

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                send_msg("LEAVE_QUEUE"); pygame.quit(); sys.exit()
            if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                if ready_btn.collidepoint(event.pos) and not i_am_ready:
                    send_msg("READY")
                    i_am_ready = True
                elif cancel_btn.collidepoint(event.pos):
                    send_msg("LEAVE_QUEUE")
                    return None

        pygame.display.flip()
        clock.tick(60)


# ── GAME ──────────────────────────────────────────────────────────────────────
MAZE_W  = MAZE_COLS * TILE   # 640
MAZE_H  = MAZE_ROWS * TILE   # 640
TOP_BAR = 62


def run_game(my_username, my_role):
    screen = pygame.display.set_mode((MAZE_W, MAZE_H + TOP_BAR))
    pygame.display.set_caption("Thief & Cop — Game")
    clock  = pygame.time.Clock()

    F_BIG = pygame.font.SysFont("Arial", 22, bold=True)
    F_SM  = pygame.font.SysFont("Arial", 13)

    positions = {}
    coins     = set()
    thieves   = []
    cops      = []

    last_move = 0
    MOVE_RATE = 0.13

    while True:
        # ── Server messages ──
        while not msg_queue.empty():
            msg = msg_queue.get()
            if msg.startswith("GAME_STATE|"):
                d         = json.loads(msg.split("|", 1)[1])
                positions = d["positions"]
                coins     = set(tuple(c) for c in d["coins"])
                thieves   = d["thieves"]
                cops      = d["cops"]
            elif msg.startswith("GAME_OVER|"):
                return msg.split("|")[1]
            elif msg == "DISCONNECTED":
                pygame.quit(); sys.exit()

        # ── Keyboard movement ──
        now  = time.time()
        keys = pygame.key.get_pressed()
        if now - last_move >= MOVE_RATE:
            d = None
            if keys[pygame.K_UP]    or keys[pygame.K_w]: d = "UP"
            if keys[pygame.K_DOWN]  or keys[pygame.K_s]: d = "DOWN"
            if keys[pygame.K_LEFT]  or keys[pygame.K_a]: d = "LEFT"
            if keys[pygame.K_RIGHT] or keys[pygame.K_d]: d = "RIGHT"
            if d:
                send_msg(f"MOVE|{d}")
                last_move = now

        # ── Draw background ──
        screen.fill(BG_DARK)

        # ── Top bar ──
        pygame.draw.rect(screen, BG_CARD, (0, 0, MAZE_W, TOP_BAR))
        pygame.draw.line(screen, GRAY_WALL, (0, TOP_BAR), (MAZE_W, TOP_BAR), 2)
        rc = BLUE if my_role == "thief" else RED
        dtxt(screen, my_role.upper(),         F_BIG, rc,    80,          TOP_BAR // 2)
        dtxt(screen, f"Coins: {len(coins)}",  F_BIG, GOLD,  MAZE_W // 2, TOP_BAR // 2)
        dtxt(screen, f"T:{len(thieves)}  C:{len(cops)}", F_BIG, WHITE, MAZE_W - 85, TOP_BAR // 2)

        # ── Maze tiles ──
        for r in range(MAZE_ROWS):
            for c in range(MAZE_COLS):
                x = c * TILE
                y = r * TILE + TOP_BAR
                if _MAZE[r][c] == 1:
                    pygame.draw.rect(screen, GRAY_WALL,  (x, y, TILE, TILE))
                    pygame.draw.rect(screen, (55, 55, 85), (x, y, TILE, TILE), 1)
                else:
                    pygame.draw.rect(screen, GRAY_FLOOR, (x, y, TILE, TILE))

        # ── Coins ──
        for (r, c) in coins:
            cx = c * TILE + TILE // 2
            cy = r * TILE + TILE // 2 + TOP_BAR
            pygame.draw.circle(screen, (160, 120, 0), (cx, cy), 8)
            pygame.draw.circle(screen, GOLD,          (cx, cy), 6)

        # ── Players ──
        for name, pos in positions.items():
            r, c   = pos
            px     = c * TILE + TILE // 2
            py     = r * TILE + TILE // 2 + TOP_BAR
            col    = BLUE if name in thieves else RED
            is_me  = (name == my_username)

            pygame.draw.circle(screen, (0, 0, 0),  (px + 2, py + 2), 14)  # shadow
            pygame.draw.circle(screen, col,         (px, py), 13)
            if is_me:
                pygame.draw.circle(screen, WHITE, (px, py), 13, 3)
            ltr = F_SM.render(name[0].upper(), True, WHITE)
            screen.blit(ltr, (px - ltr.get_width() // 2, py - ltr.get_height() // 2))

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit(); sys.exit()

        pygame.display.flip()
        clock.tick(60)


# ── GAME OVER ─────────────────────────────────────────────────────────────────
def run_game_over(winner, my_role):
    W, H = 600, 380
    screen = pygame.display.set_mode((W, H))
    pygame.display.set_caption("Thief & Cop — Results")
    clock  = pygame.time.Clock()

    F_HUGE = pygame.font.SysFont("Arial", 56, bold=True)
    F_BIG  = pygame.font.SysFont("Arial", 28, bold=True)
    F_SM   = pygame.font.SysFont("Arial", 17)

    i_won = (winner == "thieves" and my_role == "thief") or \
            (winner == "cops"    and my_role == "cop")

    result_col = GREEN if i_won else RED
    result_txt = "YOU WIN!" if i_won else "YOU LOSE"
    lobby_btn  = pygame.Rect(200, 300, 200, 52)

    while True:
        screen.fill(BG_DARK)
        dtxt(screen, result_txt,             F_HUGE, result_col, W // 2, 110)
        dtxt(screen, f"The {winner} win!",   F_BIG,  WHITE,      W // 2, 190)
        dtxt(screen, "Stats updated",        F_SM,   TEXT_DIM,   W // 2, 240)
        drect(screen, BLUE, lobby_btn, r=12)
        dtxt(screen, "Back to Lobby",        F_SM,   WHITE,      lobby_btn.centerx, lobby_btn.centery)

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit(); sys.exit()
            if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                if lobby_btn.collidepoint(event.pos):
                    return

        pygame.display.flip()
        clock.tick(60)


# ── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    try:
        do_key_exchange()
    except Exception as e:
        print(f"[!] Cannot connect to server: {e}")
        sys.exit(1)

    username = run_auth()
    if not username:
        sys.exit(0)

    pygame.init()
    pygame.font.init()

    threading.Thread(target=network_listener, daemon=True).start()

    # Grab the LOBBY_DATA message that was queued during login
    wins, losses = 0, 0
    deadline = time.time() + 3
    while msg_queue.empty() and time.time() < deadline:
        time.sleep(0.01)
    if not msg_queue.empty():
        lm = msg_queue.get()
        if lm and lm.startswith("LOBBY_DATA|"):
            _, w, l = lm.split("|")
            wins, losses = int(w), int(l)

    # Main game loop
    while True:
        role = run_lobby(username, wins, losses)

        send_msg(f"JOIN_QUEUE|{role}")

        confirmed_role = run_waiting_room(role)
        if confirmed_role is None:
            continue   # player cancelled → back to lobby

        winner = run_game(username, confirmed_role)

        if (winner == "thieves" and confirmed_role == "thief") or \
           (winner == "cops"    and confirmed_role == "cop"):
            wins += 1
        else:
            losses += 1

        run_game_over(winner, confirmed_role)


if __name__ == "__main__":
    main()
