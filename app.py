from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from flask_socketio import SocketIO, emit, join_room
import sqlite3
import bcrypt

# ================== 基本設定 ==================
app = Flask(__name__)
app.secret_key = 'dev_key'
socketio = SocketIO(app, async_mode='threading')

DATABASE = 'users.db'


# ================== DB 工具 ==================
def get_db():
    # check_same_thread=False：SocketIO threading 模式下較安全
    return sqlite3.connect(DATABASE, check_same_thread=False)


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS friends (
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        UNIQUE(user_id, friend_id)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(sender_id, receiver_id)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS blocked_users (
        user_id INTEGER NOT NULL,
        blocked_id INTEGER NOT NULL,
        UNIQUE(user_id, blocked_id)
    )
    """)

    # ✅ 統一 messages 欄位：sender_id
    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        room TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def cleanup_expired_requests(conn: sqlite3.Connection):
    """清掉 24 小時前的邀請（讓資料庫保持乾淨）"""
    c = conn.cursor()
    c.execute("""
        DELETE FROM friend_requests
        WHERE datetime(created_at) <= datetime('now', '-24 hours')
    """)


# ================== Login ==================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id_, username):
        self.id = id_
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1])
    return None


# ================== Auth ==================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('兩次密碼不一致', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('密碼至少 6 碼', 'danger')
            return redirect(url_for('register'))

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        try:
            conn = get_db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed)
            )
            conn.commit()
            flash('註冊成功，請登入', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('使用者名稱已存在', 'danger')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if row and bcrypt.checkpw(password.encode(), row[1].encode()):
            login_user(User(row[0], username))
            flash('登入成功', 'success')
            return redirect(url_for('chat'))

        flash('帳號或密碼錯誤', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ================== 邀請/好友/封鎖 ==================

@app.route('/send_friend_request', methods=['POST'])
@login_required
def send_friend_request():
    data = request.get_json(force=True)
    receiver_id = data.get('friend_id')

    if not receiver_id:
        return jsonify({'error': 'no receiver'}), 400

    if int(receiver_id) == int(current_user.id):
        return jsonify({'error': 'cannot invite self'}), 400

    conn = get_db()
    c = conn.cursor()

    # 清理過期邀請（含全域）
    cleanup_expired_requests(conn)

    # 對方是否封鎖我
    c.execute("""
        SELECT 1 FROM blocked_users
        WHERE user_id=? AND blocked_id=?
    """, (receiver_id, current_user.id))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'blocked'}), 403

    # 我是否封鎖對方（封鎖了就不應該邀請）
    c.execute("""
        SELECT 1 FROM blocked_users
        WHERE user_id=? AND blocked_id=?
    """, (current_user.id, receiver_id))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'you_blocked_user'}), 400

    # 已是好友就不處理
    c.execute("""
        SELECT 1 FROM friends
        WHERE user_id=? AND friend_id=?
    """, (current_user.id, receiver_id))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'already friends'}), 400

    # 已存在「任一方向」未過期邀請 → 不重複建立
    c.execute("""
        SELECT 1
        FROM friend_requests
        WHERE (
            (sender_id=? AND receiver_id=?)
            OR
            (sender_id=? AND receiver_id=?)
        )
          AND datetime(created_at) > datetime('now', '-24 hours')
    """, (current_user.id, receiver_id, receiver_id, current_user.id))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'request exists'}), 400

    # 建立邀請
    c.execute("""
        INSERT OR IGNORE INTO friend_requests (sender_id, receiver_id)
        VALUES (?, ?)
    """, (current_user.id, receiver_id))

    conn.commit()
    conn.close()

    # 🔔 即時通知對方（讓他 badge + 邀請頁刷新）
    socketio.emit('friend_request_received', room=f"user_{receiver_id}")
    return jsonify({'success': True})


@app.route('/friend_requests_page')
@login_required
def friend_requests_page():
    return render_template('friend_requests.html')


@app.route('/friend_request_count')
@login_required
def friend_request_count():
    conn = get_db()
    c = conn.cursor()

    cleanup_expired_requests(conn)
    conn.commit()

    c.execute("""
        SELECT COUNT(*)
        FROM friend_requests
        WHERE receiver_id = ?
          AND datetime(created_at) > datetime('now', '-24 hours')
    """, (current_user.id,))
    count = c.fetchone()[0]

    conn.close()
    return jsonify({'count': count})


@app.route('/friend_requests')
@login_required
def friend_requests():
    conn = get_db()
    c = conn.cursor()

    cleanup_expired_requests(conn)
    conn.commit()

    c.execute("""
        SELECT fr.id, u.id, u.username,
       strftime('%s', 'now') - strftime('%s', fr.created_at) AS seconds_passed
FROM friend_requests fr
JOIN users u ON fr.sender_id = u.id
WHERE fr.receiver_id = ?
    """, (current_user.id,))

    data = [
        {
            'request_id': r[0],
            'user_id': r[1],
            'username': r[2],
            'created_at': r[3],
        }
        for r in c.fetchall()
    ]

    conn.close()
    return jsonify(data)





@app.route('/accept_friend_request', methods=['POST'])
@login_required
def accept_friend_request():
    data = request.get_json(force=True)
    request_id = data.get('request_id')

    conn = get_db()
    c = conn.cursor()

    # ① 找出邀請者
    c.execute("""
        SELECT sender_id
        FROM friend_requests
        WHERE id=? AND receiver_id=?
    """, (request_id, current_user.id))

    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'not found'}), 404

    sender_id = row[0]

    # ② 雙向加好友
    c.execute(
        "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
        (current_user.id, sender_id)
    )
    c.execute(
        "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
        (sender_id, current_user.id)
    )

    # ③ 清掉雙向邀請
    c.execute("""
        DELETE FROM friend_requests
        WHERE (sender_id=? AND receiver_id=?)
           OR (sender_id=? AND receiver_id=?)
    """, (
        sender_id, current_user.id,
        current_user.id, sender_id
    ))

    conn.commit()
    conn.close()

    # ✅ 關鍵：通知「雙方」
    socketio.emit('friends_updated', room=f"user_{current_user.id}")
    socketio.emit('friends_updated', room=f"user_{sender_id}")

    # 🔔 更新 badge
    socketio.emit('friend_request_received', room=f"user_{current_user.id}")

    return jsonify({'success': True})


@app.route('/friends')
@login_required
def friends():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT u.id, u.username
        FROM friends f
        JOIN users u ON f.friend_id = u.id
        WHERE f.user_id = ?
        ORDER BY u.username COLLATE NOCASE
    """, (current_user.id,))
    data = [{'id': r[0], 'username': r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify(data)


@app.route('/remove_friend', methods=['POST'])
@login_required
def remove_friend():
    data = request.get_json(force=True)
    friend_id = data.get('friend_id')

    if not friend_id:
        return jsonify({'error': 'no friend id'}), 400

    conn = get_db()
    c = conn.cursor()

    # 雙向刪除
    c.execute("DELETE FROM friends WHERE user_id=? AND friend_id=?",
              (current_user.id, friend_id))
    c.execute("DELETE FROM friends WHERE user_id=? AND friend_id=?",
              (friend_id, current_user.id))

    conn.commit()
    conn.close()

    socketio.emit('friends_updated', room=f"user_{current_user.id}")
    socketio.emit('friends_updated', room=f"user_{friend_id}")
    return jsonify({'success': True})


@app.route('/block_user', methods=['POST'])
@login_required
def block_user():
    data = request.get_json(force=True)
    target_id = data.get('user_id')

    if not target_id:
        return jsonify({'error': 'no user_id'}), 400

    if int(target_id) == int(current_user.id):
        return jsonify({'error': 'cannot block self'}), 400

    conn = get_db()
    c = conn.cursor()

    # 加入封鎖
    c.execute("""
        INSERT OR IGNORE INTO blocked_users (user_id, blocked_id)
        VALUES (?, ?)
    """, (current_user.id, target_id))

    # 移除好友
    c.execute("DELETE FROM friends WHERE user_id=? AND friend_id=?",
              (current_user.id, target_id))
    c.execute("DELETE FROM friends WHERE user_id=? AND friend_id=?",
              (target_id, current_user.id))

    # 移除邀請（雙向）
    c.execute("DELETE FROM friend_requests WHERE sender_id=? AND receiver_id=?",
              (current_user.id, target_id))
    c.execute("DELETE FROM friend_requests WHERE sender_id=? AND receiver_id=?",
              (target_id, current_user.id))

    conn.commit()
    conn.close()

    # 更新雙方好友列表 & badge
    socketio.emit('friends_updated', room=f"user_{current_user.id}")
    socketio.emit('friends_updated', room=f"user_{target_id}")
    socketio.emit('friend_request_received', room=f"user_{current_user.id}")
    socketio.emit('friend_request_received', room=f"user_{target_id}")

    return jsonify({'success': True})


@app.route('/search_users')
@login_required
def search_users():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])

    conn = get_db()
    c = conn.cursor()

    # 先清掉過期邀請（保證乾淨）
    cleanup_expired_requests(conn)
    conn.commit()

    c.execute("""
        SELECT u.id, u.username
        FROM users u
        WHERE u.username LIKE ?
          AND u.id != ?
          AND NOT EXISTS (
              SELECT 1 FROM friends f
              WHERE f.user_id = ? AND f.friend_id = u.id
          )
          AND NOT EXISTS (
              SELECT 1 FROM friend_requests fr
              WHERE fr.sender_id = ?
                AND fr.receiver_id = u.id
                AND datetime(fr.created_at) > datetime('now', '-24 hours')
          )
        ORDER BY u.username COLLATE NOCASE
        LIMIT 10
    """, (
        f"%{q}%",
        current_user.id,
        current_user.id,
        current_user.id
    ))

    users = [{'id': r[0], 'username': r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify(users)



# ================== 訊息 ==================
@app.route('/messages/<room>')
@login_required
def messages(room):
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT u.username, m.message
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.room=?
        ORDER BY m.id DESC
        LIMIT ? OFFSET ?
    """, (room, per_page, offset))

    rows = c.fetchall()
    conn.close()

    rows.reverse()  # 舊→新
    return jsonify([{'username': r[0], 'message': r[1]} for r in rows])


# ================== SocketIO ==================
@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        join_room(f"user_{current_user.id}")


@socketio.on('send_message')
def send_message(data):
    if not current_user.is_authenticated:
        return

    room = data.get('room', 'global')
    msg = (data.get('message') or '').strip()
    if not msg:
        return

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO messages (sender_id, room, message) VALUES (?, ?, ?)",
        (current_user.id, room, msg)
    )
    conn.commit()
    conn.close()

    join_room(room)
    emit('receive_message', {
        'username': current_user.username,
        'message': msg,
        'room': room
    }, to=room)


# ================== 頁面 ==================
@app.route('/')
@login_required
def chat():
    return render_template('chat.html', username=current_user.username)


# ================== 啟動 ==================
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)
