"""Online Quiz System - Flask + SQLAlchemy (SQLite by default, MySQL via DATABASE_URL)."""
import os, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, abort, render_template
from jinja2 import DictLoader
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
db_url = os.environ.get("DATABASE_URL", "sqlite:///quiz.db")
if db_url.startswith("mysql://"):
    db_url = db_url.replace("mysql://", "mysql+pymysql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
db = SQLAlchemy(app)

GRACE_SECONDS = 30
def now():  # India Standard Time (server may run in UTC)
    return datetime.utcnow() + timedelta(hours=5, minutes=30)

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")  # student/teacher/hod/admin

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    instructions = db.Column(db.Text, default="")
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"))
    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    duration_min = db.Column(db.Integer, default=10)
    marks_per_q = db.Column(db.Integer, default=1)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    max_attempts = db.Column(db.Integer, default=1)
    published = db.Column(db.Boolean, default=False)
    subject = db.relationship("Subject")
    creator = db.relationship("User")
    questions = db.relationship("Question", backref="quiz", cascade="all, delete-orphan")
    attempts = db.relationship("Attempt", backref="quiz", cascade="all, delete-orphan")
    @property
    def total_marks(self): return len(self.questions) * self.marks_per_q

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    qtype = db.Column(db.String(10), default="mcq")  # mcq / tf
    opt_a = db.Column(db.String(300)); opt_b = db.Column(db.String(300))
    opt_c = db.Column(db.String(300)); opt_d = db.Column(db.String(300))
    correct = db.Column(db.String(1), nullable=False)  # a/b/c/d
    def options(self):
        o = [("a", self.opt_a), ("b", self.opt_b), ("c", self.opt_c), ("d", self.opt_d)]
        return [(k, v) for k, v in o if v]

class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    started_at = db.Column(db.DateTime, default=now)
    submitted_at = db.Column(db.DateTime)
    score = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, default=0)
    answers_json = db.Column(db.Text, default="{}")
    late = db.Column(db.Boolean, default=False)
    user = db.relationship("User")
    @property
    def answers(self): return json.loads(self.answers_json or "{}")
    @property
    def deadline(self): return self.started_at + timedelta(minutes=self.quiz.duration_min)

# ---------------- Auth helpers ----------------
def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            u = current_user()
            if not u:
                return redirect(url_for("login"))
            if roles and u.role not in roles:
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco

@app.context_processor
def inject():
    return {"me": current_user(), "now": now}

@app.errorhandler(403)
def forbidden(e): return render_template("msg.html", title="Access denied", msg="You are not allowed to open this page."), 403

# ---------------- Public routes ----------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name, username, pw = request.form["name"].strip(), request.form["username"].strip(), request.form["password"]
        if not (name and username and len(pw) >= 6):
            flash("Fill all fields; password needs at least 6 characters.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
        else:
            db.session.add(User(name=name, username=username, password_hash=generate_password_hash(pw), role="student"))
            db.session.commit()
            flash("Registered! Please login.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(username=request.form["username"].strip()).first()
        if u and check_password_hash(u.password_hash, request.form["password"]):
            session["uid"] = u.id
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required()
def dashboard():
    u = current_user()
    if u.role == "student":
        quizzes = Quiz.query.order_by(Quiz.start_time.desc()).all()
        mine = {}
        for a in Attempt.query.filter_by(user_id=u.id).all():
            mine.setdefault(a.quiz_id, []).append(a)
        return render_template("student.html", quizzes=quizzes, mine=mine)
    if u.role == "teacher":
        quizzes = Quiz.query.filter_by(creator_id=u.id).order_by(Quiz.id.desc()).all()
    else:
        quizzes = Quiz.query.order_by(Quiz.id.desc()).all()
    stats = {"students": User.query.filter_by(role="student").count(), "teachers": User.query.filter_by(role="teacher").count(),
             "quizzes": Quiz.query.count(), "attempts": Attempt.query.filter(Attempt.submitted_at.isnot(None)).count()}
    return render_template("staff.html", quizzes=quizzes, stats=stats, subjects=Subject.query.order_by(Subject.name).all())

# ---------------- Admin ----------------
@app.route("/admin", methods=["GET", "POST"])
@login_required("admin")
def admin():
    if request.method == "POST":
        f = request.form
        if f.get("action") == "subject" and f["name"].strip():
            if not Subject.query.filter_by(name=f["name"].strip()).first():
                db.session.add(Subject(name=f["name"].strip())); db.session.commit()
        elif f.get("action") == "user":
            if User.query.filter_by(username=f["username"].strip()).first() or len(f["password"]) < 6:
                flash("Username exists or password too short.", "danger")
            else:
                db.session.add(User(name=f["name"].strip(), username=f["username"].strip(),
                                    password_hash=generate_password_hash(f["password"]), role=f["role"]))
                db.session.commit(); flash("User created.", "success")
        return redirect(url_for("admin"))
    return render_template("admin.html", users=User.query.order_by(User.role, User.name).all(), subjects=Subject.query.all())

@app.route("/admin/user/<int:uid>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_user(uid):
    u = db.session.get(User, uid)
    if u and u.id != current_user().id:
        Attempt.query.filter_by(user_id=uid).delete()
        Quiz.query.filter_by(creator_id=uid).delete()
        db.session.delete(u); db.session.commit()
    return redirect(url_for("admin"))

@app.route("/admin/subject/<int:sid>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_subject(sid):
    s = db.session.get(Subject, sid)
    if s:
        Quiz.query.filter_by(subject_id=sid).update({"subject_id": None})
        db.session.delete(s); db.session.commit()
    return redirect(url_for("admin"))

# ---------------- Teacher: quiz management ----------------
def parse_dt(s): return datetime.strptime(s, "%Y-%m-%dT%H:%M")

def own_quiz(qid):
    q = db.session.get(Quiz, qid) or abort(404)
    u = current_user()
    if u.role == "teacher" and q.creator_id != u.id: abort(403)
    return q

@app.route("/quiz/new", methods=["GET", "POST"])
@login_required("teacher", "admin")
def quiz_new():
    if request.method == "POST":
        f = request.form
        try:
            q = Quiz(title=f["title"].strip(), instructions=f["instructions"], subject_id=f.get("subject_id") or None,
                     creator_id=current_user().id, duration_min=int(f["duration"]), marks_per_q=int(f["marks"]),
                     max_attempts=int(f["attempts"]), start_time=parse_dt(f["start"]), end_time=parse_dt(f["end"]))
            if q.end_time <= q.start_time or q.duration_min < 1: raise ValueError
        except Exception:
            flash("Please enter valid details (end must be after start).", "danger")
            return render_template("quiz_form.html", subjects=Subject.query.all())
        db.session.add(q); db.session.commit()
        flash("Quiz created. Now add questions.", "success")
        return redirect(url_for("quiz_manage", qid=q.id))
    return render_template("quiz_form.html", subjects=Subject.query.all())

@app.route("/quiz/<int:qid>", methods=["GET", "POST"])
@login_required("teacher", "admin", "hod")
def quiz_manage(qid):
    q = own_quiz(qid) if current_user().role != "hod" else (db.session.get(Quiz, qid) or abort(404))
    if request.method == "POST":
        if current_user().role == "hod": abort(403)
        f = request.form
        qt = f["qtype"]
        if qt == "tf":
            a, b, c, d, correct = "True", "False", None, None, f["correct_tf"]
        else:
            a, b, c, d, correct = f["a"], f["b"], f.get("c") or None, f.get("d") or None, f["correct"]
        if not f["text"].strip() or not (a and b):
            flash("Question and at least two options are required.", "danger")
        else:
            db.session.add(Question(quiz_id=q.id, text=f["text"].strip(), qtype=qt, opt_a=a, opt_b=b, opt_c=c, opt_d=d, correct=correct))
            db.session.commit(); flash("Question added.", "success")
        return redirect(url_for("quiz_manage", qid=q.id))
    done = Attempt.query.filter(Attempt.quiz_id == q.id, Attempt.submitted_at.isnot(None)).order_by(Attempt.score.desc()).all()
    return render_template("quiz_manage.html", q=q, done=done)

@app.route("/quiz/<int:qid>/publish", methods=["POST"])
@login_required("teacher", "admin")
def quiz_publish(qid):
    q = own_quiz(qid); q.published = not q.published; db.session.commit()
    return redirect(url_for("quiz_manage", qid=qid))

@app.route("/quiz/<int:qid>/delete", methods=["POST"])
@login_required("teacher", "admin")
def quiz_delete(qid):
    q = own_quiz(qid); db.session.delete(q); db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/question/<int:id>/delete", methods=["POST"])
@login_required("teacher", "admin")
def question_delete(id):
    qs = db.session.get(Question, id) or abort(404)
    qid = qs.quiz_id; own_quiz(qid)
    db.session.delete(qs); db.session.commit()
    return redirect(url_for("quiz_manage", qid=qid))

@app.route("/quiz/<int:qid>/export")
@login_required("teacher", "admin", "hod")
def quiz_export(qid):
    q = db.session.get(Quiz, qid) or abort(404)
    rows = ["Student,Username,Score,Total,Submitted,Late"]
    for a in Attempt.query.filter(Attempt.quiz_id == qid, Attempt.submitted_at.isnot(None)).all():
        rows.append(f'"{a.user.name}",{a.user.username},{a.score},{a.total},{a.submitted_at:%Y-%m-%d %H:%M},{"yes" if a.late else "no"}')
    return ("\n".join(rows), 200, {"Content-Type": "text/csv", "Content-Disposition": f"attachment; filename=quiz_{q.id}_results.csv"})

# ---------------- Student: attempt ----------------
@app.route("/quiz/<int:qid>/start", methods=["GET", "POST"])
@login_required("student")
def quiz_start(qid):
    q = db.session.get(Quiz, qid) or abort(404)
    u = current_user()
    t = now()
    open_attempt = Attempt.query.filter_by(quiz_id=qid, user_id=u.id, submitted_at=None).first()
    if open_attempt and open_attempt.deadline + timedelta(seconds=GRACE_SECONDS) > t:
        return redirect(url_for("attempt", aid=open_attempt.id))
    used = Attempt.query.filter(Attempt.quiz_id == qid, Attempt.user_id == u.id).count()
    err = None
    if not q.questions: err = "This quiz has no questions yet."
    elif t < q.start_time: err = f"Quiz opens on {q.start_time:%d %b %Y, %I:%M %p}."
    elif t > q.end_time: err = "This quiz is closed."
    elif used >= q.max_attempts: err = "You have already used all attempts for this quiz."
    if err: return render_template("msg.html", title="Cannot start quiz", msg=err)
    if request.method == "POST":
        a = Attempt(quiz_id=qid, user_id=u.id, started_at=t, total=q.total_marks)
        db.session.add(a); db.session.commit()
        return redirect(url_for("attempt", aid=a.id))
    return render_template("quiz_intro.html", q=q)

@app.route("/attempt/<int:aid>")
@login_required("student")
def attempt(aid):
    a = db.session.get(Attempt, aid) or abort(404)
    if a.user_id != current_user().id: abort(403)
    if a.submitted_at: return redirect(url_for("result", aid=aid))
    remaining = int((a.deadline - now()).total_seconds())
    if remaining < -GRACE_SECONDS: return redirect(url_for("submit", aid=aid), code=307)
    return render_template("attempt.html", a=a, q=a.quiz, remaining=max(remaining, 0))

@app.route("/attempt/<int:aid>/submit", methods=["POST"])
@login_required("student")
def submit(aid):
    a = db.session.get(Attempt, aid) or abort(404)
    if a.user_id != current_user().id: abort(403)
    if a.submitted_at: return redirect(url_for("result", aid=aid))
    t = now()
    a.late = t > a.deadline + timedelta(seconds=GRACE_SECONDS)
    ans, score = {}, 0
    if not a.late:  # answers after time + grace are not accepted
        for qu in a.quiz.questions:
            ch = request.form.get(f"q{qu.id}")
            if ch in ("a", "b", "c", "d"):
                ans[str(qu.id)] = ch
                if ch == qu.correct: score += a.quiz.marks_per_q
    a.answers_json, a.score, a.total, a.submitted_at = json.dumps(ans), score, a.quiz.total_marks, t
    db.session.commit()
    return redirect(url_for("result", aid=aid))

@app.route("/attempt/<int:aid>/result")
@login_required("student", "teacher", "admin", "hod")
def result(aid):
    a = db.session.get(Attempt, aid) or abort(404)
    u = current_user()
    if u.role == "student" and a.user_id != u.id: abort(403)
    if not a.submitted_at: return redirect(url_for("attempt", aid=aid))
    visible = a.quiz.published or u.role != "student"
    return render_template("result.html", a=a, q=a.quiz, visible=visible)

# ---------------- Templates ----------------
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Online Quiz System</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#f4f6fb}.card{border:0;box-shadow:0 2px 10px rgba(0,0,0,.06)}</style></head><body>
<nav class="navbar navbar-dark bg-primary mb-4"><div class="container">
<a class="navbar-brand fw-bold" href="/">🎓 Online Quiz System</a>
{% if me %}<div class="text-white small">{{ me.name }} <span class="badge bg-light text-primary">{{ me.role|upper }}</span>
{% if me.role=='admin' %}<a class="btn btn-sm btn-outline-light ms-2" href="/admin">Admin</a>{% endif %}
<a class="btn btn-sm btn-light ms-2" href="/logout">Logout</a></div>{% endif %}</div></nav>
<div class="container pb-5">
{% with m = get_flashed_messages(with_categories=true) %}{% for c,t in m %}<div class="alert alert-{{c}}">{{t}}</div>{% endfor %}{% endwith %}
{% block body %}{% endblock %}</div></body></html>"""

T = {"base.html": BASE}
T["msg.html"] = """{% extends 'base.html' %}{% block body %}<div class="card p-4 text-center"><h4>{{title}}</h4><p>{{msg}}</p>
<a class="btn btn-primary" href="/dashboard">Back to dashboard</a></div>{% endblock %}"""
T["login.html"] = """{% extends 'base.html' %}{% block body %}<div class="row justify-content-center"><div class="col-md-5"><div class="card p-4">
<h4 class="mb-3">Login</h4><form method="post"><input class="form-control mb-3" name="username" placeholder="Username" required>
<input class="form-control mb-3" type="password" name="password" placeholder="Password" required>
<button class="btn btn-primary w-100">Login</button></form>
<p class="mt-3 mb-0 small">New student? <a href="/register">Register here</a></p></div></div></div>{% endblock %}"""
T["register.html"] = """{% extends 'base.html' %}{% block body %}<div class="row justify-content-center"><div class="col-md-5"><div class="card p-4">
<h4 class="mb-3">Student Registration</h4><form method="post"><input class="form-control mb-3" name="name" placeholder="Full name" required>
<input class="form-control mb-3" name="username" placeholder="Username" required>
<input class="form-control mb-3" type="password" name="password" placeholder="Password (min 6 chars)" required>
<button class="btn btn-success w-100">Register</button></form></div></div></div>{% endblock %}"""
T["student.html"] = """{% extends 'base.html' %}{% block body %}<h4>Available Quizzes</h4><div class="row g-3 mt-1">
{% for q in quizzes %}{% set t=now() %}{% set my=mine.get(q.id,[]) %}<div class="col-md-6"><div class="card p-3 h-100">
<h5>{{q.title}}</h5><div class="text-muted small mb-2">{{q.subject.name if q.subject else 'General'}} · {{q.questions|length}} questions · {{q.duration_min}} min · {{q.total_marks}} marks</div>
<div class="small mb-2">Window: {{q.start_time.strftime('%d %b %I:%M %p')}} → {{q.end_time.strftime('%d %b %I:%M %p')}}</div>
{% for a in my if a.submitted_at %}<div class="small">Attempt {{loop.index}}: {% if q.published %}<b>{{a.score}}/{{a.total}}</b>{% else %}awaiting result{% endif %}
 · <a href="/attempt/{{a.id}}/result">view</a></div>{% endfor %}
<div class="mt-auto pt-2">{% if t<q.start_time %}<span class="badge bg-secondary">Not open yet</span>
{% elif t>q.end_time %}<span class="badge bg-dark">Closed</span>
{% else %}<a class="btn btn-primary btn-sm" href="/quiz/{{q.id}}/start">Open quiz</a>{% endif %}</div></div></div>
{% else %}<p class="text-muted">No quizzes yet.</p>{% endfor %}</div>{% endblock %}"""
T["quiz_intro.html"] = """{% extends 'base.html' %}{% block body %}<div class="card p-4"><h4>{{q.title}}</h4>
<p>{{q.instructions or 'Answer all questions and submit before the timer ends.'}}</p>
<ul><li>Questions: {{q.questions|length}}</li><li>Time: {{q.duration_min}} minutes</li><li>Marks: {{q.total_marks}}</li><li>Attempts allowed: {{q.max_attempts}}</li></ul>
<form method="post"><button class="btn btn-success">Start Quiz (timer begins)</button></form></div>{% endblock %}"""
T["attempt.html"] = """{% extends 'base.html' %}{% block body %}
<div class="position-sticky top-0 bg-white p-2 mb-3 rounded shadow-sm d-flex justify-content-between" style="z-index:5">
<b>{{q.title}}</b><b>⏱ <span id="t" class="text-danger">--:--</span></b></div>
<form method="post" action="/attempt/{{a.id}}/submit" id="f">
{% for qu in q.questions %}<div class="card p-3 mb-3"><b>Q{{loop.index}}. {{qu.text}}</b>
{% for k,v in qu.options() %}<div class="form-check mt-2"><input class="form-check-input" type="radio" name="q{{qu.id}}" value="{{k}}" id="{{qu.id}}{{k}}">
<label class="form-check-label" for="{{qu.id}}{{k}}">{{v}}</label></div>{% endfor %}</div>{% endfor %}
<button class="btn btn-primary btn-lg" onclick="return confirm('Submit quiz?')">Submit</button></form>
<script>
let left={{remaining}};const key='quiz_{{a.id}}',f=document.getElementById('f');
try{const s=JSON.parse(localStorage.getItem(key)||'{}');for(const n in s){const e=f.querySelector(`[name="${n}"][value="${s[n]}"]`);if(e)e.checked=true}}catch(e){}
f.addEventListener('change',()=>{const s={};new FormData(f).forEach((v,k)=>s[k]=v);localStorage.setItem(key,JSON.stringify(s))});
function tick(){const m=Math.floor(left/60),s=left%60;document.getElementById('t').textContent=String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
if(left<=0){localStorage.removeItem(key);f.submit();return}left--;setTimeout(tick,1000)}tick();
</script>{% endblock %}"""
T["result.html"] = """{% extends 'base.html' %}{% block body %}<div class="card p-4 mb-3 text-center"><h4>{{q.title}}</h4>
{% if visible %}<h1 class="display-4">{{a.score}} / {{a.total}}</h1><p class="text-muted">{{a.user.name}}{% if a.late %} · submitted late (answers not counted){% endif %}</p>
{% else %}<p class="lead">✅ Submitted successfully. Your result will be visible once your teacher publishes it.</p>{% endif %}
<a href="/dashboard" class="btn btn-primary mx-auto">Back</a></div>
{% if visible %}{% for qu in q.questions %}{% set ch=a.answers.get(qu.id|string) %}<div class="card p-3 mb-2 border-start border-4 {{'border-success' if ch==qu.correct else 'border-danger'}}">
<b>Q{{loop.index}}. {{qu.text}}</b><div class="small mt-1">Your answer: {{ (qu.options()|selectattr(0,'equalto',ch)|list|first)[1] if ch else 'Not answered' }}
 · Correct: {{ (qu.options()|selectattr(0,'equalto',qu.correct)|list|first)[1] }}</div></div>{% endfor %}{% endif %}{% endblock %}"""
T["staff.html"] = """{% extends 'base.html' %}{% block body %}<div class="row g-3 mb-4">
{% for k,v in stats.items() %}<div class="col-6 col-md-3"><div class="card p-3 text-center"><div class="h3 mb-0">{{v}}</div><div class="text-muted text-capitalize">{{k}}</div></div></div>{% endfor %}</div>
<div class="d-flex justify-content-between mb-2"><h4>Quizzes</h4>{% if me.role in ['teacher','admin'] %}<a class="btn btn-primary" href="/quiz/new">+ Create Quiz</a>{% endif %}</div>
<div class="card"><table class="table mb-0"><tr><th>Title</th><th>Subject</th><th>Questions</th><th>Attempts</th><th>Status</th><th></th></tr>
{% for q in quizzes %}<tr><td>{{q.title}}</td><td>{{q.subject.name if q.subject else '-'}}</td><td>{{q.questions|length}}</td><td>{{q.attempts|length}}</td>
<td>{{'Published' if q.published else 'Draft'}}</td><td><a class="btn btn-sm btn-outline-primary" href="/quiz/{{q.id}}">Open</a></td></tr>
{% else %}<tr><td colspan="6" class="text-muted">No quizzes yet.</td></tr>{% endfor %}</table></div>{% endblock %}"""
T["quiz_form.html"] = """{% extends 'base.html' %}{% block body %}<div class="card p-4"><h4>Create Quiz</h4><form method="post" class="row g-3">
<div class="col-md-8"><label>Title</label><input class="form-control" name="title" required></div>
<div class="col-md-4"><label>Subject</label><select class="form-select" name="subject_id"><option value="">General</option>{% for s in subjects %}<option value="{{s.id}}">{{s.name}}</option>{% endfor %}</select></div>
<div class="col-12"><label>Instructions</label><textarea class="form-control" name="instructions" rows="2"></textarea></div>
<div class="col-md-3"><label>Duration (min)</label><input class="form-control" type="number" name="duration" value="10" min="1" required></div>
<div class="col-md-3"><label>Marks / question</label><input class="form-control" type="number" name="marks" value="1" min="1" required></div>
<div class="col-md-3"><label>Max attempts</label><input class="form-control" type="number" name="attempts" value="1" min="1" required></div><div class="col-md-3"></div>
<div class="col-md-6"><label>Available from</label><input class="form-control" type="datetime-local" name="start" required></div>
<div class="col-md-6"><label>Available until</label><input class="form-control" type="datetime-local" name="end" required></div>
<div class="col-12"><button class="btn btn-success">Create</button></div></form></div>{% endblock %}"""
T["quiz_manage.html"] = """{% extends 'base.html' %}{% block body %}<div class="d-flex justify-content-between align-items-center mb-3"><div><h4 class="mb-0">{{q.title}}</h4>
<small class="text-muted">{{q.duration_min}} min · {{q.total_marks}} marks · {{q.start_time.strftime('%d %b %I:%M %p')}} → {{q.end_time.strftime('%d %b %I:%M %p')}}</small></div>
{% if me.role!='hod' %}<div class="d-flex gap-2"><form method="post" action="/quiz/{{q.id}}/publish"><button class="btn btn-{{'warning' if q.published else 'success'}}">{{'Unpublish results' if q.published else 'Publish results'}}</button></form>
<form method="post" action="/quiz/{{q.id}}/delete" onsubmit="return confirm('Delete quiz?')"><button class="btn btn-outline-danger">Delete</button></form></div>{% endif %}</div>
<div class="row g-3"><div class="col-lg-6">
{% if me.role!='hod' %}<div class="card p-3 mb-3"><h5>Add Question</h5><form method="post">
<textarea class="form-control mb-2" name="text" placeholder="Question" required></textarea>
<select class="form-select mb-2" name="qtype" id="qt" onchange="tg()"><option value="mcq">Multiple choice</option><option value="tf">True / False</option></select>
<div id="mcq">{% for k in 'abcd' %}<input class="form-control mb-2" name="{{k}}" placeholder="Option {{k|upper}}{{' (optional)' if k in 'cd' else ''}}">{% endfor %}
<select class="form-select mb-2" name="correct">{% for k in 'abcd' %}<option value="{{k}}">Correct: {{k|upper}}</option>{% endfor %}</select></div>
<div id="tf" style="display:none"><select class="form-select mb-2" name="correct_tf"><option value="a">Correct: True</option><option value="b">Correct: False</option></select></div>
<button class="btn btn-primary">Add</button></form></div>
<script>function tg(){const t=document.getElementById('qt').value=='tf';document.getElementById('mcq').style.display=t?'none':'block';document.getElementById('tf').style.display=t?'block':'none'}</script>{% endif %}
<h5>Questions ({{q.questions|length}})</h5>{% for qu in q.questions %}<div class="card p-3 mb-2"><b>{{loop.index}}. {{qu.text}}</b>
<ul class="small mb-1">{% for k,v in qu.options() %}<li {% if k==qu.correct %}class="text-success fw-bold"{% endif %}>{{v}}</li>{% endfor %}</ul>
{% if me.role!='hod' %}<form method="post" action="/question/{{qu.id}}/delete"><button class="btn btn-sm btn-outline-danger">Remove</button></form>{% endif %}</div>{% endfor %}</div>
<div class="col-lg-6"><div class="d-flex justify-content-between"><h5>Submissions ({{done|length}})</h5><a class="btn btn-sm btn-outline-secondary" href="/quiz/{{q.id}}/export">Download CSV</a></div>
<div class="card"><table class="table mb-0"><tr><th>Student</th><th>Score</th><th>Submitted</th><th></th></tr>
{% for a in done %}<tr><td>{{a.user.name}}</td><td>{{a.score}}/{{a.total}}</td><td>{{a.submitted_at.strftime('%d %b %H:%M')}}{{' (late)' if a.late}}</td><td><a href="/attempt/{{a.id}}/result">review</a></td></tr>
{% else %}<tr><td colspan="4" class="text-muted">No submissions yet.</td></tr>{% endfor %}</table></div></div></div>{% endblock %}"""
T["admin.html"] = """{% extends 'base.html' %}{% block body %}<div class="row g-3"><div class="col-lg-8"><h4>Users</h4><div class="card"><table class="table mb-0"><tr><th>Name</th><th>Username</th><th>Role</th><th></th></tr>
{% for u in users %}<tr><td>{{u.name}}</td><td>{{u.username}}</td><td>{{u.role}}</td><td>{% if u.id!=me.id %}<form method="post" action="/admin/user/{{u.id}}/delete" onsubmit="return confirm('Delete user?')"><button class="btn btn-sm btn-outline-danger">Delete</button></form>{% endif %}</td></tr>{% endfor %}</table></div></div>
<div class="col-lg-4"><div class="card p-3 mb-3"><h5>Add user</h5><form method="post"><input type="hidden" name="action" value="user">
<input class="form-control mb-2" name="name" placeholder="Full name" required><input class="form-control mb-2" name="username" placeholder="Username" required>
<input class="form-control mb-2" type="password" name="password" placeholder="Password" required>
<select class="form-select mb-2" name="role"><option>teacher</option><option>hod</option><option>student</option><option>admin</option></select><button class="btn btn-primary">Create</button></form></div>
<div class="card p-3"><h5>Subjects</h5><form method="post" class="d-flex gap-2 mb-2"><input type="hidden" name="action" value="subject"><input class="form-control" name="name" placeholder="New subject" required><button class="btn btn-success">Add</button></form>
{% for s in subjects %}<form method="post" action="/admin/subject/{{s.id}}/delete" class="d-flex justify-content-between border-top py-1">{{s.name}}<button class="btn btn-sm text-danger">✕</button></form>{% endfor %}</div></div></div>{% endblock %}"""
app.jinja_loader = DictLoader(T)

# ---------------- Startup ----------------
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role="admin").first():
            db.session.add(User(name="Administrator", username="admin", role="admin",
                                password_hash=generate_password_hash(os.environ.get("ADMIN_PASSWORD", "Admin@123"))))
            for s in ["Python", "Mathematics", "General Knowledge"]:
                db.session.add(Subject(name=s))
            db.session.commit()
init_db()

if __name__ == "__main__":
    app.run(debug=True)
