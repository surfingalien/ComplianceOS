import os
import json
import time
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import FastAPI, Request, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, DateTime, Text, Float, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from pydantic import BaseModel


# ============================================================
# Database
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./compliance_neuralink.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# Models
# ============================================================


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String, primary_key=True, default=new_id)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class Control(Base):
    __tablename__ = "controls"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=False)
    code = Column(String, nullable=False)
    title = Column(String, nullable=False)
    category = Column(String, default="General")
    status = Column(String, default="active")
    created_at = Column(DateTime, default=utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=False)
    control_id = Column(String, nullable=False)
    source = Column(String, default="api")
    payload = Column(Text, nullable=False)
    hash = Column(String, nullable=False)
    quality_score = Column(Float, default=50.0)
    status = Column(String, default="pending_review")
    created_at = Column(DateTime, default=utcnow)


class Test(Base):
    __tablename__ = "tests"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=False)
    control_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    expected_field = Column(String, nullable=False)
    operator = Column(String, default="eq")
    expected_value = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)


class TestRun(Base):
    __tablename__ = "test_runs"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=False)
    test_id = Column(String, nullable=False)
    status = Column(String, nullable=False)
    result = Column(Text)
    created_at = Column(DateTime, default=utcnow)


class Gap(Base):
    __tablename__ = "gaps"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=False)
    control_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    status = Column(String, default="open")
    created_at = Column(DateTime, default=utcnow)


class ReviewItem(Base):
    __tablename__ = "review_items"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=False)
    queue_type = Column(String, default="framework_content")
    title = Column(String, nullable=False)
    status = Column(String, default="pending_triage")
    payload = Column(Text, default="{}")
    created_at = Column(DateTime, default=utcnow)


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id = Column(String, primary_key=True, default=new_id)
    tenant_id = Column(String, nullable=True)
    correlation_id = Column(String, nullable=True)
    flow = Column(String, nullable=False)
    step = Column(String, nullable=False)
    status = Column(String, nullable=False)
    name = Column(String, nullable=False)
    # NOTE: named event_metadata (not "metadata") because SQLAlchemy's
    # Declarative API reserves the "metadata" attribute name on models.
    event_metadata = Column(Text, default="{}")
    created_at = Column(DateTime, default=utcnow)


# ============================================================
# Pydantic Schemas
# ============================================================


class TenantIn(BaseModel):
    name: str


class ControlIn(BaseModel):
    tenant_id: Optional[str] = None
    code: str
    title: str
    category: str = "General"


class EvidenceIn(BaseModel):
    tenant_id: Optional[str] = None
    control_id: str
    source: str = "api"
    payload: dict


class TestIn(BaseModel):
    tenant_id: Optional[str] = None
    control_id: str
    name: str
    expected_field: str
    operator: str = "eq"
    expected_value: Any


class ReviewItemIn(BaseModel):
    tenant_id: Optional[str] = None
    queue_type: str = "framework_content"
    title: str
    payload: dict = {}


class ReviewDecisionIn(BaseModel):
    decision: str
    reason: Optional[str] = None


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="Compliance Neuralink AI Brain",
    version="1.0.0",
    description="Deployable compliance operating system with central AI brain tracking and monitoring.",
)

# NOTE: allow_credentials must stay False while allow_origins is "*" --
# browsers reject (and FastAPI/Starlette will refuse to honor) a wildcard
# origin combined with credentialed requests, and enabling both together
# is a well-known CORS misconfiguration. This API is unauthenticated and
# cookie-free, so no credentialed cross-origin requests are needed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Helpers
# ============================================================


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def serialize(obj):
    if obj is None:
        return None

    data = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}

    for field in ["payload", "event_metadata", "result", "expected_value"]:
        if field in data and isinstance(data[field], str):
            try:
                data[field] = json.loads(data[field])
            except Exception:
                pass

    return data


def ensure_sqlite_directory():
    if DATABASE_URL.startswith("sqlite:///"):
        path = DATABASE_URL.split("sqlite:///", 1)[1]
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)


def get_default_tenant(db: Session) -> Tenant:
    tenant = db.query(Tenant).first()
    if not tenant:
        tenant = Tenant(id=new_id(), name="Default Tenant")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    return tenant


def resolve_tenant(db: Session, tenant_id: Optional[str] = None) -> Tenant:
    if tenant_id:
        tenant = db.get(Tenant, tenant_id)
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")
        return tenant
    return get_default_tenant(db)


def record_event(
    flow: str,
    step: str,
    status: str,
    name: str,
    tenant_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    metadata: Optional[dict] = None,
):
    db = SessionLocal()
    try:
        event = TelemetryEvent(
            id=new_id(),
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            flow=flow,
            step=step,
            status=status,
            name=name,
            event_metadata=json.dumps(metadata or {}),
        )
        db.add(event)
        db.commit()
    except Exception as exc:
        db.rollback()
        print("Telemetry error:", exc)
    finally:
        db.close()


def evaluate_condition(actual: Any, operator: str, expected: Any) -> bool:
    try:
        if operator == "exists":
            return actual is not None

        if operator == "not_exists":
            return actual is None

        if actual is None:
            return False

        if operator == "eq":
            return actual == expected

        if operator == "neq":
            return actual != expected

        if operator == "gt":
            return actual > expected

        if operator == "gte":
            return actual >= expected

        if operator == "lt":
            return actual < expected

        if operator == "lte":
            return actual <= expected

        if operator == "contains":
            return expected in actual

        if operator == "not_contains":
            return expected not in actual

        if operator == "in":
            return actual in expected

        if operator == "not_in":
            return actual not in expected

        return False
    except Exception:
        return False


# ============================================================
# Telemetry Middleware / Neuralink Request Tracing
# ============================================================


@app.middleware("http")
async def neuralink_telemetry_middleware(request: Request, call_next):
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id

    start = time.time()

    record_event(
        flow="api",
        step="request.started",
        status="info",
        name="api.request",
        correlation_id=correlation_id,
        metadata={
            "method": request.method,
            "path": request.url.path,
        },
    )

    response = await call_next(request)

    duration_ms = (time.time() - start) * 1000

    record_event(
        flow="api",
        step="request.completed",
        status="success" if response.status_code < 400 else "error",
        name="api.request",
        correlation_id=correlation_id,
        metadata={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )

    response.headers["X-Correlation-ID"] = correlation_id
    return response


# ============================================================
# Startup
# ============================================================


@app.on_event("startup")
def on_startup():
    ensure_sqlite_directory()
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        get_default_tenant(db)
    finally:
        db.close()


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = """
<!doctype html>
<html>
<head>
  <title>Compliance Neuralink Brain</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      background: #0b1220;
      color: #e5eef8;
    }
    header {
      padding: 20px;
      background: #111827;
      border-bottom: 1px solid #243044;
    }
    h1 {
      margin: 0;
      font-size: 24px;
    }
    .container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      padding: 20px;
    }
    .card {
      background: #111827;
      border: 1px solid #243044;
      border-radius: 12px;
      padding: 16px;
      min-height: 220px;
    }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      color: #93c5fd;
    }
    button {
      background: #2563eb;
      color: white;
      border: 0;
      border-radius: 8px;
      padding: 10px 14px;
      cursor: pointer;
      margin-right: 8px;
    }
    button:hover {
      background: #1d4ed8;
    }
    .toolbar {
      padding: 0 20px 20px;
    }
  </style>
</head>
<body>
  <header>
    <h1>Compliance Neuralink AI Brain</h1>
    <p>Tracking, monitoring, and flow correlation for all compliance operations.</p>
  </header>

  <div class="toolbar">
    <button onclick="seedDemo()">Seed Demo Data</button>
    <button onclick="loadDashboard()">Refresh</button>
  </div>

  <div class="container">
    <div class="card">
      <h2>Metrics</h2>
      <pre id="metrics">Loading...</pre>
    </div>

    <div class="card">
      <h2>Recent Telemetry Events</h2>
      <pre id="events">Loading...</pre>
    </div>
  </div>

  <script>
    async function loadDashboard() {
      try {
        const metrics = await fetch("/v1/brain/metrics").then(r => r.json());
        document.getElementById("metrics").textContent = JSON.stringify(metrics, null, 2);

        const events = await fetch("/v1/brain/events?limit=20").then(r => r.json());
        document.getElementById("events").textContent = JSON.stringify(events, null, 2);
      } catch (error) {
        console.error(error);
      }
    }

    async function seedDemo() {
      await fetch("/v1/seed/demo", { method: "POST" });
      await loadDashboard();
    }

    loadDashboard();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "compliance-neuralink",
        "timestamp": utcnow().isoformat(),
    }


# ============================================================
# Tenant Endpoints
# ============================================================


@app.post("/v1/tenants")
def create_tenant(payload: TenantIn, request: Request, db: Session = Depends(get_db)):
    tenant = Tenant(id=new_id(), name=payload.name)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    record_event(
        flow="tenant",
        step="tenant.created",
        status="success",
        name="tenant.created",
        tenant_id=tenant.id,
        correlation_id=request.state.correlation_id,
        metadata={"tenant_name": tenant.name},
    )

    return serialize(tenant)


@app.get("/v1/tenants")
def list_tenants(db: Session = Depends(get_db)):
    tenants = db.query(Tenant).all()
    return [serialize(tenant) for tenant in tenants]


# ============================================================
# Control Endpoints
# ============================================================


@app.post("/v1/controls")
def create_control(payload: ControlIn, request: Request, db: Session = Depends(get_db)):
    tenant = resolve_tenant(db, payload.tenant_id)

    control = Control(
        id=new_id(),
        tenant_id=tenant.id,
        code=payload.code,
        title=payload.title,
        category=payload.category,
    )

    db.add(control)
    db.commit()
    db.refresh(control)

    record_event(
        flow="controls",
        step="control.created",
        status="success",
        name="control.created",
        tenant_id=tenant.id,
        correlation_id=request.state.correlation_id,
        metadata={"control_id": control.id, "code": control.code},
    )

    return serialize(control)


@app.get("/v1/controls")
def list_controls(
    tenant_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(Control)
    if tenant_id:
        query = query.filter(Control.tenant_id == tenant_id)

    controls = query.all()
    return [serialize(control) for control in controls]


# ============================================================
# Evidence Endpoints
# ============================================================


@app.post("/v1/evidence")
def create_evidence(payload: EvidenceIn, request: Request, db: Session = Depends(get_db)):
    tenant = resolve_tenant(db, payload.tenant_id)

    control = db.get(Control, payload.control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    payload_json = json.dumps(payload.payload, sort_keys=True)
    evidence_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    quality_score = 90.0 if payload.source.lower() == "api" else 50.0

    evidence = Evidence(
        id=new_id(),
        tenant_id=tenant.id,
        control_id=control.id,
        source=payload.source,
        payload=payload_json,
        hash=evidence_hash,
        quality_score=quality_score,
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    record_event(
        flow="evidence",
        step="evidence.collected",
        status="success",
        name="evidence.collected",
        tenant_id=tenant.id,
        correlation_id=request.state.correlation_id,
        metadata={
            "evidence_id": evidence.id,
            "control_id": control.id,
            "quality_score": quality_score,
            "source": evidence.source,
        },
    )

    return serialize(evidence)


@app.get("/v1/evidence")
def list_evidence(
    tenant_id: Optional[str] = Query(default=None),
    control_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(Evidence)

    if tenant_id:
        query = query.filter(Evidence.tenant_id == tenant_id)

    if control_id:
        query = query.filter(Evidence.control_id == control_id)

    evidence_items = query.order_by(Evidence.created_at.desc()).all()
    return [serialize(item) for item in evidence_items]


# ============================================================
# Test Endpoints
# ============================================================


@app.post("/v1/tests")
def create_test(payload: TestIn, request: Request, db: Session = Depends(get_db)):
    tenant = resolve_tenant(db, payload.tenant_id)

    control = db.get(Control, payload.control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    test = Test(
        id=new_id(),
        tenant_id=tenant.id,
        control_id=control.id,
        name=payload.name,
        expected_field=payload.expected_field,
        operator=payload.operator,
        expected_value=json.dumps(payload.expected_value),
    )

    db.add(test)
    db.commit()
    db.refresh(test)

    record_event(
        flow="control_testing",
        step="test.created",
        status="success",
        name="test.created",
        tenant_id=tenant.id,
        correlation_id=request.state.correlation_id,
        metadata={"test_id": test.id, "control_id": control.id},
    )

    return serialize(test)


@app.get("/v1/tests")
def list_tests(
    tenant_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(Test)
    if tenant_id:
        query = query.filter(Test.tenant_id == tenant_id)

    tests = query.all()
    return [serialize(test) for test in tests]


@app.post("/v1/tests/{test_id}/run")
def run_test(test_id: str, request: Request, db: Session = Depends(get_db)):
    test = db.get(Test, test_id)
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")

    evidence = (
        db.query(Evidence)
        .filter(Evidence.control_id == test.control_id)
        .order_by(Evidence.created_at.desc())
        .first()
    )

    if not evidence:
        status = "missing_evidence"
        result = {"reason": "No evidence found for control"}
    else:
        evidence_payload = json.loads(evidence.payload)
        actual = evidence_payload.get(test.expected_field)
        expected = json.loads(test.expected_value)

        passed = evaluate_condition(actual, test.operator, expected)
        status = "pass" if passed else "fail"
        result = {
            "actual": actual,
            "expected": expected,
            "evidence_id": evidence.id,
        }

    run = TestRun(
        id=new_id(),
        tenant_id=test.tenant_id,
        test_id=test.id,
        status=status,
        result=json.dumps(result),
    )

    db.add(run)

    if status != "pass":
        gap = Gap(
            id=new_id(),
            tenant_id=test.tenant_id,
            control_id=test.control_id,
            title=f"Test failed: {test.name}",
            status="open",
        )
        db.add(gap)

        record_event(
            flow="gap_management",
            step="gap.created",
            status="warning",
            name="gap.created",
            tenant_id=test.tenant_id,
            correlation_id=request.state.correlation_id,
            metadata={
                "test_id": test.id,
                "control_id": test.control_id,
                "test_status": status,
            },
        )

    db.commit()
    db.refresh(run)

    record_event(
        flow="control_testing",
        step="test.run.completed",
        status=status,
        name="test.run",
        tenant_id=test.tenant_id,
        correlation_id=request.state.correlation_id,
        metadata={
            "test_id": test.id,
            "control_id": test.control_id,
            "status": status,
        },
    )

    return serialize(run)


# ============================================================
# Gap Endpoints
# ============================================================


@app.get("/v1/gaps")
def list_gaps(
    tenant_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(Gap)
    if tenant_id:
        query = query.filter(Gap.tenant_id == tenant_id)

    gaps = query.order_by(Gap.created_at.desc()).all()
    return [serialize(gap) for gap in gaps]


# ============================================================
# Expert Review Console Endpoints
# ============================================================


@app.post("/v1/review-console/items")
def create_review_item(payload: ReviewItemIn, request: Request, db: Session = Depends(get_db)):
    tenant = resolve_tenant(db, payload.tenant_id)

    item = ReviewItem(
        id=new_id(),
        tenant_id=tenant.id,
        queue_type=payload.queue_type,
        title=payload.title,
        payload=json.dumps(payload.payload),
    )

    db.add(item)
    db.commit()
    db.refresh(item)

    record_event(
        flow="expert_review",
        step="review_item.created",
        status="success",
        name="review_item.created",
        tenant_id=tenant.id,
        correlation_id=request.state.correlation_id,
        metadata={
            "review_item_id": item.id,
            "queue_type": item.queue_type,
        },
    )

    return serialize(item)


@app.get("/v1/review-console/items")
def list_review_items(
    tenant_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(ReviewItem)
    if tenant_id:
        query = query.filter(ReviewItem.tenant_id == tenant_id)

    items = query.order_by(ReviewItem.created_at.desc()).all()
    return [serialize(item) for item in items]


@app.post("/v1/review-console/items/{item_id}/decision")
def review_decision(
    item_id: str,
    payload: ReviewDecisionIn,
    request: Request,
    db: Session = Depends(get_db),
):
    item = db.get(ReviewItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Review item not found")

    decision = payload.decision.lower()

    if decision in ["approved", "published"]:
        item.status = "approved"
    elif decision == "rejected":
        item.status = "rejected"
    elif decision == "deferred":
        item.status = "deferred"
    else:
        item.status = "reviewed"

    item_payload = json.loads(item.payload or "{}")
    item_payload["last_decision"] = {
        "decision": payload.decision,
        "reason": payload.reason,
        "decided_at": utcnow().isoformat(),
    }
    item.payload = json.dumps(item_payload)

    db.commit()
    db.refresh(item)

    record_event(
        flow="expert_review",
        step="review_item.decided",
        status="success",
        name="review_item.decided",
        tenant_id=item.tenant_id,
        correlation_id=request.state.correlation_id,
        metadata={
            "review_item_id": item.id,
            "decision": payload.decision,
            "reason": payload.reason,
        },
    )

    return serialize(item)


# ============================================================
# Neuralink Brain / Observability Endpoints
# ============================================================


@app.get("/v1/brain/health")
def brain_health(db: Session = Depends(get_db)):
    return {
        "status": "ok",
        "database": "connected",
        "events": db.query(TelemetryEvent).count(),
        "timestamp": utcnow().isoformat(),
    }


@app.get("/v1/brain/events")
def brain_events(
    limit: int = Query(default=50, le=500),
    flow: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    query = db.query(TelemetryEvent)

    if flow:
        query = query.filter(TelemetryEvent.flow == flow)

    events = query.order_by(TelemetryEvent.created_at.desc()).limit(limit).all()
    return [serialize(event) for event in events]


@app.get("/v1/brain/flows/{correlation_id}")
def brain_flow(correlation_id: str, db: Session = Depends(get_db)):
    events = (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.correlation_id == correlation_id)
        .order_by(TelemetryEvent.created_at.asc())
        .all()
    )

    return {
        "correlation_id": correlation_id,
        "events": [serialize(event) for event in events],
    }


@app.get("/v1/brain/metrics")
def brain_metrics(db: Session = Depends(get_db)):
    return {
        "tenants": db.query(Tenant).count(),
        "controls": db.query(Control).count(),
        "evidence": db.query(Evidence).count(),
        "tests": db.query(Test).count(),
        "test_runs": db.query(TestRun).count(),
        "gaps": db.query(Gap).count(),
        "review_items": db.query(ReviewItem).count(),
        "telemetry_events": db.query(TelemetryEvent).count(),
        "events_by_flow": dict(
            db.query(TelemetryEvent.flow, func.count(TelemetryEvent.id))
            .group_by(TelemetryEvent.flow)
            .all()
        ),
        "events_by_status": dict(
            db.query(TelemetryEvent.status, func.count(TelemetryEvent.id))
            .group_by(TelemetryEvent.status)
            .all()
        ),
        "timestamp": utcnow().isoformat(),
    }


# ============================================================
# Demo Seed Endpoint
# ============================================================


@app.post("/v1/seed/demo")
def seed_demo(request: Request, db: Session = Depends(get_db)):
    tenant = get_default_tenant(db)

    control = Control(
        id=new_id(),
        tenant_id=tenant.id,
        code="AC-001",
        title="Multi-Factor Authentication for Production Access",
        category="Access Control",
    )
    db.add(control)
    db.commit()
    db.refresh(control)

    evidence_payload = {
        "total_users": 142,
        "active_users": 142,
        "users_without_mfa": 0,
    }

    evidence_payload_json = json.dumps(evidence_payload, sort_keys=True)
    evidence_hash = hashlib.sha256(evidence_payload_json.encode("utf-8")).hexdigest()

    evidence = Evidence(
        id=new_id(),
        tenant_id=tenant.id,
        control_id=control.id,
        source="okta",
        payload=evidence_payload_json,
        hash=evidence_hash,
        quality_score=92.0,
        status="approved",
    )
    db.add(evidence)

    test = Test(
        id=new_id(),
        tenant_id=tenant.id,
        control_id=control.id,
        name="All active users have MFA",
        expected_field="users_without_mfa",
        operator="eq",
        expected_value=json.dumps(0),
    )
    db.add(test)

    db.commit()
    db.refresh(test)

    run = TestRun(
        id=new_id(),
        tenant_id=tenant.id,
        test_id=test.id,
        status="pass",
        result=json.dumps({"actual": 0, "expected": 0}),
    )
    db.add(run)

    review_item = ReviewItem(
        id=new_id(),
        tenant_id=tenant.id,
        queue_type="matrix_proposal",
        title="Review Colorado breach notification threshold update",
        payload=json.dumps(
            {
                "state_code": "CO",
                "proposed_change": {
                    "regulator_threshold": "250_residents",
                    "individual_deadline_days": 30
                },
                "confidence": 0.87,
                "legal_review_required": True,
            }
        ),
    )
    db.add(review_item)

    db.commit()

    record_event(
        flow="demo",
        step="demo.seeded",
        status="success",
        name="demo.seeded",
        tenant_id=tenant.id,
        correlation_id=request.state.correlation_id,
        metadata={
            "control_id": control.id,
            "evidence_id": evidence.id,
            "test_id": test.id,
            "review_item_id": review_item.id,
        },
    )

    return {
        "status": "demo seeded",
        "tenant_id": tenant.id,
        "control_id": control.id,
        "evidence_id": evidence.id,
        "test_id": test.id,
        "review_item_id": review_item.id,
    }
