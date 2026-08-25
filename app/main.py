import os
import json
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends, Query, Header, Body
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, DateTime, Text, Float, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session


# ============================================================
# Database
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./compliance_os.db")
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def new_id():
    return str(uuid.uuid4())


def utcnow():
    return datetime.now(timezone.utc)


# ============================================================
# Mixins
# ============================================================

class IdMixin:
    id = Column(String, primary_key=True, default=new_id)


class TimeMixin:
    created_at = Column(DateTime, default=utcnow)


class TenantMixin:
    tenant_id = Column(String, nullable=True)


# ============================================================
# Models: Tenant/Auth/Pricing
# ============================================================

class Tenant(Base, IdMixin, TimeMixin):
    __tablename__ = "tenants"
    name = Column(String, nullable=True)
    plan = Column(String, default="enterprise")


class ApiKey(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "api_keys"
    key = Column(String, nullable=False)
    scopes = Column(Text, default="[]")


class PlanEntitlement(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "plan_entitlements"
    module = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    limit_value = Column(Float, nullable=True)


# ============================================================
# Models: Frameworks/Controls/Breach Matrix
# ============================================================

class Framework(Base, IdMixin, TimeMixin):
    __tablename__ = "frameworks"
    code = Column(String, nullable=False)
    name = Column(String, nullable=False)


class Control(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "controls"
    code = Column(String, nullable=True)
    title = Column(String, nullable=True)
    category = Column(String, default="General")
    risk_level = Column(String, default="medium")
    status = Column(String, default="active")


class ControlMapping(Base, IdMixin, TimeMixin):
    __tablename__ = "control_mappings"
    control_id = Column(String, nullable=False)
    framework_id = Column(String, nullable=False)
    requirement = Column(String, nullable=True)


class BreachMatrix(Base, IdMixin, TimeMixin):
    __tablename__ = "breach_matrix"
    state_code = Column(String, nullable=False)
    state_name = Column(String, nullable=False)
    statute = Column(Text, nullable=True)
    individual_days = Column(Float, nullable=True)
    regulator_notice = Column(String, default="conditional")
    regulator_days = Column(Float, nullable=True)
    regulator_threshold = Column(String, nullable=True)
    legal_review_required = Column(Boolean, default=True)


# ============================================================
# Models: Evidence/Testing/Gaps
# ============================================================

class Evidence(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "evidence"
    control_id = Column(String, nullable=True)
    connector = Column(String, default="manual")
    payload = Column(Text, nullable=True)
    hash = Column(String, nullable=True)
    quality_score = Column(Float, default=0.0)
    status = Column(String, default="collected")


class Test(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "tests"
    control_id = Column(String, nullable=True)
    name = Column(String, nullable=True)
    expected_field = Column(String, nullable=True)
    operator = Column(String, default="eq")
    expected_value = Column(Text, nullable=True)


class TestRun(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "test_runs"
    test_id = Column(String, nullable=True)
    status = Column(String, nullable=True)
    result = Column(Text, nullable=True)


class Gap(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "gaps"
    control_id = Column(String, nullable=True)
    title = Column(String, nullable=True)
    severity = Column(String, default="medium")
    status = Column(String, default="open")


class RemediationTask(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "remediation_tasks"
    gap_id = Column(String, nullable=True)
    title = Column(String, nullable=True)
    owner = Column(String, nullable=True)
    status = Column(String, default="open")


# ============================================================
# Models: Policy AI
# ============================================================

class Policy(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "policies"
    title = Column(String, nullable=True)
    policy_type = Column(String, default="security")
    version = Column(String, default="1.0")
    status = Column(String, default="draft")


class PolicyVersion(Base, IdMixin, TimeMixin):
    __tablename__ = "policy_versions"
    policy_id = Column(String, nullable=False)
    version = Column(String, default="1.0")
    content = Column(Text, nullable=True)


# ============================================================
# Models: Questionnaire AI / Answer Library
# ============================================================

class AnswerLibrary(Base, IdMixin, TimeMixin):
    __tablename__ = "answer_library"
    key = Column(String, nullable=True)
    question = Column(Text, nullable=True)
    answer = Column(Text, nullable=True)
    source_type = Column(String, default="policy")
    weight = Column(Float, default=1.0)
    status = Column(String, default="approved")


class RetrievalConfig(Base, IdMixin, TimeMixin):
    __tablename__ = "retrieval_config"
    auto_threshold = Column(Float, default=0.75)
    review_threshold = Column(Float, default=0.45)
    source_weights = Column(Text, default="{}")


class Questionnaire(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "questionnaires"
    customer = Column(String, nullable=True)
    status = Column(String, default="imported")
    total_questions = Column(Float, default=0)
    auto_answered = Column(Float, default=0)
    needs_review = Column(Float, default=0)


class QuestionnaireAnswer(Base, IdMixin, TimeMixin):
    __tablename__ = "questionnaire_answers"
    questionnaire_id = Column(String, nullable=True)
    question = Column(Text, nullable=True)
    answer = Column(Text, nullable=True)
    confidence = Column(Float, default=0.0)
    status = Column(String, default="draft")
    sources = Column(Text, default="[]")


class QuestionnaireFeedback(Base, IdMixin, TimeMixin):
    __tablename__ = "questionnaire_feedback"
    answer_id = Column(String, nullable=True)
    question = Column(Text, nullable=True)
    feedback_type = Column(String, default="rejected")
    reason = Column(String, nullable=True)
    applied = Column(Boolean, default=False)


# ============================================================
# Models: DSAR / Workflow Satisfaction / Auditor Evidence Chain
# ============================================================

class DSARRequest(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "dsar_requests"
    request_type = Column(String, default="access")
    requester_email = Column(String, nullable=True)
    status = Column(String, default="received")
    due_date = Column(String, nullable=True)


class WorkflowSatisfaction(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "workflow_satisfactions"
    dsar_id = Column(String, nullable=False)
    workflow = Column(String, default="gdpr_dsar_v1")
    status = Column(String, default="in_progress")
    required_steps = Column(Text, default="[]")
    completed_steps = Column(Text, default="[]")
    sla_met = Column(Boolean, default=True)


class WorkflowStep(Base, IdMixin, TimeMixin):
    __tablename__ = "workflow_steps"
    satisfaction_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    status = Column(String, default="pending")
    output = Column(Text, default="{}")


class WorkflowStepEvidence(Base, IdMixin, TimeMixin):
    __tablename__ = "workflow_step_evidence"
    step_id = Column(String, nullable=False)
    evidence_id = Column(String, nullable=False)


class AuditEngagement(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "audit_engagements"
    framework = Column(String, nullable=True)
    auditor = Column(String, nullable=True)
    status = Column(String, default="active")


# ============================================================
# Models: Trust/Vendor/Incident/Reg Radar/Review/Report/Brain
# ============================================================

class TrustDocument(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "trust_documents"
    title = Column(String, nullable=True)
    access_level = Column(String, default="public")
    status = Column(String, default="active")


class NDARequest(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "nda_requests"
    requester_email = Column(String, nullable=True)
    company = Column(String, nullable=True)
    status = Column(String, default="pending")


class Vendor(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "vendors"
    name = Column(String, nullable=True)
    category = Column(String, nullable=True)
    risk_tier = Column(String, default="medium")
    status = Column(String, default="new")


class VendorAssessment(Base, IdMixin, TimeMixin):
    __tablename__ = "vendor_assessments"
    vendor_id = Column(String, nullable=False)
    assessment_type = Column(String, default="annual")
    risk_score = Column(Float, default=50.0)
    status = Column(String, default="in_progress")


class Incident(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "incidents"
    title = Column(String, nullable=True)
    severity = Column(String, default="medium")
    status = Column(String, default="open")
    affected_states = Column(Text, default="[]")
    obligations = Column(Text, default="{}")


class RegulatorySource(Base, IdMixin, TimeMixin):
    __tablename__ = "regulatory_sources"
    state_code = Column(String, nullable=True)
    name = Column(String, nullable=True)
    endpoint = Column(String, nullable=True)
    active = Column(Boolean, default=True)


class RegulatoryUpdate(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "regulatory_updates"
    source_id = Column(String, nullable=True)
    state_code = Column(String, nullable=True)
    title = Column(String, nullable=True)
    severity = Column(String, default="medium")
    status = Column(String, default="detected")
    proposed_change = Column(Text, default="{}")


class MatrixChangeProposal(Base, IdMixin, TimeMixin):
    __tablename__ = "matrix_change_proposals"
    update_id = Column(String, nullable=True)
    state_code = Column(String, nullable=True)
    current_values = Column(Text, default="{}")
    proposed_values = Column(Text, default="{}")
    status = Column(String, default="pending_legal_review")


class ReviewItem(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "review_items"
    queue_type = Column(String, default="framework_content")
    title = Column(String, nullable=True)
    status = Column(String, default="pending_triage")
    payload = Column(Text, default="{}")


class Report(Base, IdMixin, TenantMixin, TimeMixin):
    __tablename__ = "reports"
    report_type = Column(String, default="executive_summary")
    period = Column(String, nullable=True)
    payload = Column(Text, default="{}")


class TelemetryEvent(Base, IdMixin, TimeMixin):
    __tablename__ = "telemetry_events"
    tenant_id = Column(String, nullable=True)
    correlation_id = Column(String, nullable=True)
    flow = Column(String, nullable=False)
    step = Column(String, nullable=False)
    status = Column(String, nullable=False)
    name = Column(String, nullable=False)
    # NOTE: named event_metadata (not "metadata") because SQLAlchemy's
    # Declarative API reserves the "metadata" attribute name on models.
    event_metadata = Column(Text, default="{}")


# ============================================================
# App
# ============================================================

app = FastAPI(
    title="CompOS Full Integrated Platform",
    version="2.0.0",
    description="Full integrated compliance platform with Neuralink Brain.",
)

# NOTE: allow_credentials must stay False while allow_origins is "*" --
# browsers reject (and FastAPI/Starlette will refuse to honor) a wildcard
# origin combined with credentialed requests, and enabling both together
# is a well-known CORS misconfiguration. Auth here is via the X-API-Key
# header, not cookies, so no credentialed cross-origin requests are needed.
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
    for k, v in data.items():
        if isinstance(v, datetime):
            data[k] = v.isoformat()
        elif isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, (dict, list)):
                    data[k] = parsed
            except Exception:
                pass
    return data


def ensure_sqlite_directory():
    if DATABASE_URL.startswith("sqlite:///"):
        path = DATABASE_URL.split("sqlite:///", 1)[1]
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)


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
        db.add(
            TelemetryEvent(
                id=new_id(),
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                flow=flow,
                step=step,
                status=status,
                name=name,
                event_metadata=json.dumps(metadata or {}),
            )
        )
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def hash_payload(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def parse_json(value, default=None):
    try:
        return json.loads(value) if value else default
    except Exception:
        return default


# ============================================================
# Auth / Tenant / Entitlements
# ============================================================

def get_default_tenant_db(db: Session) -> Tenant:
    tenant = db.query(Tenant).first()
    if not tenant:
        tenant = Tenant(id=new_id(), name="Default Tenant", plan="enterprise")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    return tenant


def get_context(
    x_api_key: Optional[str] = Header(default=None),
    x_tenant_id: Optional[str] = Header(default=None),
):
    db = SessionLocal()
    try:
        if not AUTH_ENABLED:
            tenant = get_default_tenant_db(db)
            return {"tenant_id": tenant.id, "scopes": ["*"], "api_key": "demo"}

        if not x_api_key:
            raise HTTPException(status_code=401, detail="API key required")

        api_key = db.query(ApiKey).filter(ApiKey.key == x_api_key).first()
        if not api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")

        scopes = parse_json(api_key.scopes, [])
        tenant_id = x_tenant_id or api_key.tenant_id

        return {"tenant_id": tenant_id, "scopes": scopes, "api_key": api_key.key}
    finally:
        db.close()


def has_scope(ctx: dict, scope: str) -> bool:
    scopes = ctx.get("scopes", [])
    return "*" in scopes or scope in scopes


def ensure_scope(ctx: dict, scope: str):
    if not has_scope(ctx, scope):
        raise HTTPException(status_code=403, detail=f"Missing scope: {scope}")


def ensure_module_enabled(ctx: dict, module: str):
    db = SessionLocal()
    try:
        entitlement = (
            db.query(PlanEntitlement)
            .filter(PlanEntitlement.tenant_id == ctx["tenant_id"], PlanEntitlement.module == module)
            .first()
        )

        if entitlement and not entitlement.enabled:
            raise HTTPException(status_code=402, detail=f"Module not enabled: {module}")
    finally:
        db.close()


# ============================================================
# Evidence Quality Engine
# ============================================================

SOURCE_TRUST = {
    "aws": 95,
    "okta": 95,
    "github": 90,
    "hr": 85,
    "manual": 45,
    "workflow": 80,
}


def score_evidence(evidence: Evidence, db: Session) -> float:
    now = utcnow()
    created = evidence.created_at.replace(tzinfo=timezone.utc) if evidence.created_at.tzinfo is None else evidence.created_at
    age_days = max(0, (now - created).days)

    freshness = 100 if age_days <= 7 else 85 if age_days <= 30 else 60 if age_days <= 90 else 30
    source_trust = SOURCE_TRUST.get(evidence.connector, 50)
    completeness = 80
    coverage = 90 if evidence.control_id else 40
    integrity = 100 if evidence.hash else 0

    score = (
        freshness * 0.25 +
        source_trust * 0.25 +
        completeness * 0.20 +
        coverage * 0.15 +
        integrity * 0.15
    )

    evidence.quality_score = round(score, 2)
    db.commit()
    return evidence.quality_score


# ============================================================
# Connector Framework
# ============================================================

CONNECTOR_CONTROL_MAP = {
    "aws": ["LOG-001", "ENC-001"],
    "okta": ["AC-001"],
    "github": ["SDLC-001", "LOG-001"],
    "hr": ["HR-001"],
}


def simulate_connector(connector_name: str) -> dict:
    if connector_name == "aws":
        return {
            "cloudtrail_enabled": True,
            "s3_public_access_blocked": True,
            "ebs_encryption_enabled": True,
            "kms_enabled": True,
        }

    if connector_name == "okta":
        return {
            "total_users": 148,
            "active_users": 142,
            "users_without_mfa": 0,
            "mfa_policy_enforced": True,
        }

    if connector_name == "github":
        return {
            "repositories_checked": 27,
            "branch_protection_enabled": 26,
            "required_reviews_enabled": 26,
            "secret_scanning_enabled": 27,
        }

    if connector_name == "hr":
        return {
            "employees": 95,
            "background_checks_completed": 95,
            "security_training_completed": 92,
        }

    return {"status": "unknown_connector"}


def run_connector(connector_name: str, ctx: dict, db: Session, request: Request):
    if connector_name not in CONNECTOR_CONTROL_MAP:
        raise HTTPException(status_code=404, detail="Connector not found")

    payload = simulate_connector(connector_name)
    control_codes = CONNECTOR_CONTROL_MAP[connector_name]
    controls = (
        db.query(Control)
        .filter(Control.code.in_(control_codes), Control.tenant_id == ctx["tenant_id"])
        .all()
    )

    created = []

    for control in controls:
        evidence = Evidence(
            id=new_id(),
            tenant_id=ctx["tenant_id"],
            control_id=control.id,
            connector=connector_name,
            payload=json.dumps(payload),
            hash=hash_payload(payload),
            status="collected",
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        score_evidence(evidence, db)
        created.append(serialize(evidence))

    record_event(
        flow="connectors",
        step="connector.executed",
        status="success",
        name=f"connector.{connector_name}",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"connector": connector_name, "evidence_count": len(created)},
    )

    return {"connector": connector_name, "evidence": created}


# ============================================================
# Questionnaire AI / Retrieval / Retraining
# ============================================================

def tokenize(text: str):
    return set([x for x in text.lower().replace("?", " ").split(" ") if len(x) > 3])


def get_retrieval_config(db: Session) -> RetrievalConfig:
    config = db.query(RetrievalConfig).first()
    if not config:
        config = RetrievalConfig(
            id=new_id(),
            auto_threshold=0.75,
            review_threshold=0.45,
            source_weights=json.dumps({"policy": 1.0, "evidence": 0.9, "trust_center": 0.8}),
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def retrieve_answer(question: str, db: Session):
    config = get_retrieval_config(db)
    source_weights = parse_json(config.source_weights, {})

    answers = db.query(AnswerLibrary).filter(AnswerLibrary.status == "approved").all()
    q_tokens = tokenize(question)

    results = []

    for answer in answers:
        a_tokens = tokenize(answer.question + " " + answer.answer)
        overlap = len(q_tokens & a_tokens)
        union = len(q_tokens | a_tokens)
        base_score = overlap / max(1, union)

        source_weight = source_weights.get(answer.source_type, 0.8)
        library_weight = answer.weight or 1.0

        confidence = min(1.0, base_score * source_weight * library_weight)

        if confidence >= config.auto_threshold:
            status = "draft_ready_auto"
        elif confidence >= config.review_threshold:
            status = "draft_ready_review"
        else:
            status = "needs_source"

        results.append(
            {
                "answer_id": answer.id,
                "question": answer.question,
                "answer": answer.answer,
                "confidence": round(confidence, 3),
                "status": status,
                "source_type": answer.source_type,
            }
        )

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results[:3]


def apply_feedback(feedback: QuestionnaireFeedback, db: Session):
    config = get_retrieval_config(db)
    source_weights = parse_json(config.source_weights, {})

    answer = db.get(QuestionnaireAnswer, feedback.answer_id)
    if not answer:
        feedback.applied = True
        db.commit()
        return

    sources = parse_json(answer.sources, [])
    source_type = sources[0]["source_type"] if sources and isinstance(sources[0], dict) else "policy"

    current_weight = source_weights.get(source_type, 1.0)

    if feedback.feedback_type == "rejected":
        source_weights[source_type] = max(0.1, current_weight - 0.05)
    elif feedback.feedback_type == "approved":
        source_weights[source_type] = min(2.0, current_weight + 0.02)

    config.source_weights = json.dumps(source_weights)
    feedback.applied = True

    db.commit()


# ============================================================
# Policy AI
# ============================================================

def generate_policy_content(tenant_id: str, db: Session) -> str:
    controls = db.query(Control).filter(Control.tenant_id == tenant_id).all()

    lines = [
        "# Information Security and Compliance Policy",
        "",
        "## Purpose",
        "This policy defines the security and compliance obligations for the organization.",
        "",
        "## Scope",
        "This policy applies to all employees, systems, vendors, and data assets.",
        "",
        "## Controls",
    ]

    for control in controls:
        lines.append(f"- {control.code}: {control.title} ({control.category}, risk: {control.risk_level})")

    lines += [
        "",
        "## Enforcement",
        "Controls are continuously tested using automated evidence collection and control tests.",
        "",
        "## Exceptions",
        "Exceptions must be approved through the Expert Review Console and recorded in the compliance system.",
    ]

    return "\n".join(lines)


# ============================================================
# GDPR DSAR Workflow / Workflow Satisfaction
# ============================================================

GDPR_DSAR_STEPS = [
    "identity_verification",
    "classification",
    "data_discovery",
    "legal_hold",
    "collection_tasks",
    "redaction_review",
    "dpo_review",
    "response_generation",
    "delivery",
    "audit_sealing",
]


def start_dsar_workflow(dsar: DSARRequest, ctx: dict, db: Session, request: Request):
    satisfaction = WorkflowSatisfaction(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        dsar_id=dsar.id,
        workflow="gdpr_dsar_v1",
        status="in_progress",
        required_steps=json.dumps(GDPR_DSAR_STEPS),
        completed_steps=json.dumps([]),
        sla_met=True,
    )
    db.add(satisfaction)
    db.commit()
    db.refresh(satisfaction)

    for step_name in GDPR_DSAR_STEPS:
        db.add(
            WorkflowStep(
                id=new_id(),
                satisfaction_id=satisfaction.id,
                name=step_name,
                status="pending",
                output=json.dumps({}),
            )
        )

    db.commit()

    record_event(
        flow="privacy",
        step="dsar.workflow_started",
        status="success",
        name="dsar.workflow_started",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"dsar_id": dsar.id, "workflow_satisfaction_id": satisfaction.id},
    )

    return satisfaction


def advance_dsar_workflow(dsar_id: str, ctx: dict, db: Session, request: Request):
    satisfaction = (
        db.query(WorkflowSatisfaction)
        .filter(WorkflowSatisfaction.dsar_id == dsar_id)
        .order_by(WorkflowSatisfaction.created_at.desc())
        .first()
    )

    if not satisfaction:
        raise HTTPException(status_code=404, detail="Workflow not found")

    step = (
        db.query(WorkflowStep)
        .filter(WorkflowStep.satisfaction_id == satisfaction.id, WorkflowStep.status == "pending")
        .order_by(WorkflowStep.created_at.asc())
        .first()
    )

    if not step:
        satisfaction.status = "completed"
        db.commit()
        return serialize(satisfaction)

    step.status = "completed"
    step.output = json.dumps({"completed_at": utcnow().isoformat()})

    evidence = Evidence(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        control_id=None,
        connector="workflow",
        payload=json.dumps({"workflow_step": step.name, "dsar_id": dsar_id}),
        hash=hash_payload({"workflow_step": step.name, "dsar_id": dsar_id}),
        status="approved",
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    score_evidence(evidence, db)

    db.add(
        WorkflowStepEvidence(
            id=new_id(),
            step_id=step.id,
            evidence_id=evidence.id,
        )
    )

    completed = parse_json(satisfaction.completed_steps, [])
    completed.append(step.name)
    satisfaction.completed_steps = json.dumps(completed)

    if len(completed) == len(parse_json(satisfaction.required_steps, [])):
        satisfaction.status = "completed"

    db.commit()

    record_event(
        flow="privacy",
        step="dsar.step_completed",
        status="success",
        name="dsar.step_completed",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"dsar_id": dsar_id, "step": step.name},
    )

    return serialize(satisfaction)


def get_dsar_evidence_chain(dsar_id: str, db: Session):
    satisfaction = (
        db.query(WorkflowSatisfaction)
        .filter(WorkflowSatisfaction.dsar_id == dsar_id)
        .order_by(WorkflowSatisfaction.created_at.desc())
        .first()
    )

    if not satisfaction:
        raise HTTPException(status_code=404, detail="Workflow not found")

    steps = (
        db.query(WorkflowStep)
        .filter(WorkflowStep.satisfaction_id == satisfaction.id)
        .order_by(WorkflowStep.created_at.asc())
        .all()
    )

    result_steps = []

    for step in steps:
        evidence_links = (
            db.query(WorkflowStepEvidence)
            .filter(WorkflowStepEvidence.step_id == step.id)
            .all()
        )

        evidence_items = []
        for link in evidence_links:
            evidence = db.get(Evidence, link.evidence_id)
            if evidence:
                evidence_items.append(serialize(evidence))

        result_steps.append(
            {
                "step": serialize(step),
                "evidence": evidence_items,
            }
        )

    return {
        "workflow_satisfaction": serialize(satisfaction),
        "steps": result_steps,
    }


# ============================================================
# Telemetry Middleware
# ============================================================

@app.middleware("http")
async def neuralink_middleware(request: Request, call_next):
    if request.url.path.startswith("/static") or request.url.path == "/favicon.ico":
        return await call_next(request)

    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))
    request.state.correlation_id = correlation_id
    start = time.time()

    record_event(
        flow="api",
        step="request.started",
        status="info",
        name="api.request",
        correlation_id=correlation_id,
        metadata={"method": request.method, "path": request.url.path},
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


@app.on_event("startup")
def startup():
    ensure_sqlite_directory()
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        get_default_tenant_db(db)
    finally:
        db.close()


# ============================================================
# Pages
# ============================================================

@app.get("/", response_class=HTMLResponse)
def console():
    path = os.path.join(os.path.dirname(__file__), "console.html")
    with open(path) as f:
        return f.read()


@app.get("/health")
def health():
    return {"status": "ok", "service": "compliance-os", "timestamp": utcnow().isoformat()}


# ============================================================
# Seed Data
# ============================================================

FRAMEWORK_SEED = [
    {"code": "SOC2", "name": "SOC 2"},
    {"code": "ISO27001", "name": "ISO 27001"},
    {"code": "HIPAA", "name": "HIPAA"},
    {"code": "GDPR", "name": "GDPR"},
]

CONTROL_SEED = [
    {
        "code": "AC-001",
        "title": "Multi-Factor Authentication for Production Access",
        "category": "Access Control",
        "risk_level": "high",
        "mappings": {"SOC2": "CC6.1", "ISO27001": "A.9.4.2", "HIPAA": "164.312(d)", "GDPR": "Art.32"},
    },
    {
        "code": "ENC-001",
        "title": "Encryption at Rest for Production Data",
        "category": "Encryption",
        "risk_level": "critical",
        "mappings": {"SOC2": "CC6.1", "ISO27001": "A.10.1", "HIPAA": "164.312(a)(2)(iv)", "GDPR": "Art.32"},
    },
    {
        "code": "LOG-001",
        "title": "Audit Logging Enabled",
        "category": "Logging",
        "risk_level": "high",
        "mappings": {"SOC2": "CC7.2", "ISO27001": "A.12.4.1", "HIPAA": "164.312(b)", "GDPR": "Art.30"},
    },
    {
        "code": "IR-001",
        "title": "Incident Response Plan",
        "category": "Incident Response",
        "risk_level": "high",
        "mappings": {"SOC2": "CC7.3", "ISO27001": "A.16.1", "HIPAA": "164.308(a)(6)", "GDPR": "Art.33"},
    },
    {
        "code": "VRM-001",
        "title": "Vendor Risk Management",
        "category": "Vendor Management",
        "risk_level": "medium",
        "mappings": {"SOC2": "CC9.2", "ISO27001": "A.15.1", "HIPAA": "164.308(b)", "GDPR": "Art.28"},
    },
]

ANSWER_LIBRARY_SEED = [
    {
        "key": "encryption_at_rest",
        "question": "Do you encrypt customer data at rest?",
        "answer": "Yes. Customer data is encrypted at rest using AES-256.",
        "source_type": "policy",
        "weight": 1.0,
    },
    {
        "key": "mfa",
        "question": "Do you enforce multi-factor authentication?",
        "answer": "Yes. MFA is enforced for all production and administrative access.",
        "source_type": "policy",
        "weight": 1.0,
    },
    {
        "key": "penetration_testing",
        "question": "Do you perform penetration testing?",
        "answer": "Yes. Third-party penetration testing is performed annually.",
        "source_type": "trust_center",
        "weight": 0.9,
    },
]

REG_SOURCE_SEED = [
    {"state_code": "CO", "name": "Colorado Legislature", "endpoint": "https://leg.colorado.gov"},
    {"state_code": "CA", "name": "California Legislature", "endpoint": "https://leginfo.legislature.ca.gov"},
    {"state_code": "TX", "name": "Texas Legislature", "endpoint": "https://capitol.texas.gov"},
    {"state_code": "NY", "name": "New York Legislature", "endpoint": "https://www.nysenate.gov"},
]

BREACH_MATRIX_SEED = [
    ("AL", "Alabama", "Ala. Code §§ 8-19-1 et seq.", 45, "conditional", None, "validate"),
    ("AK", "Alaska", "Alaska Stat. §§ 45.48.010 et seq.", None, "conditional", None, "validate"),
    ("AZ", "Arizona", "Ariz. Rev. Stat. §§ 44-7501 et seq.", None, "conditional", None, "validate"),
    ("AR", "Arkansas", "Ark. Code Ann. §§ 4-110-101 et seq.", None, "conditional", None, "validate"),
    ("CA", "California", "Cal. Civ. Code § 1798.82", None, "required_if_threshold", None, "500_residents_sample_to_ag"),
    ("CO", "Colorado", "Colo. Rev. Stat. § 6-1-716", 30, "required_if_threshold", 30, "500_residents"),
    ("CT", "Connecticut", "Conn. Gen. Stat. § 36a-701b", 90, "conditional", 90, "validate"),
    ("DE", "Delaware", "Del. Code tit. 6 § 102A", 60, "conditional", None, "validate"),
    ("FL", "Florida", "Fla. Stat. § 501.171", 30, "required_if_threshold", 30, "500_residents"),
    ("GA", "Georgia", "Ga. Code §§ 10-1-911 et seq.", None, "conditional", None, "validate"),
    ("HI", "Hawaii", "Haw. Rev. Stat. §§ 487N-1 et seq.", None, "conditional", None, "validate"),
    ("ID", "Idaho", "Idaho Code §§ 48-726 et seq.", None, "conditional", None, "validate"),
    ("IL", "Illinois", "815 ILCS 530/1 et seq.", None, "required_if_threshold", None, "500_residents"),
    ("IN", "Indiana", "Ind. Code §§ 4-1.1-5-1 et seq.", None, "conditional", None, "validate"),
    ("IA", "Iowa", "Iowa Code §§ 715C.1 et seq.", None, "conditional", None, "validate"),
    ("KS", "Kansas", "Kan. Stat. Ann. §§ 50-7a01 et seq.", None, "conditional", None, "validate"),
    ("KY", "Kentucky", "Ky. Rev. Stat. § 365.732", None, "conditional", None, "validate"),
    ("LA", "Louisiana", "La. Rev. Stat. § 51:3074", None, "conditional", None, "validate"),
    ("ME", "Maine", "Me. Rev. Stat. tit. 10 § 1348", None, "conditional", None, "validate"),
    ("MD", "Maryland", "Md. Com. Law § 14-3504", None, "conditional", None, "validate"),
    ("MA", "Massachusetts", "Mass. Gen. Laws ch. 93H", None, "conditional", None, "validate"),
    ("MI", "Michigan", "Mich. Comp. Laws § 445.63", None, "conditional", None, "validate"),
    ("MN", "Minnesota", "Minn. Stat. § 325E.61", None, "conditional", None, "validate"),
    ("MS", "Mississippi", "Miss. Code Ann. §§ 75-65-1 et seq.", None, "conditional", None, "validate"),
    ("MO", "Missouri", "Mo. Rev. Stat. § 407.1500", None, "conditional", None, "validate"),
    ("MT", "Montana", "Mont. Code Ann. §§ 30-14-1701 et seq.", None, "conditional", None, "validate"),
    ("NE", "Nebraska", "Neb. Rev. Stat. §§ 87-803 et seq.", None, "conditional", None, "validate"),
    ("NV", "Nevada", "Nev. Rev. Stat. § 603A", None, "conditional", None, "validate"),
    ("NH", "New Hampshire", "N.H. Rev. Stat. Ann. § 359-C:19", None, "conditional", None, "validate"),
    ("NJ", "New Jersey", "N.J. Stat. Ann. §§ 56:8-162 et seq.", None, "conditional", None, "validate"),
    ("NM", "New Mexico", "N.M. Stat. Ann. §§ 57-12C-1 et seq.", 45, "conditional", None, "validate"),
    ("NY", "New York", "N.Y. Gen. Bus. Law § 899-aa", None, "required_if_threshold", None, "500_residents_state_agencies"),
    ("NC", "North Carolina", "N.C. Gen. Stat. § 75-65", 30, "conditional", None, "validate"),
    ("ND", "North Dakota", "N.D. Cent. Code §§ 51-30-01 et seq.", None, "conditional", None, "validate"),
    ("OH", "Ohio", "Ohio Rev. Code § 1349.19", None, "conditional", None, "validate"),
    ("OK", "Oklahoma", "Okla. Stat. tit. 24 §§ 161 et seq.", 45, "conditional", None, "validate"),
    ("OR", "Oregon", "Or. Rev. Stat. §§ 646A.602 et seq.", None, "required_if_threshold", None, "250_residents"),
    ("PA", "Pennsylvania", "73 Pa. Stat. §§ 2301 et seq.", None, "conditional", None, "validate"),
    ("RI", "Rhode Island", "R.I. Gen. Laws §§ 11-49.3-1 et seq.", 45, "conditional", None, "validate"),
    ("SC", "South Carolina", "S.C. Code Ann. § 39-1-90", 45, "conditional", None, "validate"),
    ("SD", "South Dakota", "S.D. Codified Laws §§ 22-40-1 et seq.", 60, "conditional", None, "validate"),
    ("TN", "Tennessee", "Tenn. Code Ann. § 47-18-2107", 60, "conditional", None, "validate"),
    ("TX", "Texas", "Tex. Bus. & Com. Code § 521.053", 60, "required_if_threshold", 30, "250_residents"),
    ("UT", "Utah", "Utah Code Ann. §§ 13-44-101 et seq.", None, "conditional", None, "validate"),
    ("VT", "Vermont", "Vt. Stat. tit. 9 § 2435", None, "conditional", None, "validate"),
    ("VA", "Virginia", "Va. Code Ann. § 18.2-186.6", None, "conditional", None, "validate"),
    ("WA", "Washington", "Wash. Rev. Code §§ 19.255.010 et seq.", 30, "required_if_threshold", 30, "500_residents"),
    ("WV", "West Virginia", "W. Va. Code §§ 46A-2A-101 et seq.", None, "conditional", None, "validate"),
    ("WI", "Wisconsin", "Wis. Stat. § 134.98", 45, "conditional", None, "validate"),
    ("WY", "Wyoming", "Wyo. Stat. Ann. §§ 40-12-501 et seq.", None, "conditional", None, "validate"),
]


@app.post("/v1/seed/full")
def seed_full(request: Request, db: Session = Depends(get_db)):
    if db.query(Framework).count() > 0:
        return {"status": "already seeded"}

    tenant = get_default_tenant_db(db)

    db.add(ApiKey(id=new_id(), tenant_id=tenant.id, key="demo-key", scopes=json.dumps(["*"])))

    modules = [
        "controls", "evidence", "testing", "policy_ai", "questionnaire_ai", "auditor_portal",
        "trust_center", "privacy_dsar", "vendor_risk", "regulatory_radar", "incident_response",
        "executive_reporting", "mcp_api", "pricing_entitlements"
    ]

    for module in modules:
        db.add(PlanEntitlement(id=new_id(), tenant_id=tenant.id, module=module, enabled=True))

    framework_ids = {}
    for fw in FRAMEWORK_SEED:
        item = Framework(id=new_id(), code=fw["code"], name=fw["name"])
        db.add(item)
        db.commit()
        db.refresh(item)
        framework_ids[fw["code"]] = item.id

    for control_seed in CONTROL_SEED:
        control = Control(
            id=new_id(),
            tenant_id=tenant.id,
            code=control_seed["code"],
            title=control_seed["title"],
            category=control_seed["category"],
            risk_level=control_seed["risk_level"],
            status="active",
        )
        db.add(control)
        db.commit()
        db.refresh(control)

        for framework_code, requirement in control_seed["mappings"].items():
            db.add(
                ControlMapping(
                    id=new_id(),
                    control_id=control.id,
                    framework_id=framework_ids[framework_code],
                    requirement=requirement,
                )
            )

    for row in BREACH_MATRIX_SEED:
        db.add(
            BreachMatrix(
                id=new_id(),
                state_code=row[0],
                state_name=row[1],
                statute=row[2],
                individual_days=row[3],
                regulator_notice=row[4],
                regulator_days=row[5],
                regulator_threshold=row[6],
                legal_review_required=True,
            )
        )

    for answer in ANSWER_LIBRARY_SEED:
        db.add(
            AnswerLibrary(
                id=new_id(),
                key=answer["key"],
                question=answer["question"],
                answer=answer["answer"],
                source_type=answer["source_type"],
                weight=answer["weight"],
                status="approved",
            )
        )

    for source in REG_SOURCE_SEED:
        db.add(
            RegulatorySource(
                id=new_id(),
                state_code=source["state_code"],
                name=source["name"],
                endpoint=source["endpoint"],
                active=True,
            )
        )

    get_retrieval_config(db)

    db.add(
        Questionnaire(
            id=new_id(),
            tenant_id=tenant.id,
            customer="Acme Corp",
            status="imported",
            total_questions=3,
        )
    )

    db.add(
        Incident(
            id=new_id(),
            tenant_id=tenant.id,
            title="Suspicious login from new geography",
            severity="high",
            status="open",
            affected_states=json.dumps(["TX", "CA", "CO"]),
        )
    )

    db.add(
        Vendor(
            id=new_id(),
            tenant_id=tenant.id,
            name="CloudHost Inc",
            category="infrastructure",
            risk_tier="high",
            status="new",
        )
    )

    db.add(
        AuditEngagement(
            id=new_id(),
            tenant_id=tenant.id,
            framework="SOC 2 Type II",
            auditor="Example Assurance LLP",
            status="active",
        )
    )

    db.commit()

    record_event(
        flow="seed",
        step="seed.completed",
        status="success",
        name="seed.completed",
        tenant_id=tenant.id,
        correlation_id=getattr(request.state, "correlation_id", None),
    )

    return {"status": "seeded", "tenant_id": tenant.id}


# ============================================================
# Core Read Endpoints
# ============================================================

@app.get("/v1/controls")
def list_controls(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(Control).filter(Control.tenant_id == ctx["tenant_id"]).all()]


@app.get("/v1/evidence")
def list_evidence(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(Evidence).filter(Evidence.tenant_id == ctx["tenant_id"]).all()]


@app.get("/v1/framework-mappings")
def list_mappings(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    mappings = db.query(ControlMapping).all()
    result = []
    for mapping in mappings:
        control = db.get(Control, mapping.control_id)
        framework = db.get(Framework, mapping.framework_id)
        result.append(
            {
                "control": serialize(control),
                "framework": serialize(framework),
                "requirement": mapping.requirement,
            }
        )
    return result


@app.get("/v1/breach-matrix")
def breach_matrix(state: Optional[str] = Query(default=None), db: Session = Depends(get_db)):
    q = db.query(BreachMatrix)
    if state:
        q = q.filter(BreachMatrix.state_code == state)
    return [serialize(x) for x in q.all()]


@app.get("/v1/questionnaires")
def list_questionnaires(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(Questionnaire).filter(Questionnaire.tenant_id == ctx["tenant_id"]).all()]


@app.get("/v1/questionnaires/{questionnaire_id}/answers")
def list_questionnaire_answers(questionnaire_id: str, db: Session = Depends(get_db)):
    return [
        serialize(x)
        for x in db.query(QuestionnaireAnswer)
        .filter(QuestionnaireAnswer.questionnaire_id == questionnaire_id)
        .all()
    ]


@app.get("/v1/dsar")
def list_dsar(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(DSARRequest).filter(DSARRequest.tenant_id == ctx["tenant_id"]).all()]


# ============================================================
# Connector Endpoints
# ============================================================

@app.post("/v1/connectors/{connector_name}/run")
def connector_run(connector_name: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "evidence")
    return run_connector(connector_name, ctx, db, request)


# ============================================================
# Testing Engine
# ============================================================

@app.post("/v1/tests/seed-default")
def seed_default_test(request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    control = db.query(Control).filter(Control.code == "AC-001", Control.tenant_id == ctx["tenant_id"]).first()
    if not control:
        raise HTTPException(status_code=404, detail="Run full seed first")

    existing = db.query(Test).filter(Test.control_id == control.id).first()
    if existing:
        return serialize(existing)

    test = Test(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        control_id=control.id,
        name="All active users have MFA",
        expected_field="users_without_mfa",
        operator="eq",
        expected_value=json.dumps(0),
    )
    db.add(test)
    db.commit()
    db.refresh(test)

    record_event(
        flow="testing",
        step="test.created",
        status="success",
        name="test.created",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
    )

    return serialize(test)


@app.post("/v1/tests/{test_id}/run")
def run_test(test_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "testing")

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
        result = {"reason": "No evidence found"}
    else:
        payload = parse_json(evidence.payload, {})
        actual = payload.get(test.expected_field)
        expected = parse_json(test.expected_value, None)

        passed = False
        if test.operator == "eq":
            passed = actual == expected
        elif test.operator == "neq":
            passed = actual != expected
        elif test.operator == "exists":
            passed = actual is not None

        status = "pass" if passed else "fail"
        result = {"actual": actual, "expected": expected, "evidence_id": evidence.id}

    run = TestRun(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        test_id=test.id,
        status=status,
        result=json.dumps(result),
    )
    db.add(run)

    if status != "pass":
        db.add(
            Gap(
                id=new_id(),
                tenant_id=ctx["tenant_id"],
                control_id=test.control_id,
                title=f"Test failed: {test.name}",
                severity="high",
                status="open",
            )
        )

    db.commit()

    record_event(
        flow="testing",
        step="test.run",
        status=status,
        name="test.run",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"test_id": test_id},
    )

    return serialize(run)


# ============================================================
# Policy AI Endpoints
# ============================================================

@app.post("/v1/policies/generate")
def policy_generate(request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "policy_ai")

    content = generate_policy_content(ctx["tenant_id"], db)

    policy = Policy(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        title="Information Security and Compliance Policy",
        policy_type="security",
        version="1.0",
        status="draft",
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    version = PolicyVersion(
        id=new_id(),
        policy_id=policy.id,
        version="1.0",
        content=content,
    )
    db.add(version)
    db.commit()

    record_event(
        flow="policy_ai",
        step="policy.generated",
        status="success",
        name="policy.generated",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"policy_id": policy.id},
    )

    return serialize(policy)


@app.get("/v1/policies")
def list_policies(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(Policy).filter(Policy.tenant_id == ctx["tenant_id"]).all()]


# ============================================================
# Questionnaire AI Endpoints
# ============================================================

@app.post("/v1/questionnaires/{questionnaire_id}/process")
def questionnaire_process(questionnaire_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "questionnaire_ai")

    questionnaire = db.get(Questionnaire, questionnaire_id)
    if not questionnaire:
        raise HTTPException(status_code=404, detail="Questionnaire not found")

    questions = [
        "Do you encrypt customer data at rest?",
        "Do you enforce multi-factor authentication?",
        "Do you perform penetration testing?",
    ]

    auto = 0
    review = 0

    for question in questions:
        candidates = retrieve_answer(question, db)
        best = candidates[0] if candidates else None

        if best:
            answer = best["answer"]
            confidence = best["confidence"]
            status = best["status"]
            sources = [{"answer_id": best["answer_id"], "source_type": best["source_type"]}]
        else:
            answer = "Requires human review."
            confidence = 0.0
            status = "needs_source"
            sources = []

        if status == "draft_ready_auto":
            auto += 1
        else:
            review += 1

        db.add(
            QuestionnaireAnswer(
                id=new_id(),
                questionnaire_id=questionnaire.id,
                question=question,
                answer=answer,
                confidence=confidence,
                status=status,
                sources=json.dumps(sources),
            )
        )

    questionnaire.auto_answered = auto
    questionnaire.needs_review = review
    questionnaire.status = "in_review"
    db.commit()

    record_event(
        flow="questionnaire_ai",
        step="questionnaire.processed",
        status="success",
        name="questionnaire.processed",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"questionnaire_id": questionnaire.id},
    )

    return serialize(questionnaire)


@app.post("/v1/questionnaires/feedback")
def questionnaire_feedback(payload: dict = Body(...), request: Request = None, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    feedback = QuestionnaireFeedback(
        id=new_id(),
        answer_id=payload.get("answer_id"),
        question=payload.get("question"),
        feedback_type=payload.get("feedback_type", "rejected"),
        reason=payload.get("reason"),
        applied=False,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)

    apply_feedback(feedback, db)

    record_event(
        flow="questionnaire_ai",
        step="feedback.applied",
        status="success",
        name="feedback.applied",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"feedback_id": feedback.id},
    )

    return serialize(feedback)


# ============================================================
# GDPR DSAR Endpoints
# ============================================================

@app.post("/v1/dsar/start")
def dsar_start(payload: dict = Body(...), request: Request = None, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "privacy_dsar")

    dsar = DSARRequest(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        request_type=payload.get("request_type", "access"),
        requester_email=payload.get("requester_email"),
        status="received",
        due_date=(utcnow() + timedelta(days=30)).date().isoformat(),
    )
    db.add(dsar)
    db.commit()
    db.refresh(dsar)

    satisfaction = start_dsar_workflow(dsar, ctx, db, request)

    return {
        "dsar": serialize(dsar),
        "workflow_satisfaction": serialize(satisfaction),
    }


@app.post("/v1/dsar/{dsar_id}/advance")
def dsar_advance(dsar_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "privacy_dsar")
    return advance_dsar_workflow(dsar_id, ctx, db, request)


@app.get("/v1/dsar/{dsar_id}/chain")
def dsar_chain(dsar_id: str, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return get_dsar_evidence_chain(dsar_id, db)


@app.get("/v1/auditor/dsar/{dsar_id}/evidence-chain")
def auditor_dsar_chain(dsar_id: str, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "auditor_portal")
    return get_dsar_evidence_chain(dsar_id, db)


# ============================================================
# Incident Response + Breach Matrix
# ============================================================

@app.post("/v1/incidents/{incident_id}/triage")
def incident_triage(incident_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "incident_response")

    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    states = parse_json(incident.affected_states, [])
    matrix_rows = db.query(BreachMatrix).filter(BreachMatrix.state_code.in_(states)).all()

    obligations = {}

    for row in matrix_rows:
        obligations[row.state_code] = {
            "state_name": row.state_name,
            "statute": row.statute,
            "individual_days": row.individual_days,
            "regulator_notice": row.regulator_notice,
            "regulator_days": row.regulator_days,
            "regulator_threshold": row.regulator_threshold,
            "legal_review_required": row.legal_review_required,
        }

    incident.status = "triaged"
    incident.obligations = json.dumps(obligations)
    db.commit()

    record_event(
        flow="incident_response",
        step="incident.triaged",
        status="success",
        name="incident.triaged",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"incident_id": incident.id, "states": states},
    )

    return serialize(incident)


@app.get("/v1/incidents")
def list_incidents(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(Incident).filter(Incident.tenant_id == ctx["tenant_id"]).all()]


# ============================================================
# Regulatory Radar + Matrix Proposals + Expert Review
# ============================================================

@app.post("/v1/reg-radar/crawl")
def reg_radar_crawl(request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "regulatory_radar")

    sources = db.query(RegulatorySource).filter(RegulatorySource.active == True).all()  # noqa: E712
    created = []

    for source in sources:
        update = RegulatoryUpdate(
            id=new_id(),
            tenant_id=ctx["tenant_id"],
            source_id=source.id,
            state_code=source.state_code,
            title=f"Detected legislative activity in {source.state_code}",
            severity="medium",
            status="detected",
            proposed_change=json.dumps({"regulator_threshold": "250_residents"}),
        )
        db.add(update)
        db.commit()
        db.refresh(update)
        created.append(serialize(update))

    record_event(
        flow="regulatory_radar",
        step="radar.crawl",
        status="success",
        name="radar.crawl",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"updates_created": len(created)},
    )

    return created


@app.post("/v1/reg-radar/{update_id}/analyze")
def reg_radar_analyze(update_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "regulatory_radar")

    update = db.get(RegulatoryUpdate, update_id)
    if not update:
        raise HTTPException(status_code=404, detail="Update not found")

    current = db.query(BreachMatrix).filter(BreachMatrix.state_code == update.state_code).first()

    proposal = MatrixChangeProposal(
        id=new_id(),
        update_id=update.id,
        state_code=update.state_code,
        current_values=json.dumps(serialize(current) if current else {}),
        proposed_values=update.proposed_change,
        status="pending_legal_review",
    )
    db.add(proposal)

    review_item = ReviewItem(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        queue_type="matrix_proposal",
        title=f"Review breach matrix change for {update.state_code}",
        status="pending_triage",
        payload=json.dumps(
            {
                "regulatory_update_id": update.id,
                "proposal_id": proposal.id,
                "state_code": update.state_code,
                "proposed_change": parse_json(update.proposed_change, {}),
            }
        ),
    )
    db.add(review_item)

    update.status = "impact_analyzed"
    db.commit()

    record_event(
        flow="regulatory_radar",
        step="update.analyzed",
        status="success",
        name="update.analyzed",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"update_id": update.id, "proposal_id": proposal.id},
    )

    return serialize(proposal)


@app.get("/v1/review-items")
def list_review_items(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(ReviewItem).filter(ReviewItem.tenant_id == ctx["tenant_id"]).all()]


@app.post("/v1/review-items/{item_id}/approve")
def review_approve(item_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    item = db.get(ReviewItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Review item not found")

    item.status = "approved"
    payload = parse_json(item.payload, {})

    if item.queue_type == "matrix_proposal" and payload.get("state_code"):
        matrix = db.query(BreachMatrix).filter(BreachMatrix.state_code == payload["state_code"]).first()
        proposed = payload.get("proposed_change", {})

        if matrix and isinstance(proposed, dict):
            if "individual_days" in proposed:
                matrix.individual_days = proposed["individual_days"]
            if "regulator_threshold" in proposed:
                matrix.regulator_threshold = proposed["regulator_threshold"]
            if "regulator_days" in proposed:
                matrix.regulator_days = proposed["regulator_days"]

    db.commit()

    record_event(
        flow="expert_review",
        step="review.approved",
        status="success",
        name="review.approved",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"item_id": item.id},
    )

    return serialize(item)


# ============================================================
# Vendor Risk
# ============================================================

@app.post("/v1/vendors/{vendor_id}/assess")
def vendor_assess(vendor_id: str, request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "vendor_risk")

    vendor = db.get(Vendor, vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    assessment = VendorAssessment(
        id=new_id(),
        vendor_id=vendor.id,
        assessment_type="annual_review",
        risk_score=72.0,
        status="completed",
    )
    db.add(assessment)

    vendor.status = "assessed"
    db.commit()

    record_event(
        flow="vendor_risk",
        step="vendor.assessed",
        status="success",
        name="vendor.assessed",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"vendor_id": vendor.id},
    )

    return serialize(assessment)


@app.get("/v1/vendors")
def list_vendors(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return [serialize(x) for x in db.query(Vendor).filter(Vendor.tenant_id == ctx["tenant_id"]).all()]


# ============================================================
# Executive Reporting
# ============================================================

@app.post("/v1/reports/generate")
def report_generate(request: Request, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    ensure_module_enabled(ctx, "executive_reporting")

    controls = db.query(Control).filter(Control.tenant_id == ctx["tenant_id"]).count()
    gaps = db.query(Gap).filter(Gap.tenant_id == ctx["tenant_id"], Gap.status == "open").count()
    evidence = db.query(Evidence).filter(Evidence.tenant_id == ctx["tenant_id"]).count()

    readiness = max(0, min(100, 100 - (gaps * 10)))

    report = Report(
        id=new_id(),
        tenant_id=ctx["tenant_id"],
        report_type="executive_summary",
        period=utcnow().date().isoformat(),
        payload=json.dumps(
            {
                "overall_readiness_score": readiness,
                "controls": controls,
                "open_gaps": gaps,
                "evidence_items": evidence,
                "top_risks": [
                    "Open control gaps",
                    "Vendor review pending",
                    "Regulatory matrix proposals awaiting legal review",
                ],
            }
        ),
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    record_event(
        flow="reporting",
        step="report.generated",
        status="success",
        name="report.generated",
        tenant_id=ctx["tenant_id"],
        correlation_id=getattr(request.state, "correlation_id", None),
        metadata={"report_id": report.id},
    )

    return serialize(report)


# ============================================================
# Neuralink Brain Analytics
# ============================================================

@app.get("/v1/brain/metrics")
def brain_metrics(ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    return {
        "controls": db.query(Control).filter(Control.tenant_id == ctx["tenant_id"]).count(),
        "evidence": db.query(Evidence).filter(Evidence.tenant_id == ctx["tenant_id"]).count(),
        "tests": db.query(Test).filter(Test.tenant_id == ctx["tenant_id"]).count(),
        "gaps": db.query(Gap).filter(Gap.tenant_id == ctx["tenant_id"]).count(),
        "policies": db.query(Policy).filter(Policy.tenant_id == ctx["tenant_id"]).count(),
        "questionnaires": db.query(Questionnaire).filter(Questionnaire.tenant_id == ctx["tenant_id"]).count(),
        "dsar_requests": db.query(DSARRequest).filter(DSARRequest.tenant_id == ctx["tenant_id"]).count(),
        "vendors": db.query(Vendor).filter(Vendor.tenant_id == ctx["tenant_id"]).count(),
        "incidents": db.query(Incident).filter(Incident.tenant_id == ctx["tenant_id"]).count(),
        "regulatory_updates": db.query(RegulatoryUpdate).filter(RegulatoryUpdate.tenant_id == ctx["tenant_id"]).count(),
        "review_items": db.query(ReviewItem).filter(ReviewItem.tenant_id == ctx["tenant_id"]).count(),
        "telemetry_events": db.query(TelemetryEvent).count(),
    }


@app.get("/v1/brain/events")
def brain_events(limit: int = Query(default=50), db: Session = Depends(get_db)):
    events = db.query(TelemetryEvent).order_by(TelemetryEvent.created_at.desc()).limit(limit).all()
    return [serialize(e) for e in events]


@app.get("/v1/brain/flows/{correlation_id}")
def brain_flow(correlation_id: str, db: Session = Depends(get_db)):
    events = (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.correlation_id == correlation_id)
        .order_by(TelemetryEvent.created_at.asc())
        .all()
    )
    return {"correlation_id": correlation_id, "events": [serialize(e) for e in events]}


@app.get("/v1/brain/anomalies")
def brain_anomalies(db: Session = Depends(get_db)):
    now = utcnow()
    recent_window = now - timedelta(minutes=5)
    previous_window = now - timedelta(minutes=10)

    recent = (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.created_at >= recent_window)
        .count()
    )

    previous = (
        db.query(TelemetryEvent)
        .filter(TelemetryEvent.created_at >= previous_window, TelemetryEvent.created_at < recent_window)
        .count()
    )

    anomaly = recent > max(10, previous * 3)

    return {
        "recent_events_5m": recent,
        "previous_events_5m": previous,
        "anomaly_detected": anomaly,
    }


# ============================================================
# MCP Server + Scope Matrix + OpenAPI
# ============================================================

MCP_TOOLS = [
    {"name": "get_metrics", "description": "Get compliance metrics", "scope": "compliance.read"},
    {"name": "list_controls", "description": "List controls", "scope": "controls.read"},
    {"name": "run_connector", "description": "Run connector evidence collection", "scope": "evidence.write"},
    {"name": "generate_policy", "description": "Generate AI policy", "scope": "policies.write"},
    {"name": "process_questionnaire", "description": "Process questionnaire with AI", "scope": "questionnaires.write"},
    {"name": "advance_dsar", "description": "Advance DSAR workflow", "scope": "privacy.write"},
    {"name": "triage_incident", "description": "Triage incident using breach matrix", "scope": "incidents.write"},
    {"name": "crawl_reg_radar", "description": "Crawl regulatory radar sources", "scope": "regulatory.write"},
]

SCOPE_MATRIX = {
    "compliance.read": ["get_metrics"],
    "controls.read": ["list_controls"],
    "evidence.write": ["run_connector"],
    "policies.write": ["generate_policy"],
    "questionnaires.write": ["process_questionnaire"],
    "privacy.write": ["advance_dsar"],
    "incidents.write": ["triage_incident"],
    "regulatory.write": ["crawl_reg_radar"],
}


@app.get("/v1/mcp/tools")
def mcp_tools():
    return MCP_TOOLS


@app.get("/v1/platform/scopes")
def platform_scopes():
    return SCOPE_MATRIX


@app.get("/v1/platform/openapi")
def platform_openapi():
    return app.openapi()


@app.post("/v1/mcp/call")
def mcp_call(payload: dict = Body(...), request: Request = None, ctx: dict = Depends(get_context), db: Session = Depends(get_db)):
    tool_name = payload.get("tool")
    args = payload.get("arguments", {})

    tool = next((t for t in MCP_TOOLS if t["name"] == tool_name), None)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")

    ensure_scope(ctx, tool["scope"])

    if tool_name == "get_metrics":
        return brain_metrics(ctx, db)

    if tool_name == "list_controls":
        return list_controls(ctx, db)

    if tool_name == "run_connector":
        return run_connector(args.get("connector", "aws"), ctx, db, request)

    if tool_name == "generate_policy":
        return policy_generate(request, ctx, db)

    if tool_name == "process_questionnaire":
        questionnaire = db.query(Questionnaire).filter(Questionnaire.tenant_id == ctx["tenant_id"]).first()
        if not questionnaire:
            raise HTTPException(status_code=404, detail="No questionnaire found. Run full seed.")
        return questionnaire_process(questionnaire.id, request, ctx, db)

    if tool_name == "advance_dsar":
        dsar = db.query(DSARRequest).filter(DSARRequest.tenant_id == ctx["tenant_id"]).first()
        if not dsar:
            raise HTTPException(status_code=404, detail="No DSAR found. Start DSAR first.")
        return advance_dsar_workflow(dsar.id, ctx, db, request)

    if tool_name == "triage_incident":
        incident = db.query(Incident).filter(Incident.tenant_id == ctx["tenant_id"]).first()
        if not incident:
            raise HTTPException(status_code=404, detail="No incident found. Run full seed.")
        return incident_triage(incident.id, request, ctx, db)

    if tool_name == "crawl_reg_radar":
        return reg_radar_crawl(request, ctx, db)

    raise HTTPException(status_code=400, detail="Tool not implemented")
