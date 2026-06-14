"""
VAPTForge ML Severity Predictor
================================
Random Forest classifier that predicts vulnerability severity
(critical / high / medium / low / info) from finding features.

Features used (all numeric, no text embedding needed):
  - owasp_category_encoded  : A01-A10 → 1-10
  - confidence              : 0.0–1.0
  - cvss_score              : 0.0–10.0 (0 if missing)
  - risk_score              : computed by engine
  - http_method_encoded     : GET=0, POST=1, OTHER=2
  - has_parameter           : 0 or 1

Model is trained on a rich synthetic dataset that mirrors real VAPT
distributions, then fine-tuned on actual scan findings in the database
whenever predict_and_update() is called.
"""

import os
import pickle
import logging
from pathlib import Path
from typing import List, Dict, Any

import numpy as np

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE       = Path(__file__).parent
MODEL_PATH  = _HERE / "vapt_severity_model.pkl"

# ── Label encoding ─────────────────────────────────────────────────────────────
SEV_LABELS  = ["info", "low", "medium", "high", "critical"]
SEV_TO_INT  = {s: i for i, s in enumerate(SEV_LABELS)}
INT_TO_SEV  = {i: s for s, i in SEV_TO_INT.items()}

OWASP_TO_INT = {
    "A01": 1, "A02": 2, "A03": 3, "A04": 4, "A05": 5,
    "A06": 6, "A07": 7, "A08": 8, "A09": 9, "A10": 10,
}

METHOD_TO_INT = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 2, "PATCH": 2}

# ── Feature extraction ─────────────────────────────────────────────────────────

def _extract_features(finding: Dict[str, Any]) -> List[float]:
    """Convert a finding dict → fixed-length feature vector."""
    owasp   = finding.get("owasp_category", "A05")
    owasp_n = OWASP_TO_INT.get(owasp[:3].upper(), 5)

    conf    = float(finding.get("confidence", 0.8) or 0.8)
    cvss    = float(finding.get("cvss_score") or 0.0)
    risk    = float(finding.get("risk_score", 0.0) or 0.0)

    method  = (finding.get("http_method") or "GET").upper()
    meth_n  = METHOD_TO_INT.get(method, 2)

    has_param = 1 if finding.get("affected_parameter") else 0

    # Derived signals
    conf_x_cvss = conf * cvss
    risk_norm   = min(risk / 10.0, 1.0)

    return [owasp_n, conf, cvss, risk, meth_n, has_param, conf_x_cvss, risk_norm]


# ── Synthetic training data ────────────────────────────────────────────────────

def _build_synthetic_dataset():
    """
    Generate ~1 200 labeled samples that reflect real VAPT severity distributions.
    This gives the model a strong prior even before any real scans exist.
    """
    from sklearn.utils import shuffle as sk_shuffle

    rng = np.random.default_rng(42)
    X, y = [], []

    # (owasp, conf, cvss, risk, method, has_param) → typical severity
    templates = [
        # critical
        (3,  0.95, 9.8, 9.3, 1, 1, "critical"),  # SQLi POST
        (3,  0.90, 9.0, 8.5, 1, 1, "critical"),  # SQLi POST low conf
        (1,  0.85, 9.1, 8.8, 0, 0, "critical"),  # Broken AC
        (10, 0.92, 9.3, 9.0, 0, 1, "critical"),  # SSRF
        (3,  0.88, 8.8, 8.6, 1, 1, "critical"),  # XSS POST
        # high
        (3,  0.80, 7.5, 6.0, 0, 1, "high"),      # XSS GET
        (7,  0.82, 7.2, 5.8, 0, 0, "high"),      # Auth failure
        (2,  0.78, 7.8, 6.2, 0, 0, "high"),      # Crypto failure
        (8,  0.75, 7.0, 5.5, 0, 0, "high"),      # Integrity failure
        (1,  0.70, 7.4, 5.9, 0, 1, "high"),      # IDOR
        # medium
        (5,  0.70, 5.3, 4.2, 0, 0, "medium"),    # Sec misconfig header
        (6,  0.65, 5.5, 4.0, 0, 0, "medium"),    # Vuln component
        (4,  0.60, 5.0, 3.8, 0, 0, "medium"),    # Insecure design
        (9,  0.60, 4.8, 3.5, 0, 0, "medium"),    # Logging failure
        (7,  0.65, 5.2, 4.1, 0, 0, "medium"),    # Weak cookie
        # low
        (5,  0.55, 3.1, 2.5, 0, 0, "low"),       # Missing header
        (2,  0.50, 2.8, 2.0, 0, 0, "low"),       # Weak TLS
        (6,  0.50, 2.5, 1.8, 0, 0, "low"),       # Outdated minor version
        # info
        (9,  0.40, 0.0, 0.5, 0, 0, "info"),      # Debug path exposed
        (5,  0.35, 0.0, 0.3, 0, 0, "info"),      # Server header
    ]

    for owasp_n, conf_base, cvss_base, risk_base, meth, param, sev in templates:
        n = 60  # 60 samples per template
        owasp_arr  = np.full(n, owasp_n, dtype=float)
        conf_arr   = np.clip(rng.normal(conf_base, 0.07, n), 0.1, 1.0)
        cvss_arr   = np.clip(rng.normal(cvss_base, 0.5,  n), 0.0, 10.0)
        risk_arr   = np.clip(rng.normal(risk_base, 0.6,  n), 0.0, 10.0)
        meth_arr   = np.full(n, meth,  dtype=float)
        param_arr  = np.full(n, param, dtype=float)
        cxc_arr    = conf_arr * cvss_arr
        rnorm_arr  = np.clip(risk_arr / 10.0, 0.0, 1.0)

        batch = np.column_stack([
            owasp_arr, conf_arr, cvss_arr, risk_arr,
            meth_arr, param_arr, cxc_arr, rnorm_arr
        ])
        X.append(batch)
        y.extend([SEV_TO_INT[sev]] * n)

    X_arr = np.vstack(X)
    y_arr = np.array(y)
    X_arr, y_arr = sk_shuffle(X_arr, y_arr, random_state=42)
    return X_arr, y_arr


# ── Train / load model ─────────────────────────────────────────────────────────

def _train_model(extra_X=None, extra_y=None):
    """Train (or retrain) Random Forest. Optionally include real findings."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    X_syn, y_syn = _build_synthetic_dataset()

    if extra_X is not None and len(extra_X) > 0:
        X_all = np.vstack([X_syn, extra_X])
        y_all = np.concatenate([y_syn, extra_y])
    else:
        X_all, y_all = X_syn, y_syn

    clf = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=4,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])
    clf.fit(X_all, y_all)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)

    logger.info("ML severity model trained on %d samples and saved.", len(y_all))
    return clf


def _load_or_train() -> Any:
    if MODEL_PATH.exists():
        try:
            with open(MODEL_PATH, "rb") as f:
                clf = pickle.load(f)
            logger.info("ML severity model loaded from disk.")
            return clf
        except Exception as e:
            logger.warning("Could not load model (%s) — retraining.", e)
    return _train_model()


# Singleton model instance
_model = None

def get_model():
    global _model
    if _model is None:
        _model = _load_or_train()
    return _model


# ── Public API ─────────────────────────────────────────────────────────────────

def predict_severity(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Predict severity for a single finding dict.

    Returns:
        {
          "ml_severity":    "high",
          "ml_confidence":  0.87,
          "ml_probabilities": {"info":0.01, "low":0.03, "medium":0.09, "high":0.87, "critical":0.00},
          "agrees_with_rule_based": True
        }
    """
    clf = get_model()
    feat = np.array([_extract_features(finding)])

    pred_int  = int(clf.predict(feat)[0])
    proba     = clf.predict_proba(feat)[0]

    # Map probabilities to class labels (clf.classes_ may not start at 0)
    classes   = list(clf.classes_)
    prob_dict = {INT_TO_SEV[c]: round(float(p), 4) for c, p in zip(classes, proba)}
    ml_sev    = INT_TO_SEV[pred_int]
    ml_conf   = round(float(proba[classes.index(pred_int)]), 4)

    rule_sev  = (finding.get("severity") or "").lower()
    if hasattr(rule_sev, "value"):
        rule_sev = rule_sev.value

    agrees = (ml_sev == rule_sev)

    return {
        "ml_severity":         ml_sev,
        "ml_confidence":       ml_conf,
        "ml_probabilities":    prob_dict,
        "agrees_with_rule_based": agrees,
    }


def batch_predict(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Predict severity for a list of findings."""
    if not findings:
        return []
    clf  = get_model()
    feat = np.array([_extract_features(f) for f in findings])

    preds = clf.predict(feat)
    probas = clf.predict_proba(feat)
    classes = list(clf.classes_)

    results = []
    for finding, pred_int, proba in zip(findings, preds, probas):
        prob_dict = {INT_TO_SEV[c]: round(float(p), 4) for c, p in zip(classes, proba)}
        ml_sev    = INT_TO_SEV[int(pred_int)]
        ml_conf   = round(float(proba[classes.index(int(pred_int))]), 4)
        rule_sev  = (finding.get("severity") or "").lower()
        agrees    = (ml_sev == rule_sev)
        results.append({
            "finding_id":             finding.get("id"),
            "ml_severity":            ml_sev,
            "ml_confidence":          ml_conf,
            "ml_probabilities":       prob_dict,
            "agrees_with_rule_based": agrees,
        })
    return results


def retrain_on_findings(findings: List[Dict[str, Any]]):
    """
    Fine-tune model on real scan findings from the database.
    Called after each scan completes to improve model over time.
    """
    global _model
    if len(findings) < 5:
        return  # not enough data to fine-tune
    try:
        X = np.array([_extract_features(f) for f in findings])
        y = np.array([SEV_TO_INT.get((f.get("severity") or "info").lower(), 0)
                      for f in findings])
        _model = _train_model(extra_X=X, extra_y=y)
        logger.info("ML model retrained on %d real findings.", len(findings))
    except Exception as e:
        logger.warning("ML retrain failed: %s", e)
