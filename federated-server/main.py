"""
Federated Learning Aggregation Server
Collects model weight submissions from opt-in nodes, runs FedAvg aggregation,
and serves the global model for download.

Deploy this separately from the SBC agent — e.g. on a cloud VPS or GitHub Actions.
Run: uvicorn main:app --host 0.0.0.0 --port 8765
"""

import gzip
import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI SBC Security — Federated Learning Server",
    description="Privacy-preserving model aggregation server for the AI SBC Security community.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Storage paths
DATA_DIR = os.getenv("FL_DATA_DIR", "/var/lib/fl-server")
SUBMISSIONS_DIR = os.path.join(DATA_DIR, "submissions")
GLOBAL_MODEL_FILE = os.path.join(DATA_DIR, "global_model.json.gz")
METADATA_FILE = os.path.join(DATA_DIR, "metadata.json")

# Aggregation config
MIN_SUBMISSIONS_FOR_AGGREGATION = 3    # minimum nodes before aggregating
MAX_SUBMISSIONS_PER_ROUND = 500         # cap per aggregation round
AGGREGATION_INTERVAL = 3600            # 1 hour between aggregation runs
MAX_SUBMISSION_SIZE = 2 * 1024 * 1024  # 2 MB per submission

os.makedirs(SUBMISSIONS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# In-memory state
_submissions: List[dict] = []       # recent submissions awaiting aggregation
_last_aggregation = 0.0
_global_model_data: Optional[bytes] = None
_stats = {
    "total_submissions": 0,
    "total_aggregations": 0,
    "active_nodes": set(),
    "started_at": datetime.now(tz=timezone.utc).isoformat(),
}

_load_metadata_lock = False


# ── Helpers ────────────────────────────────────────────────────────────────────
def _load_global_model():
    global _global_model_data
    if os.path.exists(GLOBAL_MODEL_FILE):
        with open(GLOBAL_MODEL_FILE, "rb") as f:
            _global_model_data = f.read()
        logger.info("Loaded global model from %s", GLOBAL_MODEL_FILE)


def _save_metadata():
    try:
        data = {
            "total_submissions": _stats["total_submissions"],
            "total_aggregations": _stats["total_aggregations"],
            "active_nodes": len(_stats["active_nodes"]),
            "started_at": _stats["started_at"],
            "last_aggregation": datetime.fromtimestamp(
                _last_aggregation, tz=timezone.utc
            ).isoformat() if _last_aggregation else None,
        }
        with open(METADATA_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning("Failed to save metadata: %s", e)


# ── FedAvg aggregation ─────────────────────────────────────────────────────────
def _fedavg_thresholds(submissions: List[dict]) -> Optional[List[List[float]]]:
    """
    Compute FedAvg of tree thresholds across submissions.
    Returns averaged threshold arrays for each tree position.
    """
    if not submissions:
        return None

    # Collect per-tree threshold arrays from all submissions
    per_tree: Dict[int, List[np.ndarray]] = defaultdict(list)

    for sub in submissions:
        trees = sub.get("trees", [])
        for i, tree_data in enumerate(trees[:20]):
            thresh = tree_data.get("threshold")
            if thresh:
                arr = np.array(thresh, dtype=np.float64)
                per_tree[i].append(arr)

    if not per_tree:
        return None

    averaged_trees = []
    for tree_idx in sorted(per_tree.keys()):
        arrays = per_tree[tree_idx]
        if not arrays:
            continue
        # Only average arrays of same shape
        shapes = [a.shape for a in arrays]
        common_shape = max(set(shapes), key=shapes.count)
        compatible = [a for a in arrays if a.shape == common_shape]
        if compatible:
            averaged = np.mean(compatible, axis=0)
            averaged_trees.append(averaged.tolist())

    return averaged_trees if averaged_trees else None


def run_aggregation():
    global _submissions, _last_aggregation, _global_model_data

    if len(_submissions) < MIN_SUBMISSIONS_FOR_AGGREGATION:
        logger.info("Not enough submissions for aggregation (%d/%d)", len(_submissions), MIN_SUBMISSIONS_FOR_AGGREGATION)
        return False

    logger.info("Running FedAvg aggregation over %d submissions", len(_submissions))

    # Take up to MAX_SUBMISSIONS_PER_ROUND most recent
    batch = sorted(_submissions, key=lambda s: s.get("_received_at", 0))[-MAX_SUBMISSIONS_PER_ROUND:]

    # Parse each submission
    parsed = []
    for sub in batch:
        weights = sub.get("weights")
        if weights and isinstance(weights, dict):
            parsed.append(weights)

    if not parsed:
        logger.warning("No parseable submissions in batch")
        return False

    avg_trees = _fedavg_thresholds(parsed)
    if not avg_trees:
        logger.warning("FedAvg produced no trees")
        return False

    # Build global model payload
    n_features = parsed[0].get("n_features", 14)
    global_model = {
        "model_type": "IsolationForest",
        "aggregation": "FedAvg",
        "n_submissions": len(parsed),
        "n_estimators": len(avg_trees),
        "n_features": n_features,
        "trees": [{"threshold": t} for t in avg_trees],
        "aggregated_at": datetime.now(tz=timezone.utc).isoformat(),
        "round": _stats["total_aggregations"] + 1,
    }

    # Serialize and compress
    json_bytes = json.dumps(global_model, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(json_bytes, compresslevel=6)

    # Save to disk
    with open(GLOBAL_MODEL_FILE, "wb") as f:
        f.write(compressed)

    _global_model_data = compressed
    _last_aggregation = time.time()
    _stats["total_aggregations"] += 1

    # Clear processed submissions (keep last 10 for redundancy)
    _submissions = _submissions[-10:]

    _save_metadata()
    logger.info(
        "Aggregation complete: %d trees, %d bytes compressed",
        len(avg_trees), len(compressed),
    )
    return True


# ── Startup ────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    _load_global_model()
    logger.info("Federated Learning Server started")


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service": "AI SBC Security — Federated Learning Server",
        "version": "1.0.0",
        "privacy": "Gaussian differential privacy applied client-side. No raw data accepted.",
        "status": "operational",
    }


@app.get("/api/v1/status")
async def status():
    return {
        "total_submissions": _stats["total_submissions"],
        "total_aggregations": _stats["total_aggregations"],
        "active_nodes": len(_stats["active_nodes"]),
        "pending_submissions": len(_submissions),
        "global_model_available": _global_model_data is not None,
        "global_model_size_kb": round(len(_global_model_data) / 1024, 1) if _global_model_data else 0,
        "last_aggregation": datetime.fromtimestamp(
            _last_aggregation, tz=timezone.utc
        ).isoformat() if _last_aggregation else None,
        "started_at": _stats["started_at"],
    }


@app.post("/api/v1/submit")
async def submit_weights(
    request: Request,
    x_node_id: str = Header(..., alias="X-Node-ID"),
    x_package_hash: str = Header(..., alias="X-Package-Hash"),
):
    """Accept model weight submission from a node."""
    # Validate node ID (must be 64-char hex)
    if len(x_node_id) != 64 or not all(c in "0123456789abcdef" for c in x_node_id.lower()):
        raise HTTPException(400, "Invalid node ID format")

    # Read body
    body = await request.body()
    if len(body) > MAX_SUBMISSION_SIZE:
        raise HTTPException(413, f"Submission too large (max {MAX_SUBMISSION_SIZE} bytes)")
    if not body:
        raise HTTPException(400, "Empty submission")

    # Verify hash
    actual_hash = hashlib.sha256(body).hexdigest()
    if actual_hash != x_package_hash.lower():
        raise HTTPException(400, "Hash mismatch — data corruption in transit")

    # Decompress
    try:
        json_bytes = gzip.decompress(body)
        weights = json.loads(json_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Failed to decompress or parse submission")

    # Validate model type
    if weights.get("model_type") != "IsolationForest":
        raise HTTPException(400, "Unsupported model type")

    # Validate DP was applied
    dp_noise = weights.get("dp_noise_multiplier", 0)
    if dp_noise <= 0:
        raise HTTPException(400, "Submissions without differential privacy are not accepted")

    # Store
    _submissions.append({
        "node_id": x_node_id[:8] + "...",  # truncate for privacy
        "weights": weights,
        "_received_at": time.time(),
    })
    _stats["total_submissions"] += 1
    _stats["active_nodes"].add(x_node_id[:8])

    logger.info(
        "Received submission from node %s... (total=%d pending=%d)",
        x_node_id[:8], _stats["total_submissions"], len(_submissions),
    )

    # Auto-aggregate if enough new submissions
    if len(_submissions) >= MIN_SUBMISSIONS_FOR_AGGREGATION:
        if time.time() - _last_aggregation >= AGGREGATION_INTERVAL:
            run_aggregation()

    _save_metadata()
    return JSONResponse({"status": "accepted", "pending_submissions": len(_submissions)})


@app.get("/api/v1/global_model")
async def get_global_model(
    x_node_id: str = Header(..., alias="X-Node-ID"),
):
    """Serve the aggregated global model to nodes."""
    if _global_model_data is None:
        # Try trigger aggregation with whatever we have
        run_aggregation()
        if _global_model_data is None:
            raise HTTPException(404, "No global model available yet. Submit more local models first.")

    return Response(
        content=_global_model_data,
        media_type="application/octet-stream",
        headers={
            "Content-Encoding": "gzip",
            "X-Model-Round": str(_stats["total_aggregations"]),
            "X-Submissions-Used": str(
                min(len(_submissions) + MAX_SUBMISSIONS_PER_ROUND, _stats["total_submissions"])
            ),
        }
    )


@app.post("/api/v1/admin/aggregate")
async def force_aggregation(request: Request):
    """Manually trigger aggregation (for admin use)."""
    admin_key = request.headers.get("X-Admin-Key", "")
    expected = os.getenv("FL_ADMIN_KEY", "")
    if expected and admin_key != expected:
        raise HTTPException(403, "Unauthorized")

    success = run_aggregation()
    return {"success": success, "total_aggregations": _stats["total_aggregations"]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8765, log_level="info")
