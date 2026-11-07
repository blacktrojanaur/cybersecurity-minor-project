"""
testbed/evaluate_model.py – Evaluation wrapper for model benchmarking.
======================================================================
Invokes the evaluation pipeline from evaluation/evaluate.py.

Usage:
    python testbed/evaluate_model.py [--seed 42]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from evaluation.evaluate import run_evaluation

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate ZTSP Models")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--data-dir", type=str, default="testbed/data", help="Dataset directory")
    args = parser.parse_args()

    run_evaluation(data_dir=Path(args.data_dir), seed=args.seed)

