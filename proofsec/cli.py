"""ProofSec command line interface."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from proofsec.contract import load_security_model, merge_invariants, propose_security_contract, write_contract
from proofsec.invariants import (
    confirm_all_proposed,
    evaluate_invariants,
    invariant_state_payload,
    load_model_if_present,
    load_security_contract,
    update_invariant_status,
    write_invariant_state,
)
from proofsec.llm import LLMError, OllamaProvider, suggest_invariants_with_llm
from proofsec.security_model import build_security_model, write_model_json, write_model_sqlite


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="proofsec",
        description="ProofSec security model and exploitability validation for authorized local applications.",
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Build a local application security model.")
    analyze.add_argument("target", help="Project folder to analyze.")
    analyze.add_argument("--stack", choices=["auto", "spring", "spring-boot"], default="auto")
    analyze.add_argument("--out", default="proofsec-security-model.json", help="Security model JSON output path.")
    analyze.add_argument("--sqlite", default=None, help="Optional SQLite database output path.")

    contract = subparsers.add_parser("contract", help="Generate a proposed Security Contract.")
    contract.add_argument("target", nargs="?", default=None, help="Project folder to analyze.")
    contract.add_argument("--model", default=None, help="Existing ProofSec security model JSON.")
    contract.add_argument("--stack", choices=["auto", "spring", "spring-boot"], default="auto")
    contract.add_argument("--out", default="security-contract.json", help="Security Contract JSON/YAML output path.")
    contract.add_argument("--ollama", action="store_true", help="Ask local Ollama for additional proposed invariants.")
    contract.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Ollama base URL.")
    contract.add_argument("--ollama-model", default="llama3.1", help="Ollama model name.")
    contract.add_argument("--ollama-timeout", type=int, default=60, help="Ollama request timeout in seconds.")

    invariants = subparsers.add_parser("invariants", help="Review and evaluate Security Contract invariants.")
    invariants.add_argument("--contract", required=True, help="Security Contract JSON path.")
    invariants.add_argument("--model", default=None, help="Optional ProofSec security model JSON for endpoint coverage.")
    invariants.add_argument("--out", default="invariant-state.json", help="Invariant state JSON output path.")
    invariants.add_argument("--updated-contract", default=None, help="Optional output path for contract after status changes.")
    invariants.add_argument("--confirm", action="append", default=[], help="Confirm an invariant by id. Can be repeated.")
    invariants.add_argument("--reject", action="append", default=[], help="Reject an invariant by id. Can be repeated.")
    invariants.add_argument("--confirm-all", action="store_true", help="Confirm all proposed invariants.")

    return parser.parse_args(argv)


def command_analyze(args: argparse.Namespace) -> int:
    try:
        model = build_security_model(Path(args.target), args.stack)
        output = Path(args.out)
        write_model_json(model, output)
        model_id = None
        if args.sqlite:
            model_id = write_model_sqlite(model, Path(args.sqlite))
    except Exception as exc:
        print(f"ProofSec analyze failed: {exc}", file=sys.stderr)
        return 2

    kpis = model.kpis()
    print("ProofSec security model generated")
    print(f"Framework: {model.framework}")
    print(f"Endpoints discovered: {kpis['endpoints_discovered']}")
    print(f"Resources discovered: {kpis['resources_discovered']}")
    print(f"Roles discovered: {kpis['roles_discovered']}")
    print(f"Security edges: {kpis['security_edges']}")
    print(f"Model JSON: {output.expanduser().resolve()}")
    if args.sqlite:
        print(f"SQLite model id: {model_id}")
        print(f"SQLite: {Path(args.sqlite).expanduser().resolve()}")
    return 0


def command_contract(args: argparse.Namespace) -> int:
    try:
        if args.model:
            model = load_security_model(Path(args.model))
        elif args.target:
            model = build_security_model(Path(args.target), args.stack)
        else:
            print("ProofSec contract requires either a target folder or --model.", file=sys.stderr)
            return 2
        contract = propose_security_contract(model)
        if args.ollama:
            provider = OllamaProvider(args.ollama_url, args.ollama_model)
            try:
                contract = merge_invariants(
                    contract,
                    suggest_invariants_with_llm(model, provider, timeout=max(args.ollama_timeout, 1)),
                )
                contract.notes.append(
                    f"Ollama suggestions were added as inferred/proposed only using model {args.ollama_model}."
                )
            except (LLMError, ValueError) as exc:
                contract.notes.append(f"Ollama invariant suggestions unavailable: {friendly_llm_error(exc)}")
        output = Path(args.out)
        write_contract(contract, output)
    except Exception as exc:
        print(f"ProofSec contract failed: {exc}", file=sys.stderr)
        return 2

    kpis = contract.kpis()
    print("ProofSec Security Contract proposed")
    print(f"Roles: {kpis['roles']}")
    print(f"Resources: {kpis['resources']}")
    print(f"Permissions: {kpis['permissions']}")
    print(f"Invariants proposed: {kpis['invariants']}")
    print(f"Confirmed invariants: {kpis['confirmed_invariants']}")
    print(f"Contract: {output.expanduser().resolve()}")
    return 0


def friendly_llm_error(exc: Exception) -> str:
    message = str(exc)
    if "Operation not permitted" in message:
        return "local Ollama could not be reached from this execution environment."
    if "Connection refused" in message or "Failed to establish" in message:
        return "local Ollama is not running or not listening on the configured URL."
    return message[:240]


def command_invariants(args: argparse.Namespace) -> int:
    try:
        contract = load_security_contract(Path(args.contract))
        if args.confirm_all:
            contract = confirm_all_proposed(contract)
        for invariant_id in args.confirm:
            contract = update_invariant_status(contract, invariant_id, "confirmed")
        for invariant_id in args.reject:
            contract = update_invariant_status(contract, invariant_id, "rejected")
        model = load_model_if_present(args.model)
        evaluations = evaluate_invariants(contract, model)
        payload = invariant_state_payload(contract, evaluations)
        output = Path(args.out)
        write_invariant_state(payload, output)
        if args.updated_contract:
            write_contract(contract, Path(args.updated_contract))
    except Exception as exc:
        print(f"ProofSec invariants failed: {exc}", file=sys.stderr)
        return 2

    print("ProofSec invariants evaluated")
    print(f"Invariants: {len(evaluations)}")
    for readiness, count in sorted(payload["readiness_counts"].items()):
        print(f"{readiness}: {count}")
    print(f"Invariant state: {output.expanduser().resolve()}")
    if args.updated_contract:
        print(f"Updated contract: {Path(args.updated_contract).expanduser().resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "analyze":
        return command_analyze(args)
    if args.command == "contract":
        return command_contract(args)
    if args.command == "invariants":
        return command_invariants(args)
    print("Use one of: analyze, contract, invariants", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
