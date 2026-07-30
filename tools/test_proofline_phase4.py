import copy
import hashlib
import unittest

import loom_proofline


def _contract(request):
    request_hash = hashlib.sha256(request.encode("utf-8")).hexdigest()
    body = {
        "request_hash": request_hash,
        "tier": "M",
        "domain_route": {"consequence": {"class": "material"}},
        "current_facts_to_verify": [],
        "verification_media": [],
    }
    body["contract_hash"] = loom_proofline.digest(body)
    return body


def _draft():
    return {
        "work_orders": [{
            "id": "WO-001",
            "title": "Add gallery navigation",
            "outcome": "Visitors can move to the next and previous artwork.",
            "tasks": ["Implement next and previous controls."],
            "acceptance": ["Observed result: navigation changes the visible artwork."],
            "negative_acceptance": ["Observed rejection: navigation never skips an artwork."],
            "touches": ["src/gallery/**"],
        }, {
            "id": "WO-002",
            "title": "Preserve original artwork",
            "outcome": "Original image files remain unchanged.",
            "tasks": ["Serve derivatives without rewriting originals."],
            "acceptance": ["Observed result: original image digests remain equal."],
            "negative_acceptance": ["Observed rejection: no original image is overwritten."],
            "touches": ["assets/art/**"],
        }]
    }


class ProoflineTests(unittest.TestCase):
    def test_material_ledger_is_deterministic_and_exactly_bound(self):
        request = (
            "Add next and previous gallery navigation. "
            "Preserve every original artwork image.")
        contract = _contract(request)
        first = loom_proofline.build_material_ledger(
            request=request, plan_contract=contract, semantic_draft=_draft())
        second = loom_proofline.build_material_ledger(
            request=request, plan_contract=contract, semantic_draft=_draft())
        self.assertEqual(first, second)
        self.assertEqual(
            [item["work_order"] for item in first["atoms"]],
            ["WO-001", "WO-002"])
        loom_proofline.validate_material_ledger(first, request=request)

    def test_ambiguous_atom_remains_unresolved(self):
        request = "Make the gallery better."
        ledger = loom_proofline.build_material_ledger(
            request=request, plan_contract=_contract(request),
            semantic_draft=_draft())
        self.assertEqual("unresolved", ledger["atoms"][0]["ambiguity"]["state"])
        self.assertIsNone(ledger["atoms"][0]["work_order"])

    def test_file_paths_versions_urls_and_crlf_preserve_exact_source_spans(self):
        request = (
            "Add gallery navigation to src/gallery/app.py on v1.8.19.\r\n"
            "Document https://example.invalid/gallery.html.")
        draft = {
            "work_orders": [{
                "id": "WO-001",
                "title": "Add gallery navigation",
                "outcome": "Gallery navigation works in src/gallery/app.py.",
                "tasks": ["Update src/gallery/app.py for v1.8.19."],
                "acceptance": [
                    "Observe navigation and document "
                    "https://example.invalid/gallery.html."],
                "negative_acceptance": ["No unrelated path changes."],
                "touches": ["src/gallery/app.py"],
            }]
        }
        ledger = loom_proofline.build_material_ledger(
            request=request, plan_contract=_contract(request),
            semantic_draft=draft)
        self.assertEqual(2, len(ledger["atoms"]))
        self.assertEqual(
            "Add gallery navigation to src/gallery/app.py on v1.8.19.",
            ledger["atoms"][0]["normalized_meaning"])
        self.assertEqual(
            "Document https://example.invalid/gallery.html.",
            ledger["atoms"][1]["normalized_meaning"])
        for atom in ledger["atoms"]:
            source = atom["source"]
            exact = request[source["start"]:source["end"]]
            self.assertEqual(atom["normalized_meaning"], " ".join(exact.split()))
            self.assertEqual("resolved", atom["ambiguity"]["state"])
            self.assertEqual("WO-001", atom["work_order"])

    def test_terminal_file_extension_is_not_a_false_intent_atom(self):
        request = "Plan a financial double-entry accounting change to src/app.py"
        draft = {
            "work_orders": [{
                "id": "WO-001",
                "title": "Change double-entry accounting",
                "outcome": "Financial accounting behavior changes in src/app.py.",
                "tasks": ["Update the accounting implementation."],
                "acceptance": ["Observe balanced entries in src/app.py."],
                "negative_acceptance": ["Unbalanced entries remain rejected."],
                "touches": ["src/app.py"],
            }]
        }
        ledger = loom_proofline.build_material_ledger(
            request=request, plan_contract=_contract(request),
            semantic_draft=draft)
        self.assertEqual(1, len(ledger["atoms"]))
        self.assertEqual(request, ledger["atoms"][0]["normalized_meaning"])
        self.assertEqual("resolved", ledger["atoms"][0]["ambiguity"]["state"])
        self.assertEqual("WO-001", ledger["atoms"][0]["work_order"])

    def test_inline_code_quotes_and_unicode_preserve_material_atoms(self):
        cases = [
            "Print exactly `Hello, <name>!`.",
            'Run "python -m unittest -v; echo done!" then inspect results.',
            "Show \u201cReady!\u201d and preserve the Unicode label \u062a\u0645\u0627\u0645.",
            "Keep 'src/gallery/app.py;v=1' unchanged.",
            "Use ``literal `code!` value`` without splitting.",
        ]
        for request in cases:
            with self.subTest(request=request):
                draft = {
                    "work_orders": [{
                        "id": "WO-001",
                        "title": "Preserve exact requested text",
                        "outcome": request,
                        "tasks": [request],
                        "acceptance": [request],
                        "negative_acceptance": ["No unrelated path changes."],
                        "touches": ["src/gallery/app.py"],
                    }]
                }
                ledger = loom_proofline.build_material_ledger(
                    request=request, plan_contract=_contract(request),
                    semantic_draft=draft)
                self.assertEqual(1, len(ledger["atoms"]))
                self.assertEqual(
                    request, ledger["atoms"][0]["normalized_meaning"])
                loom_proofline.validate_material_ledger(
                    ledger, request=request)

    def test_multiline_code_fence_is_one_protected_source_span(self):
        request = (
            "Run this example:\n"
            "```python\n"
            "print('Hello!')\n"
            "raise SystemExit('stop; now')\n"
            "```\n"
            "Then inspect the result.")
        segments = loom_proofline._segments(request)
        self.assertEqual([
            "Run this example:",
            "```python\nprint('Hello!')\nraise SystemExit('stop; now')\n```",
            "Then inspect the result.",
        ], [item[2] for item in segments])

    def test_unterminated_markdown_code_span_fails_closed(self):
        request = "Print `Hello!"
        with self.assertRaisesRegex(
                loom_proofline.ProoflineError, "unterminated Markdown"):
            loom_proofline.build_material_ledger(
                request=request, plan_contract=_contract(request),
                semantic_draft=_draft())

    def test_validator_rejects_resegmented_but_rehashed_ledger(self):
        request = "Print exactly `Hello, <name>!`."
        draft = {
            "work_orders": [{
                "id": "WO-001",
                "title": "Print the exact greeting",
                "outcome": request,
                "tasks": [request],
                "acceptance": [request],
                "negative_acceptance": ["No other output is printed."],
                "touches": ["hello.py"],
            }]
        }
        ledger = loom_proofline.build_material_ledger(
            request=request, plan_contract=_contract(request),
            semantic_draft=draft)
        tampered = copy.deepcopy(ledger)
        first = tampered["atoms"][0]
        first["source"]["end"] -= 2
        exact = request[first["source"]["start"]:first["source"]["end"]]
        first["source"]["text_sha256"] = hashlib.sha256(
            exact.encode("utf-8")).hexdigest()
        first["normalized_meaning"] = " ".join(exact.split())
        first["content_digest"] = loom_proofline.digest({
            key: item for key, item in first.items()
            if key != "content_digest"})
        tampered["ledger_sha256"] = loom_proofline.digest({
            key: item for key, item in tampered.items()
            if key != "ledger_sha256"})
        with self.assertRaisesRegex(
                loom_proofline.ProoflineError, "segmentation changed"):
            loom_proofline.validate_material_ledger(
                tampered, request=request)

    def test_tampered_source_and_digest_fail_closed(self):
        request = "Add gallery navigation."
        ledger = loom_proofline.build_material_ledger(
            request=request, plan_contract=_contract(request),
            semantic_draft=_draft())
        tampered = copy.deepcopy(ledger)
        tampered["atoms"][0]["normalized_meaning"] = "Different"
        with self.assertRaises(loom_proofline.ProoflineError):
            loom_proofline.validate_material_ledger(tampered, request=request)
        with self.assertRaises(loom_proofline.ProoflineError):
            loom_proofline.validate_material_ledger(
                ledger, request=request + " changed")

    def test_graph_rejects_cycles_missing_nodes_and_subject_drift(self):
        request = "Add next and previous gallery navigation."
        contract = _contract(request)
        draft = _draft()
        ledger = loom_proofline.build_material_ledger(
            request=request, plan_contract=contract, semantic_draft=draft)
        assignments = {
            "plan_contract_hash": contract["contract_hash"],
            "assignment_digest": "sha256:" + "a" * 64,
        }
        graph = loom_proofline.build_graph(
            ledger=ledger, plan_contract=contract, semantic_draft=draft,
            assignments=assignments)
        loom_proofline.validate_graph(graph)
        missing = copy.deepcopy(graph)
        missing["edges"][0]["target"] = "work-order:wo-999"
        with self.assertRaises(loom_proofline.ProoflineError):
            loom_proofline.validate_graph(missing)
        cycle = copy.deepcopy(graph)
        body = {
            "edge_id": "edge:cycle",
            "edge_type": "requires",
            "source": "authority:request",
            "target": "atom:intent-001",
            "governing_authority": cycle["nodes"][0]["governing_authority"],
            "subject_digests": [request and contract["request_hash"]],
        }
        cycle["edges"].append({**body, "edge_sha256": loom_proofline.digest(body)})
        cycle["graph_sha256"] = loom_proofline.digest({
            key: value for key, value in cycle.items() if key != "graph_sha256"})
        with self.assertRaises(loom_proofline.ProoflineError):
            loom_proofline.validate_graph(cycle)

    def test_path_matching_is_safe_and_conservative(self):
        self.assertTrue(loom_proofline.path_matches("src/**", "src/a/b.py"))
        self.assertFalse(loom_proofline.path_matches("src/**", "tests/a.py"))
        with self.assertRaises(loom_proofline.ProoflineError):
            loom_proofline.path_matches("../**", "src/a.py")


if __name__ == "__main__":
    unittest.main()
