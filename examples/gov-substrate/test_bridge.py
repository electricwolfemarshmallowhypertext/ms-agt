"""Focused contracts using the actual native AGT engine; no external effects."""

import asyncio
import copy
import unittest


class BridgeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from agent_control_specification import AgentControl, EnforcementMode
            from agentmesh.identity.agent_id import AgentIdentity
            from bridge import MANIFEST, BoundaryPolicy, TrustedBridge
        except ImportError as exc:
            raise unittest.SkipTest("run these contracts in the built controller image") from exc
        cls.AgentControl, cls.EnforcementMode = AgentControl, EnforcementMode
        cls.MANIFEST, cls.BoundaryPolicy, cls.TrustedBridge = MANIFEST, BoundaryPolicy, TrustedBridge
        cls.identity = AgentIdentity.create("contract-worker", "operator@example.test")

    def setUp(self):
        class Client:
            def __init__(self):
                self.requests = []
                self.receipt = None

            def request(self, method, path, body=None, session=None):
                self.requests.append((path, copy.deepcopy(body)))
                if path == "/stop":
                    return copy.deepcopy(self.receipt)
                if path == "/authorizations":
                    return {"decision": "allow", "execution_token": "test-grant", "event_id": 1}
                return {"decision": "allow", "outcome": "succeeded", "event_id": 2}

        self.substrate, self.operator = Client(), Client()
        self.bridge = self.TrustedBridge(self.identity, "test-session", self.substrate,
                                         self.operator, "test-session-token", "agent")

    def test_evaluate_only_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "strict AGT enforcement"):
            self.TrustedBridge(self.identity, "s", self.substrate, self.operator,
                               "session", "agent", mode=self.EnforcementMode.EVALUATE_ONLY)

    def test_native_deny_never_calls_substrate(self):
        result = asyncio.run(self.bridge.run("blocked_email", {}, "denied"))
        self.assertEqual(result["system"], "agt")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(self.substrate.requests, [])

    def test_only_native_effective_arguments_are_submitted(self):
        class TransformPolicy(self.BoundaryPolicy):
            def evaluate(self, invocation):
                if invocation["input"]["intervention_point"] == "pre_tool_call":
                    return {"decision": "transform",
                            "transform": {"path": "$target.content", "value": "approved"}}
                return super().evaluate(invocation)

        self.bridge.control = self.AgentControl.from_native(
            self.MANIFEST, policy_dispatcher=TransformPolicy())
        original = {"path": "result.txt", "content": "unapproved"}
        result = asyncio.run(self.bridge.run("write_file", original, "transformed"))
        self.assertEqual(result["outcome"], "succeeded")
        actions = [body["action"] for path, body in self.substrate.requests]
        self.assertEqual(len(actions), 2)
        self.assertTrue(all(action["content"] == "approved" for action in actions))
        self.assertEqual(original["content"], "unapproved")

    def test_wrong_approval_binding_cannot_release_execution(self):
        async def exercise():
            task = asyncio.create_task(self.bridge.run("approval_email", {}, "approval"))
            try:
                while not self.bridge.pending and not task.done():
                    await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertEqual(self.substrate.requests, [])
                with self.assertRaisesRegex(ValueError, "pending action"):
                    self.bridge.resolve("approval", "wrong-action", "allow")
                self.assertEqual(self.substrate.requests, [])
                identity = self.bridge.pending["approval"]["identity"]
                self.bridge.resolve("approval", identity, "deny")
                result = await task
                self.assertEqual(result["decision"], "deny")
                self.assertEqual(self.substrate.requests, [])
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

        asyncio.run(asyncio.wait_for(exercise(), timeout=5))

    def test_shutdown_requires_exact_worker_identity_and_confirmation(self):
        self.bridge.workers = {"generation": "immutable-id"}
        valid = {"agent_did": str(self.identity.did), "session_id": "test-session",
                 "shutdown_confirmed": True,
                 "workers": [{"generation_id": "generation", "runtime_id": "immutable-id",
                              "confirmed": True}]}
        self.operator.receipt = valid
        self.bridge._terminate()
        for change in ({"agent_did": "other"}, {"session_id": "other"},
                       {"shutdown_confirmed": False}, {"workers": []},
                       {"workers": [{"generation_id": "generation", "runtime_id": "other",
                                     "confirmed": True}]},
                       {"workers": [{"generation_id": "generation", "runtime_id": "immutable-id",
                                     "confirmed": False}]}):
            with self.subTest(change=change):
                self.operator.receipt = {**valid, **change}
                with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                    self.bridge._terminate()

    def test_prepared_worker_cannot_skip_runtime_binding(self):
        result = asyncio.run(self.bridge.run("start_worker", {"input_ids": ["input"]},
                                             "worker", prepare_only=True))
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(self.substrate.requests, [])


if __name__ == "__main__":
    unittest.main()
