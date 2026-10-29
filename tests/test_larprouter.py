"""Offline regression checks for the REDCON HAWK LarpRouter adapter."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock
from utils.ai_models_utils import (
    validate_api_key, format_model_name_for_litellm, model_completion_options,
    create_model_agent, discover_larprouter_models,
)

class LarpRouterTests(unittest.TestCase):
    def setUp(self):
        self.model = SimpleNamespace(vendor="larprouter", model_name="deepseek-v4.1-flash", api_key="lrsk-" + "x" * 64)
        self.catalog = [{"id": self.model.model_name, "pricing": {"input_per_1m_usd": .01, "output_per_1m_usd": .05}}]

    def test_gateway_key_validation(self):
        self.assertTrue(validate_api_key("larprouter", self.model.api_key))
        self.assertFalse(validate_api_key("larprouter", "sk-invalid"))

    def test_existing_provider_format_preserved(self):
        other = SimpleNamespace(vendor="openai", model_name="gpt-4o")
        self.assertEqual(format_model_name_for_litellm(other), "openai/gpt-4o")
        self.assertEqual(model_completion_options(other), {"model": "openai/gpt-4o"})

    @patch("utils.ai_models_utils.load_larprouter_catalog")
    def test_explicit_credentials_and_pricing(self, catalog):
        catalog.return_value = self.catalog
        options = model_completion_options(self.model)
        self.assertEqual(options["model"], "openai/deepseek-v4.1-flash")
        self.assertEqual(options["api_base"], "https://larprouter.com/v1")
        self.assertEqual(options["api_key"], self.model.api_key)
        self.assertAlmostEqual(options["input_cost_per_token"], 1e-8)
        self.assertAlmostEqual(options["output_cost_per_token"], 5e-8)
        self.assertNotIn(self.model.api_key, format_model_name_for_litellm(self.model))

    @patch("utils.ai_models_utils.load_larprouter_catalog", return_value=[])
    def test_missing_prices_fail_safely(self, catalog):
        with self.assertRaises(ValueError):
            model_completion_options(self.model)

    @patch("utils.ai_models_utils.load_larprouter_catalog")
    def test_agent_uses_its_own_credentials(self, catalog):
        catalog.return_value = self.catalog
        engine = SimpleNamespace(generator_params={})
        agent = SimpleNamespace(generation_engine=engine)
        with patch("nerve.runtime.agent.Agent.create", new=AsyncMock(return_value=agent)):
            result = asyncio.run(create_model_agent(self.model, "generator", "configuration"))
        self.assertIs(result, agent)
        self.assertEqual(engine.generator_params["api_key"], self.model.api_key)
        self.assertIn("input_cost_per_token", engine.generator_params)

    @patch("utils.ai_models_utils.load_larprouter_catalog")
    def test_discovery_keeps_flash_and_owner(self, catalog):
        from unittest.mock import MagicMock
        catalog.return_value = self.catalog
        session = MagicMock()
        session.query.return_value.filter_by.return_value.first.return_value = None
        result = discover_larprouter_models(None, session, self.model.api_key, owner_id=17)
        self.assertIsNone(result["error"])
        self.assertEqual(result["successful_models"], [self.model.model_name])
        added = session.add.call_args.args[0]
        self.assertEqual(added.owner_id, 17)
        self.assertEqual(added.vendor, "larprouter")

if __name__ == "__main__":
    unittest.main()
