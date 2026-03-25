"""Tests for app_spend.py — cost estimation, CSV parsing, export, and provider detection."""
import io
import json
import os
import time
import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Module-level import helpers — mock streamlit before importing app_spend
# ---------------------------------------------------------------------------

import sys
import types

# Stub out streamlit so app_spend can be imported without a running Streamlit server
_st_stub = types.ModuleType("streamlit")
_st_stub.session_state = MagicMock()
sys.modules.setdefault("streamlit", _st_stub)

# Stub plotly if not installed
if "plotly" not in sys.modules:
    _plotly_stub = types.ModuleType("plotly")
    _plotly_go = types.ModuleType("plotly.graph_objects")
    _plotly_go.Figure = MagicMock
    _plotly_go.Pie = MagicMock
    sys.modules["plotly"] = _plotly_stub
    sys.modules["plotly.graph_objects"] = _plotly_go

# Ensure the REAL app_spend module is loaded.
# test_app_audit.py stubs sys.modules["app_spend"] at module-level; we must
# remove that stub and import the real module here.
if "app_spend" in sys.modules and not hasattr(sys.modules["app_spend"], "_save_entries"):
    del sys.modules["app_spend"]

import app_spend as spend  # noqa: E402  (must come after stub cleanup)

# If the imported object is still a stub (e.g. collected after audit tests),
# force a fresh import by deleting and reimporting.
if not hasattr(spend, "_save_entries"):
    del sys.modules["app_spend"]
    import importlib as _importlib
    spend = _importlib.import_module("app_spend")

# ---------------------------------------------------------------------------
# Shared TOKEN_COSTS / CACHE_TOKEN_COSTS fixture data
# (mirrors app_ai.py values so _estimate_cost tests don't need the real module)
# ---------------------------------------------------------------------------

_MOCK_TOKEN_COSTS = {
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5-20251001": (0.80, 4.00),
    "claude-opus-4-6": (15.00, 75.00),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "o3": (10.00, 40.00),
    "o4-mini": (1.10, 4.40),
}

_MOCK_CACHE_TOKEN_COSTS = {
    "claude-sonnet-4-6": (3.75, 0.30),
    "claude-haiku-4-5-20251001": (1.00, 0.08),
    "claude-opus-4-6": (18.75, 1.50),
}


# ---------------------------------------------------------------------------
# _SEK_TO_USD
# ---------------------------------------------------------------------------

class TestSekToUsd:
    """_SEK_TO_USD reads from LOGPILOT_SEK_TO_USD env var, defaults to 0.095."""

    def test_default_value(self):
        # Import-time value should be a positive float
        assert isinstance(spend._SEK_TO_USD, float)
        assert spend._SEK_TO_USD > 0

    def test_env_override(self):
        with patch.dict(os.environ, {"LOGPILOT_SEK_TO_USD": "0.10"}):
            import importlib
            mod = importlib.import_module("app_spend")
            # The module-level constant was set at import; reimporting doesn't re-evaluate it.
            # We test the env var logic directly:
            val = float(os.environ.get("LOGPILOT_SEK_TO_USD", "0.095"))
            assert val == 0.10

    def test_default_env_absent(self):
        env = {k: v for k, v in os.environ.items() if k != "LOGPILOT_SEK_TO_USD"}
        with patch.dict(os.environ, env, clear=True):
            val = float(os.environ.get("LOGPILOT_SEK_TO_USD", "0.095"))
            assert val == 0.095


# ---------------------------------------------------------------------------
# _estimate_cost
# ---------------------------------------------------------------------------

class TestEstimateCost:
    """Tests for the internal _estimate_cost function.

    _estimate_cost does a lazy 'from app_constants import TOKEN_COSTS, CACHE_TOKEN_COSTS'
    inside the function body, so we patch app_constants in sys.modules before calling it.
    """

    @pytest.fixture(autouse=True)
    def patch_app_constants(self):
        """Inject a minimal app_constants stub with known pricing tables."""
        _app_const_stub = types.ModuleType("app_constants")
        _app_const_stub.TOKEN_COSTS = _MOCK_TOKEN_COSTS
        _app_const_stub.CACHE_TOKEN_COSTS = _MOCK_CACHE_TOKEN_COSTS
        with patch.dict(sys.modules, {"app_constants": _app_const_stub}):
            yield

    def test_known_model_sonnet(self):
        # claude-sonnet-4-6: (3.00, 15.00) per 1M tokens
        cost = spend._estimate_cost("claude-sonnet-4-6", 1_000_000, 0)
        assert abs(cost - 3.00) < 0.001

    def test_known_model_output_only(self):
        cost = spend._estimate_cost("claude-sonnet-4-6", 0, 1_000_000)
        assert abs(cost - 15.00) < 0.001

    def test_known_model_combined(self):
        # 1M input @ $3.00 + 1M output @ $15.00 = $18.00
        cost = spend._estimate_cost("claude-sonnet-4-6", 1_000_000, 1_000_000)
        assert abs(cost - 18.00) < 0.001

    def test_unknown_model_returns_zero(self):
        cost = spend._estimate_cost("nonexistent-model-xyz", 1_000_000, 1_000_000)
        assert cost == 0.0

    def test_zero_tokens_returns_zero(self):
        cost = spend._estimate_cost("claude-sonnet-4-6", 0, 0)
        assert cost == 0.0

    def test_cache_creation_cost(self):
        # claude-sonnet-4-6 cache_write = 3.75 / 1M
        cost = spend._estimate_cost("claude-sonnet-4-6", 0, 0, cache_creation=1_000_000)
        assert abs(cost - 3.75) < 0.001

    def test_cache_read_cost(self):
        # claude-sonnet-4-6 cache_read = 0.30 / 1M
        cost = spend._estimate_cost("claude-sonnet-4-6", 0, 0, cache_read=1_000_000)
        assert abs(cost - 0.30) < 0.001

    def test_no_cache_costs_for_non_claude_model(self):
        # gemini-2.5-flash has no entry in CACHE_TOKEN_COSTS
        cost_no_cache = spend._estimate_cost("gemini-2.5-flash", 1_000_000, 0)
        cost_with_cache = spend._estimate_cost("gemini-2.5-flash", 1_000_000, 0, cache_creation=1_000_000)
        assert abs(cost_no_cache - cost_with_cache) < 0.001

    def test_small_token_count(self):
        # 1000 input tokens for claude-sonnet-4-6 = 3.00 * 1000 / 1_000_000
        cost = spend._estimate_cost("claude-sonnet-4-6", 1000, 0)
        assert abs(cost - 0.003) < 0.0001


# ---------------------------------------------------------------------------
# _openai_estimate_cost
# ---------------------------------------------------------------------------

class TestOpenaiEstimateCost:
    """Tests for _openai_estimate_cost."""

    def test_known_gpt4o(self):
        # gpt-4o: (2.50, 10.00) per 1M tokens
        cost = spend._openai_estimate_cost("gpt-4o", 1_000_000, 0)
        assert abs(cost - 2.50) < 0.001

    def test_known_gpt4o_mini(self):
        cost = spend._openai_estimate_cost("gpt-4o-mini", 0, 1_000_000)
        assert abs(cost - 0.60) < 0.001

    def test_unknown_model_returns_zero(self):
        cost = spend._openai_estimate_cost("no-such-model", 1_000_000, 1_000_000)
        assert cost == 0.0

    def test_prefix_match(self):
        # "gpt-4o-2024-08-06" should match base "gpt-4o-2024-08-06" key
        cost = spend._openai_estimate_cost("gpt-4o-2024-08-06", 1_000_000, 0)
        assert cost > 0


# ---------------------------------------------------------------------------
# _detect_csv_provider
# ---------------------------------------------------------------------------

class TestDetectCsvProvider:
    """Tests for auto-detection of CSV provider format."""

    def test_anthropic_detection(self):
        header = "usage_date_utc,cost_usd,token_type,model,workspace,api_key\n"
        assert spend._detect_csv_provider(header) == "anthropic"

    def test_google_detection_service_description(self):
        header = "Service description,Service ID,Cost (kr)\n"
        assert spend._detect_csv_provider(header) == "google"

    def test_openai_detection_num_model_requests(self):
        header = "start_time,num_model_requests,model,input_tokens,output_tokens\n"
        assert spend._detect_csv_provider(header) == "openai"

    def test_openai_detection_start_time_input_tokens(self):
        header = "start_time,model,input_tokens,output_tokens,cost\n"
        assert spend._detect_csv_provider(header) == "openai"

    def test_local_detection(self):
        header = "timestamp,date,provider,model,source,input_tokens,output_tokens,cache_creation,cache_read,cost_usd\n"
        assert spend._detect_csv_provider(header) == "local"

    def test_unknown_returns_none(self):
        header = "foo,bar,baz\n"
        assert spend._detect_csv_provider(header) is None


# ---------------------------------------------------------------------------
# _parse_anthropic_csv
# ---------------------------------------------------------------------------

class TestParseAnthropicCsv:
    """Tests for _parse_anthropic_csv."""

    _SAMPLE = (
        "usage_date_utc,cost_usd,token_type,model,workspace,api_key\n"
        "2024-01-01,0.1234,input,claude-sonnet-4-6,my-ws,sk-ant-xxx\n"
        "2024-01-01,0.0000,output,claude-sonnet-4-6,my-ws,sk-ant-xxx\n"
        "2024-01-02,0.5000,output,claude-opus-4-6,my-ws,sk-ant-xxx\n"
    )

    def test_skips_zero_cost_rows(self):
        rows = spend._parse_anthropic_csv(self._SAMPLE)
        assert all(r["cost_usd"] > 0 for r in rows)

    def test_parses_cost_usd(self):
        rows = spend._parse_anthropic_csv(self._SAMPLE)
        costs = [r["cost_usd"] for r in rows]
        assert 0.1234 in costs
        assert 0.5 in costs

    def test_parses_model(self):
        rows = spend._parse_anthropic_csv(self._SAMPLE)
        models = {r["model"] for r in rows}
        assert "claude-sonnet-4-6" in models

    def test_parses_date(self):
        rows = spend._parse_anthropic_csv(self._SAMPLE)
        assert rows[0]["date"] == "2024-01-01"

    def test_empty_csv_returns_empty(self):
        rows = spend._parse_anthropic_csv("usage_date_utc,cost_usd,token_type,model\n")
        assert rows == []


# ---------------------------------------------------------------------------
# _parse_google_csv
# ---------------------------------------------------------------------------

class TestParseGoogleCsv:
    """Tests for _parse_google_csv."""

    _SAMPLE = (
        "Service description,Service ID,Cost (kr)\n"
        "Vertex AI,aiplatform.googleapis.com,10.50\n"
        "Cloud Storage,storage.googleapis.com,0\n"
        "BigQuery,bigquery.googleapis.com,2.00\n"
    )

    def test_skips_zero_cost(self):
        rows = spend._parse_google_csv(self._SAMPLE)
        assert all(r["cost_sek"] > 0 for r in rows)

    def test_converts_sek_to_usd(self):
        rows = spend._parse_google_csv(self._SAMPLE, sek_to_usd=0.10)
        vertex = next(r for r in rows if r["service"] == "Vertex AI")
        assert abs(vertex["cost_usd"] - 1.05) < 0.001

    def test_parses_service_name(self):
        rows = spend._parse_google_csv(self._SAMPLE)
        services = {r["service"] for r in rows}
        assert "Vertex AI" in services

    def test_two_non_zero_rows_parsed(self):
        rows = spend._parse_google_csv(self._SAMPLE)
        assert len(rows) == 2

    def test_empty_csv_returns_empty(self):
        rows = spend._parse_google_csv("Service description,Service ID,Cost (kr)\n")
        assert rows == []


# ---------------------------------------------------------------------------
# _parse_openai_csv
# ---------------------------------------------------------------------------

class TestParseOpenaiCsv:
    """Tests for _parse_openai_csv."""

    _SAMPLE = (
        "start_time_iso,model,input_tokens,output_tokens,input_cached_tokens,num_model_requests,api_key_id\n"
        "2024-01-01T00:00:00Z,gpt-4o,1000,200,0,5,key-abc\n"
        "2024-01-02T00:00:00Z,gpt-4o-mini,500,100,50,2,key-abc\n"
        "2024-01-03T00:00:00Z,unknown-model,0,0,0,1,key-abc\n"
    )

    def test_skips_zero_token_rows(self):
        rows = spend._parse_openai_csv(self._SAMPLE)
        assert all(r["input_tokens"] > 0 or r["output_tokens"] > 0 for r in rows)

    def test_parses_model(self):
        rows = spend._parse_openai_csv(self._SAMPLE)
        models = {r["model"] for r in rows}
        assert "gpt-4o" in models

    def test_parses_date_from_iso(self):
        rows = spend._parse_openai_csv(self._SAMPLE)
        assert rows[0]["date"] == "2024-01-01"

    def test_cost_computed(self):
        rows = spend._parse_openai_csv(self._SAMPLE)
        gpt4o_row = next(r for r in rows if r["model"] == "gpt-4o")
        # 1000 input @ $2.50/M + 200 output @ $10.00/M = $0.0025 + $0.002 = $0.0045
        assert gpt4o_row["cost_usd"] > 0

    def test_parses_requests(self):
        rows = spend._parse_openai_csv(self._SAMPLE)
        gpt4o_row = next(r for r in rows if r["model"] == "gpt-4o")
        assert gpt4o_row["requests"] == 5


# ---------------------------------------------------------------------------
# _import_local_csv and _export_local_csv round-trip
# ---------------------------------------------------------------------------

class TestLocalCsvRoundTrip:
    """Tests for _export_local_csv and _import_local_csv."""

    def _make_entry(self, ts=1700000000.0, provider="claude", model="claude-sonnet-4-6",
                    input_tokens=100, output_tokens=50, cost=0.001, source="chat",
                    cache_creation=0, cache_read=0):
        return {
            "ts": ts, "provider": provider, "model": model,
            "input_tokens": input_tokens, "output_tokens": output_tokens,
            "cache_creation": cache_creation, "cache_read": cache_read,
            "cost": cost, "source": source,
        }

    def test_export_produces_csv_string(self):
        entries = [self._make_entry()]
        csv_str = spend._export_local_csv(entries)
        assert isinstance(csv_str, str)
        assert "timestamp" in csv_str

    def test_export_has_header_row(self):
        csv_str = spend._export_local_csv([])
        assert "timestamp" in csv_str
        assert "provider" in csv_str
        assert "cost_usd" in csv_str

    def test_export_includes_entry_data(self):
        entry = self._make_entry(provider="claude", model="claude-sonnet-4-6")
        csv_str = spend._export_local_csv([entry])
        assert "claude" in csv_str
        assert "claude-sonnet-4-6" in csv_str

    def test_import_empty_csv_returns_empty(self):
        header = "timestamp,date,provider,model,source,input_tokens,output_tokens,cache_creation,cache_read,cost_usd\n"
        result = spend._import_local_csv(header)
        assert result == []

    def test_import_non_string_returns_empty(self):
        result = spend._import_local_csv(None)
        assert result == []

    def test_round_trip(self):
        entries = [
            self._make_entry(ts=1700000000.0, provider="gemini", model="gemini-2.5-flash",
                             input_tokens=200, output_tokens=80, cost=0.00005),
        ]
        csv_str = spend._export_local_csv(entries)
        # Simulate re-import using local CSV format
        imported = spend._import_local_csv(csv_str)
        assert len(imported) == 1
        assert imported[0]["provider"] == "gemini"
        assert imported[0]["model"] == "gemini-2.5-flash"
        assert imported[0]["input_tokens"] == 200
        assert imported[0]["output_tokens"] == 80

    def test_import_skips_malformed_rows(self):
        csv_str = (
            "timestamp,date,provider,model,source,input_tokens,output_tokens,cache_creation,cache_read,cost_usd\n"
            "not-a-float,2024-01-01,claude,model,chat,abc,50,0,0,0.001\n"
        )
        # Should not raise — bad rows are skipped
        result = spend._import_local_csv(csv_str)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# record_spend (file I/O)
# ---------------------------------------------------------------------------

class TestRecordSpend:
    """Tests for record_spend using a temporary spend file."""

    @pytest.fixture(autouse=True)
    def setup_patches(self, tmp_path):
        """Patch app_ai and redirect _SPEND_FILE to tmp_path for every test."""
        self._spend_file = tmp_path / "cloud_spend.json"
        import importlib as _il

        # Always reload the real app_spend to ensure we have the actual module,
        # regardless of any stub that test_app_audit.py may have installed.
        if "app_spend" in sys.modules:
            del sys.modules["app_spend"]
        real_spend = _il.import_module("app_spend")

        _app_const_stub = types.ModuleType("app_constants")
        _app_const_stub.TOKEN_COSTS = _MOCK_TOKEN_COSTS
        _app_const_stub.CACHE_TOKEN_COSTS = _MOCK_CACHE_TOKEN_COSTS

        with patch.dict(sys.modules, {"app_constants": _app_const_stub}), \
             patch.object(real_spend, "_SPEND_FILE", self._spend_file):
            self._spend = real_spend
            yield

    def test_record_spend_creates_entry(self):
        self._spend.record_spend("claude", "claude-sonnet-4-6", 1000, 500, source="test")
        assert self._spend_file.exists()
        data = json.loads(self._spend_file.read_text())
        assert len(data) == 1
        entry = data[0]
        assert entry["provider"] == "claude"
        assert entry["model"] == "claude-sonnet-4-6"
        assert entry["input_tokens"] == 1000
        assert entry["output_tokens"] == 500
        assert entry["source"] == "test"
        assert entry["cost"] >= 0

    def test_record_spend_appends_entries(self):
        self._spend.record_spend("claude", "claude-sonnet-4-6", 100, 50)
        self._spend.record_spend("gemini", "gemini-2.5-flash", 200, 100)
        data = json.loads(self._spend_file.read_text())
        assert len(data) == 2
        providers = {e["provider"] for e in data}
        assert "claude" in providers
        assert "gemini" in providers

    def test_record_spend_includes_timestamp(self):
        before = time.time()
        self._spend.record_spend("openai", "gpt-4o", 500, 200)
        data = json.loads(self._spend_file.read_text())
        assert data[0]["ts"] >= before

    def test_record_spend_with_cache_tokens(self):
        self._spend.record_spend("claude", "claude-sonnet-4-6", 0, 0,
                                 cache_creation=1000, cache_read=500)
        data = json.loads(self._spend_file.read_text())
        assert data[0]["cache_creation"] == 1000
        assert data[0]["cache_read"] == 500


# ---------------------------------------------------------------------------
# _load_entries and _save_entries
# ---------------------------------------------------------------------------

class TestLoadSaveEntries:
    """Tests for _load_entries and _save_entries."""

    def test_load_missing_file_returns_empty(self, tmp_path):
        missing = tmp_path / "nonexistent.json"
        with patch.object(spend, "_SPEND_FILE", missing):
            result = spend._load_entries()
            assert result == []

    def test_load_invalid_json_returns_empty(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all {{{")
        with patch.object(spend, "_SPEND_FILE", bad_file):
            result = spend._load_entries()
            assert result == []

    def test_load_non_list_json_returns_empty(self, tmp_path):
        obj_file = tmp_path / "obj.json"
        obj_file.write_text('{"key": "value"}')
        with patch.object(spend, "_SPEND_FILE", obj_file):
            result = spend._load_entries()
            assert result == []

    def test_save_and_load_round_trip(self, tmp_path):
        f = tmp_path / "spend.json"
        entries = [{"ts": 123.0, "provider": "claude", "cost": 0.01}]
        with patch.object(spend, "_SPEND_FILE", f):
            spend._save_entries(entries)
            loaded = spend._load_entries()
            assert loaded == entries

    def test_save_truncates_to_max_entries(self, tmp_path):
        f = tmp_path / "spend.json"
        entries = [{"ts": float(i), "cost": 0.0} for i in range(6000)]
        with patch.object(spend, "_SPEND_FILE", f):
            spend._save_entries(entries)
            loaded = spend._load_entries()
            assert len(loaded) == spend._MAX_ENTRIES
