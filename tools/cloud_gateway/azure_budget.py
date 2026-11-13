"""Read-only Azure Consumption budget guard; this adapter never creates budgets."""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from dataclasses import dataclass
from urllib.parse import quote
from urllib.request import Request

from .azure_identity import ManagedIdentityCredential
from .safe_http import open_no_redirect, read_bounded, require_json_content_type


def urlopen(request, timeout=10):
    """Compatibility seam backed by the production no-redirect transport."""
    return open_no_redirect(request, timeout=timeout)


class BudgetReadError(RuntimeError):
    pass


@dataclass(frozen=True)
class BudgetSnapshot:
    amount: float
    current_spend: float
    forecast_spend: float | None
    currency: str

    def __post_init__(self):
        values = (self.amount, self.current_spend)
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0
            for value in values
        ):
            raise ValueError("Budget amount and current spend must be finite non-negative numbers")
        if self.forecast_spend is not None and (
            isinstance(self.forecast_spend, bool)
            or not isinstance(self.forecast_spend, (int, float))
            or not math.isfinite(self.forecast_spend)
            or self.forecast_spend < 0
        ):
            raise ValueError("Budget forecast must be a finite non-negative number")
        if self.forecast_spend is not None and self.forecast_spend < self.current_spend:
            raise ValueError("Budget forecast cannot be below current spend")
        if not isinstance(self.currency, str) or not self.currency:
            raise ValueError("Budget currency is required")

    def permits(self, projected_cost: float) -> bool:
        if (isinstance(projected_cost, bool) or not isinstance(projected_cost, (int, float))
                or not math.isfinite(projected_cost) or projected_cost < 0):
            return False
        # A missing forecast is UNKNOWN, not permission to provision.
        if self.currency.upper() != "USD" or self.forecast_spend is None:
            return False
        if self.current_spend + projected_cost > self.amount:
            return False
        return self.forecast_spend + projected_cost <= self.amount


def _amount(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0):
        raise ValueError("Budget amount is not a finite non-negative number")
    return float(value)


class AzureBudgetReader:
    def __init__(self, subscription_id, budget_name, credential=None, timeout=10):
        if not isinstance(subscription_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", subscription_id):
            raise ValueError("Invalid subscription ID")
        if not isinstance(budget_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", budget_name):
            raise ValueError("Invalid budget name")
        self.subscription_id = subscription_id
        self.budget_name = budget_name
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 30:
            raise ValueError("Azure budget timeout must be 1..30 seconds")
        self.credential = credential or ManagedIdentityCredential()
        self.timeout = timeout

    def read(self):
        url = (
            "https://management.azure.com/subscriptions/" + self.subscription_id
            + "/providers/Microsoft.Consumption/budgets/" + quote(self.budget_name, safe="")
            + "?api-version=2023-05-01"
        )
        try:
            token = self.credential.get_token("https://management.azure.com/")
            if not isinstance(token, str) or not token or len(token) > 8192 or "\\r" in token or "\\n" in token:
                raise ValueError("Managed identity returned an invalid token")
            req = Request(url, headers={"Accept": "application/json"})
            req.add_unredirected_header("Authorization", "Bearer " + token)
            with urlopen(req, timeout=self.timeout) as response:
                raw = read_bounded(response, 65536)
                if raw:
                    require_json_content_type(response)
                data = json.loads(raw.decode("utf-8"))
        except BudgetReadError:
            raise
        except ValueError as exc:
            if "size limit" in str(exc):
                raise BudgetReadError("Azure budget response exceeded the size limit") from exc
            raise BudgetReadError("Azure budget response failed validation") from exc
        except Exception as exc:
            raise BudgetReadError("Azure budget read failed: " + type(exc).__name__) from exc
        try:
            properties = data["properties"]
            if properties.get("category") != "Cost":
                raise ValueError("Budget category is not Cost")
            period = properties["timePeriod"]
            start = datetime.fromisoformat(str(period["startDate"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(period["endDate"]).replace("Z", "+00:00"))
            current_time = datetime.now(timezone.utc)
            if (start.tzinfo is None or end.tzinfo is None or start >= end
                    or current_time < start or current_time >= end):
                raise ValueError("Budget time period is not current")
            amount = _amount(properties["amount"])
            current = properties["currentSpend"]
            current_amount = _amount(current["amount"])
            currency = str(current["unit"])
            forecast = properties.get("forecastSpend")
            if not isinstance(forecast, dict) or "amount" not in forecast or "unit" not in forecast:
                raise ValueError("Forecast is missing")
            forecast_amount = _amount(forecast["amount"])
            forecast_currency = str(forecast["unit"])
            if forecast_currency != currency:
                raise ValueError("Forecast currency mismatch")
            return BudgetSnapshot(amount, current_amount, forecast_amount, currency)
        except (KeyError, TypeError, ValueError) as exc:
            raise BudgetReadError("Azure budget response is incomplete or invalid") from exc
