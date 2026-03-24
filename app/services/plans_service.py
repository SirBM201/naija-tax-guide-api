from __future__ import annotations

from typing import Any, Dict, List, Optional


PLAN_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "code": "starter_monthly",
        "name": "Starter Monthly",
        "tier": "starter",
        "cycle": "monthly",
        "price": 5000,
        "currency": "NGN",
        "duration_days": 30,
        "credits": 100,
        "support_level": "Standard support",
        "recommended": False,
        "active": True,
        "description": "Simple AI-guided tax help for lighter personal tax questions and early-stage users.",
        "audience": "Best for individuals, salary earners, and first-time users.",
        "sort_order": 10,
    },
    {
        "code": "starter_quarterly",
        "name": "Starter Quarterly",
        "tier": "starter",
        "cycle": "quarterly",
        "price": 14000,
        "currency": "NGN",
        "duration_days": 90,
        "credits": 300,
        "support_level": "Standard support",
        "recommended": False,
        "active": True,
        "description": "Simple AI-guided tax help for lighter personal tax questions and early-stage users.",
        "audience": "Best for individuals, salary earners, and first-time users.",
        "sort_order": 20,
    },
    {
        "code": "starter_yearly",
        "name": "Starter Yearly",
        "tier": "starter",
        "cycle": "yearly",
        "price": 51000,
        "currency": "NGN",
        "duration_days": 365,
        "credits": 1200,
        "support_level": "Standard support",
        "recommended": False,
        "active": True,
        "description": "Simple AI-guided tax help for lighter personal tax questions and early-stage users.",
        "audience": "Best for individuals, salary earners, and first-time users.",
        "sort_order": 30,
    },
    {
        "code": "professional_monthly",
        "name": "Professional Monthly",
        "tier": "professional",
        "cycle": "monthly",
        "price": 12000,
        "currency": "NGN",
        "duration_days": 30,
        "credits": 300,
        "support_level": "Priority support",
        "recommended": True,
        "active": True,
        "description": "Stronger monthly usage capacity for users who need more regular tax guidance and compliance support.",
        "audience": "Best for freelancers, consultants, creators, and SMEs.",
        "sort_order": 40,
    },
    {
        "code": "professional_quarterly",
        "name": "Professional Quarterly",
        "tier": "professional",
        "cycle": "quarterly",
        "price": 33600,
        "currency": "NGN",
        "duration_days": 90,
        "credits": 900,
        "support_level": "Priority support",
        "recommended": True,
        "active": True,
        "description": "Stronger monthly usage capacity for users who need more regular tax guidance and compliance support.",
        "audience": "Best for freelancers, consultants, creators, and SMEs.",
        "sort_order": 50,
    },
    {
        "code": "professional_yearly",
        "name": "Professional Yearly",
        "tier": "professional",
        "cycle": "yearly",
        "price": 122400,
        "currency": "NGN",
        "duration_days": 365,
        "credits": 3600,
        "support_level": "Priority support",
        "recommended": True,
        "active": True,
        "description": "Stronger monthly usage capacity for users who need more regular tax guidance and compliance support.",
        "audience": "Best for freelancers, consultants, creators, and SMEs.",
        "sort_order": 60,
    },
    {
        "code": "business_monthly",
        "name": "Business Monthly",
        "tier": "business",
        "cycle": "monthly",
        "price": 25000,
        "currency": "NGN",
        "duration_days": 30,
        "credits": 800,
        "support_level": "Priority support + account review",
        "recommended": False,
        "active": True,
        "description": "Higher usage capacity and stronger support for businesses or users who expect more continuous activity.",
        "audience": "Best for heavier usage, business support, and ongoing tax guidance needs.",
        "sort_order": 70,
    },
    {
        "code": "business_quarterly",
        "name": "Business Quarterly",
        "tier": "business",
        "cycle": "quarterly",
        "price": 70000,
        "currency": "NGN",
        "duration_days": 90,
        "credits": 2400,
        "support_level": "Priority support + account review",
        "recommended": False,
        "active": True,
        "description": "Higher usage capacity and stronger support for businesses or users who expect more continuous activity.",
        "audience": "Best for heavier usage, business support, and ongoing tax guidance needs.",
        "sort_order": 80,
    },
    {
        "code": "business_yearly",
        "name": "Business Yearly",
        "tier": "business",
        "cycle": "yearly",
        "price": 255000,
        "currency": "NGN",
        "duration_days": 365,
        "credits": 9600,
        "support_level": "Priority support + account review",
        "recommended": False,
        "active": True,
        "description": "Higher usage capacity and stronger support for businesses or users who expect more continuous activity.",
        "audience": "Best for heavier usage, business support, and ongoing tax guidance needs.",
        "sort_order": 90,
    },
]


def _normalize_code(plan_code: str | None) -> str:
    return str(plan_code or "").strip().lower()


def list_plans(active_only: bool = True) -> List[Dict[str, Any]]:
    plans = [dict(plan) for plan in PLAN_DEFINITIONS]
    if active_only:
        plans = [plan for plan in plans if bool(plan.get("active", True))]
    return sorted(plans, key=lambda p: int(p.get("sort_order") or 0))


def get_plan(plan_code: str | None) -> Optional[Dict[str, Any]]:
    code = _normalize_code(plan_code)
    if not code:
        return None

    for plan in PLAN_DEFINITIONS:
        if _normalize_code(plan.get("code")) == code:
            return dict(plan)

    return None


def list_plans_by_cycle(cycle: str, active_only: bool = True) -> List[Dict[str, Any]]:
    cycle = _normalize_code(cycle)
    plans = list_plans(active_only=active_only)
    return [plan for plan in plans if _normalize_code(plan.get("cycle")) == cycle]


def list_plans_by_tier(tier: str, active_only: bool = True) -> List[Dict[str, Any]]:
    tier = _normalize_code(tier)
    plans = list_plans(active_only=active_only)
    return [plan for plan in plans if _normalize_code(plan.get("tier")) == tier]
