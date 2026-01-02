def calculate_paye(monthly_salary):
    annual = monthly_salary * 12

    relief = max(200_000 + (0.2 * annual), 0)
    taxable = max(annual - relief, 0)

    tax = 0
    brackets = [
        (300_000, 0.07),
        (300_000, 0.11),
        (500_000, 0.15),
        (500_000, 0.19),
        (1_600_000, 0.21),
        (float("inf"), 0.24)
    ]

    for limit, rate in brackets:
        if taxable <= 0:
            break
        portion = min(limit, taxable)
        tax += portion * rate
        taxable -= portion

    return {
        "annual_tax": round(tax, 2),
        "monthly_tax": round(tax / 12, 2)
    }
