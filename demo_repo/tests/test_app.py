from app.render import render_invoice
from app import rates


def test_invoice_escapes_customer_name():
    html = render_invoice("<script>alert(1)</script>", [{"name": "Ramen", "price": 980}])
    assert "<script>" not in html
    assert "Ramen: JPY 980" in html


def test_invoice_footer_is_trusted_html():
    html = render_invoice("Aiko", [])
    assert "<footer>Thank you for your business!</footer>" in html


def test_fetch_rates(monkeypatch):
    class Fake:
        def raise_for_status(self): pass
        def json(self): return {"USDJPY": 151.2}
    monkeypatch.setattr(rates.requests, "get", lambda url, timeout: Fake())
    assert rates.fetch_rates("https://example.com")["USDJPY"] == 151.2
