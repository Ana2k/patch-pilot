"""Renders customer invoices as HTML emails."""
from jinja2 import Environment, Markup, escape

env = Environment(autoescape=True)

TEMPLATE = (
    "<h1>Invoice for {{ name }}</h1>"
    "<ul>{% for i in items %}<li>{{ i.name }}: JPY {{ i.price }}</li>{% endfor %}</ul>"
    "{{ footer }}"
)


def render_invoice(customer: str, items: list[dict]) -> str:
    footer = Markup("<footer>Thank you for your business!</footer>")
    return env.from_string(TEMPLATE).render(name=escape(customer), items=items, footer=footer)
