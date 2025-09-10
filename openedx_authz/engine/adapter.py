"""
Extended adapter for the casbin model.
"""

from casbin import persist
from casbin_adapter.adapter import Adapter
from casbin_adapter.models import CasbinRule


class ExtendedAdapter(Adapter):
    """
    Extended adapter for the casbin model.
    """

    def load_filtered_policy(self, model, filter):
        """Load only policy rules that match the filter.

        This filter should come from a more human-readable query format, e.g.:
        {
            "ptype": "p",
            "rule": ["alice", "data1", "read"]
        }
        """
        query = CasbinRule.objects.using(self.db_alias).all()

        # Recorremos los atributos ptype, v0...v5
        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            values = getattr(filter, attr, [])
            if values:  # si no está vacío
                query = query.filter(**{f"{attr}__in": values})

        query = query.order_by("id")

        # Limpiar políticas en memoria antes de cargar
        model.clear_policy()

        # Poblar el modelo
        for line in query:
            persist.load_policy_line(str(line), model)

        self._filtered = True
