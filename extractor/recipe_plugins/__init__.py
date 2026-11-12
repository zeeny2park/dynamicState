"""Recipe definition files (IMP-018).

Every module in this package is imported once when :mod:`extractor.diagnostic_recipes` is loaded.  A module
registers a complete recipe from this one file: the recipe (observation kinds it needs + its verdict rule) with
``diagnostic_recipes.register_recipe`` and, for a new observation kind, its collector with
``runtime_evidence_provider.register_observation_collector``.  No recipe_id branch elsewhere needs editing.
"""
