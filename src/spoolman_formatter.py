# -*- coding: utf-8 -*-
"""Utilities to convert Bambu tag data into a payload for Spoolman."""

from typing import Any, Dict

from src.bambutag_parse import Tag, Unit


def _unit_value(value: Any) -> Any:
    """Return the numeric value from a Unit or the value itself."""
    return value.value if isinstance(value, Unit) else value


def tag_to_spoolman_payload(tag: Tag) -> Dict[str, Any]:
    """Convert a :class:`~src.bambutag_parse.Tag` into a Spoolman-friendly dict."""
    data = tag.data
    temps = data.get("temperatures", {})

    payload: Dict[str, Any] = {
        "uid": data.get("uid"),
        "filament_type": data.get("filament_type"),
        "detailed_filament_type": data.get("detailed_filament_type"),
        "material_id": data.get("material_id"),
        "variant_id": data.get("variant_id"),
        "color_hex": data.get("filament_color"),
        "spool_weight_g": _unit_value(data.get("spool_weight")),
        "filament_length_m": _unit_value(data.get("filament_length")),
        "filament_diameter_mm": _unit_value(data.get("filament_diameter")),
        "spool_width_mm": _unit_value(data.get("spool_width")),
        "nozzle_diameter_mm": _unit_value(data.get("nozzle_diameter")),
        "temperatures": {
            "drying_temp_c": _unit_value(temps.get("drying_temp")),
            "drying_time_h": _unit_value(temps.get("drying_time")),
            "bed_temp_c": _unit_value(temps.get("bed_temp")),
            "hotend_temp_min_c": _unit_value(temps.get("min_hotend")),
            "hotend_temp_max_c": _unit_value(temps.get("max_hotend")),
        },
        "production_date": str(data.get("production_date")),
    }

    return payload
