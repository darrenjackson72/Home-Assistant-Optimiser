"""Optimizer - Execution layer for HA Optimizer."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util

from .const import DOMAIN, RISK_HIGH

_LOGGER = logging.getLogger(__name__)


class PurgeEngine:
    """Handles the actual deletion/disabling of entities."""

    def __init__(self, hass: HomeAssistant):
        self.hass = hass

    async def async_purge_entities(
        self, entity_ids: list[str], soft_delete: bool = True
    ) -> dict[str, Any]:
        """Purge a list of entities. Returns results dict."""
        results = {
            "success": [],
            "failed": [],
            "soft_deleted": [],        # newly disabled by this call
            "already_disabled": [],    # was already disabled before — still added to trash
            "yaml_manual": [],
            "skipped_high_risk": [],
        }

        ent_reg = er.async_get(self.hass)

        for entity_id in entity_ids:
            try:
                entry = ent_reg.async_get(entity_id)
                domain = entity_id.split(".")[0]

                if not entry:
                    # Not in registry — try domain-specific removal
                    ok = await self._remove_by_domain(entity_id)
                    if ok:
                        results["success"].append(entity_id)
                    else:
                        results["failed"].append({"entity_id": entity_id, "error": "Not found in registry"})
                    continue

                # For automations and scripts, always use domain-specific deletion
                # (entity_registry.async_remove alone does NOT remove the config/storage)
                if domain in ("automation", "script"):
                    if soft_delete:
                        was_already_disabled = entry.disabled
                        if not was_already_disabled:
                            ent_reg.async_update_entity(
                                entity_id,
                                disabled_by=er.RegistryEntryDisabler.USER,
                            )
                            _LOGGER.info("Soft-disabled %s: %s", domain, entity_id)
                        else:
                            _LOGGER.info(
                                "%s was already disabled, adding to trash: %s",
                                domain, entity_id,
                            )
                            results["already_disabled"].append(entity_id)
                        # Either way it goes into soft_deleted (= tracked in trash)
                        results["soft_deleted"].append(entity_id)
                    else:
                        ok = await self._remove_by_domain(entity_id)
                        if ok:
                            results["success"].append(entity_id)
                        else:
                            results["yaml_manual"].append({
                                "entity_id": entity_id,
                                "platform": entry.platform,
                                "note": f"This {domain} is defined in YAML and must be removed manually",
                            })
                    continue

                # Skip high-risk safety entities
                device_class = entry.original_device_class or entry.device_class
                if device_class and device_class.lower() in _SAFETY_CLASSES:
                    results["skipped_high_risk"].append(entity_id)
                    _LOGGER.warning("Skipping high-risk safety entity: %s", entity_id)
                    continue

                # YAML-defined entities cannot be deleted via API
                if entry.config_entry_id is None and entry.platform not in ("mqtt", None):
                    results["yaml_manual"].append({
                        "entity_id": entity_id,
                        "platform": entry.platform,
                    })
                    continue

                if soft_delete:
                    # Disable the entity — USER disabler works for any entity
                    was_already_disabled = entry.disabled
                    if not was_already_disabled:
                        ent_reg.async_update_entity(
                            entity_id,
                            disabled_by=er.RegistryEntryDisabler.USER,
                        )
                        _LOGGER.info("Soft-deleted (disabled) entity: %s", entity_id)
                    else:
                        _LOGGER.info(
                            "Entity was already disabled, adding to trash: %s", entity_id
                        )
                        results["already_disabled"].append(entity_id)
                    # Always track in soft_deleted (= goes to trash)
                    results["soft_deleted"].append(entity_id)
                else:
                    # Hard delete
                    ent_reg.async_remove(entity_id)
                    results["success"].append(entity_id)
                    _LOGGER.info("Hard-deleted entity: %s", entity_id)

            except Exception as exc:
                _LOGGER.error("Error purging %s: %s", entity_id, exc)
                results["failed"].append({"entity_id": entity_id, "error": str(exc)})

        return results

    async def async_restore_entity(self, entity_id: str) -> dict:
        """Re-enable a soft-deleted (disabled) entity. Returns dict with success + re_enabled."""
        try:
            ent_reg = er.async_get(self.hass)
            entry = ent_reg.async_get(entity_id)
            if not entry:
                _LOGGER.warning("Cannot restore %s — not found in registry", entity_id)
                return {"success": False, "re_enabled": False, "error": "not found in registry"}
            if not entry.disabled:
                _LOGGER.info("Entity %s is not disabled — removing from trash only", entity_id)
                return {"success": True, "re_enabled": False}
            # Only clear USER or INTEGRATION disabler (not SYSTEM/CONFIG_ENTRY)
            if entry.disabled_by in (
                er.RegistryEntryDisabler.USER,
                er.RegistryEntryDisabler.INTEGRATION,
            ):
                ent_reg.async_update_entity(entity_id, disabled_by=None)
                _LOGGER.info("Restored entity: %s", entity_id)
                return {"success": True, "re_enabled": True}
            else:
                _LOGGER.warning(
                    "Cannot restore %s — disabled by %s (not USER/INTEGRATION)",
                    entity_id, entry.disabled_by
                )
                return {
                    "success": False,
                    "re_enabled": False,
                    "error": f"disabled by {entry.disabled_by} (not USER/INTEGRATION)",
                }
        except Exception as exc:
            _LOGGER.error("Failed to restore %s: %s", entity_id, exc)
            return {"success": False, "re_enabled": False, "error": str(exc)}

    async def async_hard_delete_soft_deleted(self, entity_ids: list[str]) -> dict[str, Any]:
        """Permanently remove entities that have been soft-deleted."""
        return await self.async_purge_entities(entity_ids, soft_delete=False)

    async def _remove_by_domain(self, entity_id: str) -> bool:
        """Try domain-specific removal for automations/scripts via their config entry."""
        domain = entity_id.split(".")[0]
        try:
            if domain == "automation":
                # Automations created via UI have a config entry — delete it
                config_entries = self.hass.config_entries.async_entries("automation")
                uid = entity_id.replace("automation.", "")
                for entry in config_entries:
                    if entry.unique_id == uid or entry.entry_id == uid:
                        await self.hass.config_entries.async_remove(entry.entry_id)
                        _LOGGER.info("Deleted automation config entry: %s", entity_id)
                        return True
                # Fallback: use automation.delete service (HA 2024.4+)
                try:
                    await self.hass.services.async_call(
                        "automation", "reload", {}, blocking=True
                    )
                    # Try websocket-style delete via automations component
                    from homeassistant.components.automation import (
                        AutomationStorageCollection,
                    )
                    store = self.hass.data.get("automation_storage")
                    if store and uid:
                        await store.async_delete_item(uid)
                        _LOGGER.info("Deleted automation via storage: %s", entity_id)
                        return True
                except Exception as inner:
                    _LOGGER.debug("automation storage delete failed: %s", inner)
                # Last resort: disable so it stops running
                ent_reg = er.async_get(self.hass)
                entry = ent_reg.async_get(entity_id)
                if entry:
                    ent_reg.async_update_entity(
                        entity_id,
                        disabled_by=er.RegistryEntryDisabler.USER,
                    )
                    _LOGGER.info("Disabled automation (could not delete): %s", entity_id)
                    return True
                return False

            elif domain == "script":
                # Scripts created via UI have a config entry
                uid = entity_id.replace("script.", "")
                config_entries = self.hass.config_entries.async_entries("script")
                for entry in config_entries:
                    if entry.unique_id == uid or entry.entry_id == uid:
                        await self.hass.config_entries.async_remove(entry.entry_id)
                        _LOGGER.info("Deleted script config entry: %s", entity_id)
                        return True
                # Fallback: scripts storage
                try:
                    from homeassistant.components.script import ScriptStorageCollection
                    store = self.hass.data.get("script_storage")
                    if store and uid:
                        await store.async_delete_item(uid)
                        _LOGGER.info("Deleted script via storage: %s", entity_id)
                        return True
                except Exception as inner:
                    _LOGGER.debug("script storage delete failed: %s", inner)
                # Disable as fallback
                ent_reg = er.async_get(self.hass)
                entry = ent_reg.async_get(entity_id)
                if entry:
                    ent_reg.async_update_entity(
                        entity_id,
                        disabled_by=er.RegistryEntryDisabler.USER,
                    )
                    _LOGGER.info("Disabled script (could not delete): %s", entity_id)
                    return True
                return False

        except Exception as exc:
            _LOGGER.debug("Could not remove %s via domain: %s", entity_id, exc)
        return False

    async def async_get_dependency_map(self, entity_id: str) -> dict[str, Any]:
        """Get all places where an entity is referenced (for impact analysis)."""
        deps = {
            "automations": [],
            "scripts": [],
            "groups": [],
            "dashboards": "Cannot be scanned at runtime - check manually",
        }

        # Check automations
        for state in self.hass.states.async_all("automation"):
            automation_id = state.entity_id
            # Check the automation's config via service
            try:
                result = await self.hass.services.async_call(
                    "automation",
                    "config",
                    {"entity_id": automation_id},
                    blocking=True,
                    return_response=True,
                )
            except Exception:
                pass

        # Simple check: scan all state attributes
        for state in self.hass.states.async_all():
            attrs_str = str(state.attributes)
            if entity_id in attrs_str:
                domain = state.entity_id.split(".")[0]
                if domain == "automation":
                    deps["automations"].append(state.entity_id)
                elif domain == "script":
                    deps["scripts"].append(state.entity_id)
                elif domain == "group":
                    deps["groups"].append(state.entity_id)

        return deps


_SAFETY_CLASSES = {
    "smoke", "moisture", "gas", "carbon_monoxide", "carbon_dioxide",
    "safety", "tamper", "lock", "battery", "problem",
}
