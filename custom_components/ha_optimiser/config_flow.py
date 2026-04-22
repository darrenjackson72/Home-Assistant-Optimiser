"""Config flow for HA Optimizer."""
from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .const import (
    DOMAIN,
    CONF_SCAN_INTERVAL_DAYS,
    CONF_STALE_DAYS_THRESHOLD,
    CONF_ENABLE_SOFT_DELETE,
    CONF_SOFT_DELETE_DAYS,
    CONF_EXCLUDE_DEVICE_CLASSES,
    DEFAULT_SCAN_INTERVAL_DAYS,
    DEFAULT_STALE_DAYS_THRESHOLD,
    DEFAULT_ENABLE_SOFT_DELETE,
    DEFAULT_SOFT_DELETE_DAYS,
    DEFAULT_EXCLUDE_DEVICE_CLASSES,
)

STEP_SCHEMA = vol.Schema({
    vol.Optional(CONF_SCAN_INTERVAL_DAYS, default=DEFAULT_SCAN_INTERVAL_DAYS):
        vol.All(int, vol.Range(min=0, max=365)),
    vol.Optional(CONF_STALE_DAYS_THRESHOLD, default=DEFAULT_STALE_DAYS_THRESHOLD):
        vol.All(int, vol.Range(min=1, max=365)),
    vol.Optional(CONF_ENABLE_SOFT_DELETE, default=DEFAULT_ENABLE_SOFT_DELETE):
        bool,
    vol.Optional(CONF_SOFT_DELETE_DAYS, default=DEFAULT_SOFT_DELETE_DAYS):
        vol.All(int, vol.Range(min=1, max=90)),
    vol.Optional(CONF_EXCLUDE_DEVICE_CLASSES, default=DEFAULT_EXCLUDE_DEVICE_CLASSES):
        str,
})


class PurgeEngineConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for HA Optimizer."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")

        if user_input is not None:
            # Store settings in options, keep data empty
            return self.async_create_entry(title="HA Optimizer", data=user_input)

        return self.async_show_form(step_id="user", data_schema=STEP_SCHEMA)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        """Return the options flow handler."""
        return PurgeEngineOptionsFlow()


class PurgeEngineOptionsFlow(config_entries.OptionsFlow):
    """Handle the options flow for HA Optimizer."""

    # No __init__ needed — HA injects config_entry via self.config_entry in newer versions

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        # Read current values from either options or data (first-time migration)
        current = dict(self.config_entry.options) or dict(self.config_entry.data)

        schema = vol.Schema({
            vol.Optional(
                CONF_SCAN_INTERVAL_DAYS,
                default=current.get(CONF_SCAN_INTERVAL_DAYS, DEFAULT_SCAN_INTERVAL_DAYS),
            ): vol.All(int, vol.Range(min=0, max=365)),
            vol.Optional(
                CONF_STALE_DAYS_THRESHOLD,
                default=current.get(CONF_STALE_DAYS_THRESHOLD, DEFAULT_STALE_DAYS_THRESHOLD),
            ): vol.All(int, vol.Range(min=1, max=365)),
            vol.Optional(
                CONF_ENABLE_SOFT_DELETE,
                default=current.get(CONF_ENABLE_SOFT_DELETE, DEFAULT_ENABLE_SOFT_DELETE),
            ): bool,
            vol.Optional(
                CONF_SOFT_DELETE_DAYS,
                default=current.get(CONF_SOFT_DELETE_DAYS, DEFAULT_SOFT_DELETE_DAYS),
            ): vol.All(int, vol.Range(min=1, max=90)),
            vol.Optional(
                CONF_EXCLUDE_DEVICE_CLASSES,
                default=current.get(CONF_EXCLUDE_DEVICE_CLASSES, DEFAULT_EXCLUDE_DEVICE_CLASSES),
            ): str,
        })

        return self.async_show_form(step_id="init", data_schema=schema)
