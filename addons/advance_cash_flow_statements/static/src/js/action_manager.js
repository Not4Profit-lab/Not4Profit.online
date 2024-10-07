/** @odoo-module */
import { registry } from "@web/core/registry";
import { BlockUI } from "@web/core/ui/block_ui";
import { download } from "@web/core/network/download";

// Check if 'xlsx' is already registered
if (!registry.category("ir.actions.report handlers").contains("xlsx")) {
    registry.category("ir.actions.report handlers").add("xlsx", async function (action) {
        if (action.report_type === 'xlsx') {
            const blockUI = new BlockUI();
            await download({
                url: '/xlsx_reports',
                data: action.data,
                complete: () => blockUI.unblock(),
                error: (error) => self.call('crash_manager', 'rpc_error', error),
            });
        }
    });
}
