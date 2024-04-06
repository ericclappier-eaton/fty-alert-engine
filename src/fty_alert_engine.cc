/*
Copyright (C) 2014 - 2020 Eaton

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "autoconfig.h"
#include "fty_alert_actions.h"
#include "fty_alert_engine_audit_log.h"
#include "fty_alert_engine_server.h"
#include <czmq.h>

static const char* CONFIG = "/etc/fty-alert-engine/fty-alert-engine.cfg";
// path to the directory, where rules are stored. CAUTION: **without** last slash!
static const char* PATH = "/var/lib/fty/fty-alert-engine";

// agents name
static const char* ENGINE_AGENT_NAME        = "fty-alert-engine";
static const char* ENGINE_AGENT_NAME_STREAM = "fty-alert-engine-stream";
static const char* ACTIONS_AGENT_NAME       = "fty-alert-actions";

// autoconfig name
static const char* AUTOCONFIG_NAME = "fty-autoconfig";

// malamute endpoint
static const char* ENDPOINT = "ipc://@/malamute";

int main(int argc, char** argv)
{
    zconfig_t* config = NULL;

    ManageFtyLog::setInstanceFtylog(ENGINE_AGENT_NAME, FTY_COMMON_LOGGING_DEFAULT_CFG);

    for (int argn = 1; argn < argc; argn++) {
        char* arg = argv[argn];
        char* par = (argn < (argc - 1)) ? argv[argn + 1] : NULL;

        if (streq(arg, "-v") || streq(arg, "--verbose")) {
            ManageFtyLog::getInstanceFtylog()->setVerboseMode();
        }
        else if (streq(arg, "-h") || streq(arg, "--help")) {
            puts("fty-alert-engine [option] [value]");
            puts("   -v|--verbose          verbose output");
            puts("   -h|--help             print help");
            puts("   -c|--config [path]    use custom config file ");
            return EXIT_SUCCESS;
        }
        else if (streq(arg, "-c") || streq(arg, "--config")) {
            if (!par) {
                printf("Missing parameter: %s, run with -h|--help \n", arg);
                return EXIT_FAILURE;
            }
            config = zconfig_load(par);
            argn++;
        }
        else {
            printf("Unknown option: %s, run with -h|--help \n", arg);
            return EXIT_FAILURE;
        }
    }

    if (!config) {
        config = zconfig_load(CONFIG);
    }

    // initialize log for auditability
    AuditLogManager::init(ENGINE_AGENT_NAME);

    zactor_t* ag_server_stream =
        zactor_new(fty_alert_engine_stream, static_cast<void*>(const_cast<char*>(ENGINE_AGENT_NAME_STREAM)));
    zactor_t* ag_server_mailbox =
        zactor_new(fty_alert_engine_mailbox, static_cast<void*>(const_cast<char*>(ENGINE_AGENT_NAME)));

    // mailbox
    zstr_sendx(ag_server_mailbox, "CONFIG", PATH, NULL);
    zstr_sendx(ag_server_mailbox, "CONNECT", ENDPOINT, NULL);
    zstr_sendx(ag_server_mailbox, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);

    // Stream
    zstr_sendx(ag_server_stream, "CONNECT", ENDPOINT, NULL);
    zstr_sendx(ag_server_stream, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    // zstr_sendx(ag_server_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL);
    zstr_sendx(ag_server_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS_UNAVAILABLE, ".*", NULL);
    zstr_sendx(ag_server_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, "status.*", NULL);
    zstr_sendx(ag_server_stream, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, ".*", NULL);

    // autoconfig
    zactor_t* ag_configurator = zactor_new(autoconfig, static_cast<void*>(const_cast<char*>(AUTOCONFIG_NAME)));
    zstr_sendx(ag_configurator, "CONFIG", PATH, NULL); // state file path
    zstr_sendx(ag_configurator, "CONNECT", ENDPOINT, NULL);
    zstr_sendx(ag_configurator, "TEMPLATES_DIR", "/usr/share/bios/fty-autoconfig", NULL); // rule template
    zstr_sendx(ag_configurator, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx(ag_configurator, "ALERT_ENGINE_NAME", ENGINE_AGENT_NAME, NULL);

    zactor_t* ag_actions = zactor_new(fty_alert_actions, static_cast<void*>(const_cast<char*>(ACTIONS_AGENT_NAME)));
    zstr_sendx(ag_actions, "CONNECT", ENDPOINT, NULL);
    zstr_sendx(ag_actions, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx(ag_actions, "CONSUMER", FTY_PROTO_STREAM_ALERTS, ".*", NULL);
    zstr_sendx(ag_actions, "ASKFORASSETS", NULL);

    log_info("%s started", ENGINE_AGENT_NAME);

    // main loop, accept any message back from server
    // copy from src/malamute.c under MPL license
    while (!zsys_interrupted) {
        char* msg = zstr_recv(ag_server_mailbox);
        if (!msg)
            break;

        log_debug("%s: recv msg '%s'", ENGINE_AGENT_NAME, msg);
        zstr_free(&msg);
    }

    log_info("%s ended", ENGINE_AGENT_NAME);

    zactor_destroy(&ag_server_stream);
    zactor_destroy(&ag_server_mailbox);
    zactor_destroy(&ag_actions);
    zactor_destroy(&ag_configurator);
    zconfig_destroy(&config);

    // release audit context
    AuditLogManager::deinit();

    return EXIT_SUCCESS;
}
