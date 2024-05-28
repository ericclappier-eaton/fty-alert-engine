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
#include <fty_common_mlm.h>
#include <czmq.h>

// path to the directory, where rules are stored. CAUTION: **without** ending slash!
static const char* PATH = "/var/lib/fty/fty-alert-engine";

// agents name
static const char* ENGINE_AGENT_NAME        = "fty-alert-engine";
static const char* ENGINE_AGENT_NAME_STREAM = "fty-alert-engine-stream";
static const char* ACTIONS_AGENT_NAME       = "fty-alert-actions";

// autoconfig name
static const char* AUTOCONFIG_NAME = "fty-autoconfig";

int main(int argc, char** argv)
{
    // default cfg file path
    const char* CFG_PATH = "/etc/fty-alert-engine/fty-alert-engine.cfg";
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        const std::string arg{argv[i]};
        const char* param = ((i + 1) < argc) ? argv[i + 1] : NULL;

        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
        else if (arg == "-h" || arg == "--help") {
            printf("%s [option] [value]\n", argv[0]);
            printf("   -v|--verbose          verbose output\n");
            printf("   -h|--help             print help\n");
            printf("   -c|--config [path]    use custom config file\n");
            return EXIT_SUCCESS;
        }
        else if (arg == "-c" || arg == "--config") {
            if (!param) {
                printf("ERROR: Missing parameter (option: %s)\n", arg.c_str());
                return EXIT_FAILURE;
            }
            CFG_PATH = param;
            i++;
        }
        else {
            printf("ERROR: Unknown option (%s)\n", arg.c_str());
            return EXIT_FAILURE;
        }
    }

    ManageFtyLog::setInstanceFtylog(ENGINE_AGENT_NAME, FTY_COMMON_LOGGING_DEFAULT_CFG);
    if (verbose) {
        ManageFtyLog::getInstanceFtylog()->setVerboseMode();
    }

    if (CFG_PATH) {
        // no cfg option allowed
        zconfig_t* config = zconfig_load(CFG_PATH);
        zconfig_destroy(&config);
    }

    // initialize log for auditability
    AuditLogManager::init(ENGINE_AGENT_NAME);

    log_debug ("%s starting...", ENGINE_AGENT_NAME);

    // mailbox
    zactor_t* mailbox_actor = zactor_new(fty_alert_engine_mailbox, static_cast<void*>(const_cast<char*>(ENGINE_AGENT_NAME)));
    zstr_sendx(mailbox_actor, "CONFIG", PATH, NULL);
    zstr_sendx(mailbox_actor, "CONNECT", MLM_ENDPOINT, NULL);
    zstr_sendx(mailbox_actor, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);

    // Stream
    zactor_t* stream_actor = zactor_new(fty_alert_engine_stream, static_cast<void*>(const_cast<char*>(ENGINE_AGENT_NAME_STREAM)));
    zstr_sendx(stream_actor, "CONNECT", MLM_ENDPOINT, NULL);
    zstr_sendx(stream_actor, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    // zstr_sendx(stream_actor, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL);
    zstr_sendx(stream_actor, "CONSUMER", FTY_PROTO_STREAM_METRICS_UNAVAILABLE, ".*", NULL);
    zstr_sendx(stream_actor, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, "status.*", NULL);
    zstr_sendx(stream_actor, "CONSUMER", FTY_PROTO_STREAM_LICENSING_ANNOUNCEMENTS, ".*", NULL);

    // autoconfig
    zactor_t* autoconf_actor = zactor_new(autoconfig, static_cast<void*>(const_cast<char*>(AUTOCONFIG_NAME)));
    zstr_sendx(autoconf_actor, "CONFIG", PATH, NULL); // state file path
    zstr_sendx(autoconf_actor, "CONNECT", MLM_ENDPOINT, NULL);
    zstr_sendx(autoconf_actor, "TEMPLATES_DIR", "/usr/share/bios/fty-autoconfig", NULL); // rule template
    zstr_sendx(autoconf_actor, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx(autoconf_actor, "ALERT_ENGINE_NAME", ENGINE_AGENT_NAME, NULL);

    // actions
    zactor_t* action_actor = zactor_new(fty_alert_actions, static_cast<void*>(const_cast<char*>(ACTIONS_AGENT_NAME)));
    zstr_sendx(action_actor, "CONNECT", MLM_ENDPOINT, NULL);
    zstr_sendx(action_actor, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx(action_actor, "CONSUMER", FTY_PROTO_STREAM_ALERTS, ".*", NULL);
    zstr_sendx(action_actor, "ASKFORASSETS", NULL);

    log_info("%s started", ENGINE_AGENT_NAME);

    // main loop, accept any message back from server
    // copy from src/malamute.c under MPL license
    while (!zsys_interrupted) {
        char* msg = zstr_recv(mailbox_actor);
        if (!msg)
            break;

        log_debug("%s: recv msg '%s'", ENGINE_AGENT_NAME, msg);
        zstr_free(&msg);
    }

    log_info("%s ended", ENGINE_AGENT_NAME);

    zactor_destroy(&action_actor);
    zactor_destroy(&autoconf_actor);
    zactor_destroy(&stream_actor);
    zactor_destroy(&mailbox_actor);

    // release audit context
    AuditLogManager::deinit();

    return EXIT_SUCCESS;
}
