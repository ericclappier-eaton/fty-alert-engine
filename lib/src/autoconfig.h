/*  =========================================================================
    autoconfig - Autoconfig

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
    =========================================================================
*/

#pragma once

#include "utils.h"
#include <fty_log.h>
#include <fty_proto.h>
#include <list>
#include <malamute.h>
#include <map>
#include <string>
#include <mutex>

#define RULES_SUBJECT "rfc-evaluator-rules"

struct AutoConfigurationInfo
{
    std::string                        type;
    std::string                        subtype;
    std::string                        operation;
    std::string                        update_ts;
    bool                               configured = false;
    uint64_t                           date       = 0;
    std::map<std::string, std::string> attributes;
    std::vector<std::string>           locations; // inames

    // not initialized?
    bool empty() const {
        return type.empty();
    }

    // ext. attribute accessor
    std::string getAttr(const std::string& attrName, const std::string& defValue = "") const
    {
        auto it = attributes.find(attrName);
        if (it != attributes.end())
            return it->second;
        return defValue;
    }

    //dbg, dump with filter on ext. attributes
    std::string dump(const std::vector<std::string>& attrFilter) const {
        if (empty()) return "<empty>"; // not initialized

        std::string s;
        s = type + "(" + subtype + ")/" + operation;
        for (auto& it : attributes) {
            if (!attrFilter.empty()) {
                bool skip{true};
                for (auto& occ : attrFilter)
                    { if (it.first.find(occ) != std::string::npos) { skip = false; break; } }
                if (skip) continue;
            }

            s += "," + it.first + "=" + it.second;
        }
        return s;
    }

    // dbg, complete dump
    std::string dump() const { return dump({}); }

    bool                               operator==(fty_proto_t* message) const
    {
        bool bResult = true;
        bResult &= (operation == fty_proto_operation(message));
        bResult &= (type == fty_proto_aux_string(message, "type", ""));
        bResult &= (subtype == fty_proto_aux_string(message, "subtype", ""));
        // self is implicitly active, so we have to test it
        bResult &= (streq(fty_proto_aux_string(message, FTY_PROTO_ASSET_STATUS, "active"), "active"));
        if (!bResult)
            return false;

        // test all ext attributes
        std::map<std::string, std::string> msg_attributes = utils::zhash_to_map(fty_proto_ext(message));
        return attributes.size() == msg_attributes.size() &&
               std::equal(attributes.begin(), attributes.end(), msg_attributes.begin());
    };
};

AutoConfigurationInfo getAssetInfoFromAutoconfig(const std::string& assetName);

void autoconfig(zsock_t* pipe, void* args);

class Autoconfig
{
public:
    Autoconfig(const std::string& agentName) : _agentName(agentName) {}
    virtual ~Autoconfig() { mlm_client_destroy(&_client); }

    static std::string StateFile;     //!< file&path where Autoconfig state is saved
    static std::string StateFilePath; //!< fully-qualified path to dir where Autoconfig state is saved
    static std::string RuleFilePath;  //!< fully-qualified path to dir where Autoconfig rule templates are saved
    static std::string AlertEngineName;

    const std::string  getEname(const std::string& iname);

    void main(zsock_t* pipe, char* name);
    void onSend(fty_proto_t** message);
    void onPoll();

    void run(zsock_t* pipe, char* name)
    {
        //onStart
        loadState();
        setPollingInterval();

        // main loop
        main(pipe, name);

        //onEnd
        cleanupState();
        saveState();
    }

    AutoConfigurationInfo configurableDevicesGet(const std::string& assetName);

private:
    void configurableDevicesAdd(const std::string& assetName, const AutoConfigurationInfo& info);
    bool configurableDevicesRemove(const std::string& assetName);
    std::map<std::string, AutoConfigurationInfo> _configurableDevices;
    std::recursive_mutex _configurableDevicesMutex; // multi-thread access protection

    void setPollingInterval();
    void cleanupState();
    void saveState();
    void loadState();

    // list of containers with their friendly names
    std::map<std::string, std::string> _containers; // iname | ename

protected:
    std::string   _agentName;
    mlm_client_t* _client{NULL};
    int           _timeout{2000};

    std::list<std::string> getElemenListMatchTemplate(std::string template_name);
    void                   listTemplates(const char* correlation_id, const char* type);
};
