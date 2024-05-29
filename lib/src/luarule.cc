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

#include "luarule.h"
#include "audit_log.h"
#include <algorithm>
#include <czmq.h>
#include <fty_log.h>


LuaRule::~LuaRule()
{
    if (_lstate)
        lua_close(_lstate);
}

LuaRule::LuaRule(const LuaRule& r)
{
    _name = r._name;
    globalVariables(r.getGlobalVariables());
    code(r._code);
}

void LuaRule::globalVariables(const std::map<std::string, double>& vars)
{
    Rule::globalVariables(vars);
    _setGlobalVariablesToLUA();
}

void LuaRule::code(const std::string& newCode)
{
    if (_lstate)
        lua_close(_lstate);
    _valid = false;
    _code.clear();

#if LUA_VERSION_NUM > 501
    _lstate = luaL_newstate();
#else
    _lstate = lua_open();
#endif
    if (!_lstate) {
        throw std::runtime_error("Can't initiate LUA context!");
    }
    luaL_openlibs(_lstate); // get functions like print();

    // set global variables
    _setGlobalVariablesToLUA();

    // set code, try to compile it
    _code     = newCode;
    int error = luaL_dostring(_lstate, _code.c_str());
    _valid    = (error == 0);
    if (!_valid) {
        throw std::runtime_error("Invalid LUA code!");
    }

    // check wether there is main() function
    lua_getglobal(_lstate, "main");
    if (!lua_isfunction(_lstate, lua_gettop(_lstate))) {
        // main() missing
        _valid = false;
        throw std::runtime_error("Function main not found!");
    }
}

static std::string auditValue(const std::string& metric, double value)
{
    char sval[32] = "NaN";
    if (!std::isnan(value)) {
        snprintf(sval, sizeof(sval), "%0.2lf", value);
        char* p = strstr(sval, ".00"); // remove .00 decimals
        if (p) { *p = 0; }
    }
    std::string topic = metric.substr(0, metric.find("@"));
    return topic + "=" + std::string{sval};
}

int LuaRule::evaluate(const MetricList& metricList, PureAlert& pureAlert)
{
    log_debug("LuaRule::evaluate %s", _name.c_str());
    int res = 0;

    std::string auditValues;

    std::vector<double> values;
    int index = 0;
    for (const auto& metric : _metrics) {
        double value = metricList.find(metric);

        auditValues += (auditValues.empty() ? "" : ", ") + auditValue(metric, value);

        if (std::isnan(value)) {
            log_debug("metric#%d: %s = NaN", index, metric.c_str());
            log_debug("Don't have everything for '%s' yet", _name.c_str());
            res = RULE_RESULT_UNKNOWN;
            break;
        }
        values.push_back(value);
        log_debug("metric#%d: %s = %lf", index, metric.c_str(), value);
        index++;
    }

    if (res != RULE_RESULT_UNKNOWN) {
        int         status     = static_cast<int>(luaEvaluate(values));
        const char* statusText = resultToString(status);
        // log_debug("LuaRule::evaluate on %s gives '%s'", _name.c_str(), statusText);

        auto outcome = _outcomes.find(statusText);
        if (outcome != _outcomes.cend()) {
            log_debug("LuaRule::evaluate %s START %s", _name.c_str(), outcome->second._severity.c_str());

            // some known outcome was found
            pureAlert = PureAlert(ALERT_START, static_cast<uint64_t>(::time(NULL)), outcome->second._description,
                _element, outcome->second._severity, outcome->second._actions);
            pureAlert.print();
        } else if (status == RULE_RESULT_OK) {
            log_debug("LuaRule::evaluate %s %s", _name.c_str(), "RESOLVED");

            // When alert is resolved, it doesn't have new severity!!!!
            pureAlert = PureAlert(
                ALERT_RESOLVED, static_cast<uint64_t>(::time(NULL)), "everything is ok", _element, "OK", {""});
            pureAlert.print();
        } else {
            log_error(
                "LuaRule::evaluate %s has returned a result %s, but it is not specified in 'result' in the JSON rule "
                "definition",
                _name.c_str(), statusText);
            res = RULE_RESULT_UNKNOWN;
        }
    }

    std::string auditDesc =
        (res == RULE_RESULT_UNKNOWN) ? ALERT_UNKNOWN : // UNKNOWN
        (pureAlert._status == ALERT_RESOLVED) ? ALERT_RESOLVED : // RESOLVED
        std::string{pureAlert._status + "/" + pureAlert._severity.substr(0, 1)} // ACTIVE/C ACTIVE/W
    ;

    audit_log_info("%8s %s (%s)", auditDesc.c_str(), _name.c_str(), auditValues.c_str());

    return res;
}

double LuaRule::luaEvaluate(const std::vector<double>& metrics)
{
    double result;

    if (!_valid) {
        throw std::runtime_error("Rule is not valid!");
    }
    lua_settop(_lstate, 0);

    lua_getglobal(_lstate, "main");
    for (const auto x : metrics) {
        lua_pushnumber(_lstate, x);
    }
    if (lua_pcall(_lstate, static_cast<int>(metrics.size()), 1, 0) != 0) {
        throw std::runtime_error("LUA calling main() failed!");
    }
    if (!lua_isnumber(_lstate, -1)) {
        throw std::runtime_error("LUA main function did not returned number!");
    }

    result = lua_tonumber(_lstate, -1);
    lua_pop(_lstate, 1);
    return result;
}

void LuaRule::_setGlobalVariablesToLUA()
{
    if (_lstate == NULL)
        return;
    for (int i = RULE_RESULT_TO_LOW_CRITICAL; i <= RULE_RESULT_UNKNOWN; i++) {
        std::string upper = Rule::resultToString(i);
        transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
        lua_pushnumber(_lstate, i);
        lua_setglobal(_lstate, upper.c_str());
    }
    for (const auto& it : getGlobalVariables()) {
        lua_pushnumber(_lstate, it.second);
        lua_setglobal(_lstate, it.first.c_str());
    }
}
