# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2012 Bryan Nolen <bryan@arc.net.au>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       Bryan Nolen
@license:      GNU General Public License 2.0 or later
@contact:      bryan@arc.net.au
@organization: N/A
"""

#pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
import volatility.debug as debug
import volatility.cache as cache
import volatility.utils as utils
import volatility.plugins.common as common

class IPConfig(common.AbstractWindowsCommand):
    """Extract the details of network interfaces from the windows registry"""

    meta_info = {}
    meta_info['author']    = 'Bryan Nolen'
    meta_info['copyright'] = 'Copyright (c) 2012 Bryan Nolen'
    meta_info['contact']   = 'bryan@arc.net.au'
    meta_info['license']   = 'GNU General Public License 2.0 or later'
    meta_info['url']       = 'https://twitter.com/BryanNolen'
    meta_info['os']        = 'WIN_32_XP_SP3'
    meta_info['version']   = '1.0Alpha'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)

        curr_ctl_set = regapi.reg_get_currentcontrolset(fullname = True)
        if not curr_ctl_set:
            debug.error("Unable to identify CurrentControlSet from registry")

        regapi.reset_current()
        regapi.set_current("SYSTEM")
        
        adapters_key   = curr_ctl_set + "\\Services\\Tcpip\\Parameters\\Adapters"
        interfaces_key = curr_ctl_set + "\\Services\\Tcpip\\Parameters\\Interfaces"
        network_key    = curr_ctl_set + "\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

        # Enumerate adapters configured in the registry
        adapter_keyset = regapi.reg_enum_key("SYSTEM", adapters_key)
        interface_set = []
        for adapter in adapter_keyset:
            adapter_name = adapter.split("\\")[-1]
            if adapter_name != "NdisWanIp":
                interface_set.append(adapter_name)
        
        # Enumerate the interface details for each adapter
        adapter_set = [];
        for interface in interface_set:
            address_set = {};
            interface_key  = interfaces_key + "\\" + interface
            connection_key = network_key    + "\\" + interface + "\\Connection"
            
            interface_name = regapi.reg_get_value(hive_name = "system", key = connection_key, value = "Name")
            address_set['Name'] = interface_name
            
            #NIC_instance_id = regapi.reg_get_value(hive_name = "system", key = connection_key, value = "PnpInstanceID")
            
            dhcp_status = regapi.reg_get_value(hive_name = "system", key = interface_key, value = "EnableDHCP")
            if dhcp_status == 1:
                key_prepend = "Dhcp"
                dhcp_string = "Yes"
            else:
                key_prepend = ""
                dhcp_string = "No"

            address_set['Interface'] = interface
            address_set['DHCP Status'] = dhcp_string
            
            query_string = key_prepend + "IPAddress"
            ip_address_set = regapi.reg_get_value(hive_name = "system", key = interface_key, value = query_string)
            address_set['IP Address'] = ""
            if ip_address_set != None:
                # Each interface may have multiple IP addresses, but we are mainly concerned with the primary address.
                # FIXME: better support for multi address interfaces
                if len(ip_address_set) == 3: # This value is stored as either a 3 value length list or as a unicode string
                    address_set['IP Address'] = ip_address_set[0]
                else:
                    address_set['IP Address'] = ip_address_set
            
            query_string = key_prepend + "DefaultGateway"
            gateway_set = regapi.reg_get_value(hive_name = "system", key = interface_key, value = query_string)
            address_set['Default Gateway'] = ""
            if gateway_set != None:
                # Each interface may have multiple gateways, but we are mainly concerned with the primary address.
                # FIXME: better support for multi gateway interfaces
                if len(gateway_set) == 3: # This value is stored as either a 3 value length list or as a unicode string
                    address_set['Default Gateway'] = gateway_set[0]
                else:
                    address_set['Default Gateway'] = gateway_set

            adapter_set.append(address_set)
        
        return adapter_set

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "30"), ("GUID", "38"), ("DHCP", "3"), ("IP Address", "16"), ("Gateway", "16")])
        for adapter in data:
            self.table_row(outfd, adapter['Name'], adapter['Interface'], adapter['DHCP Status'], adapter['IP Address'], adapter['Default Gateway'])
