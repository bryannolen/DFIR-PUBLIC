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
from time import strftime
import datetime

class SystemInfo(common.AbstractWindowsCommand):
    """Extract various details of the sytem from the windows registry"""

    meta_info = {}
    meta_info['author']    = 'Bryan Nolen'
    meta_info['copyright'] = 'Copyright (c) 2013 Bryan Nolen'
    meta_info['contact']   = 'bryan@arc.net.au'
    meta_info['license']   = 'GNU General Public License 2.0 or later'
    meta_info['url']       = 'https://twitter.com/BryanNolen'
    meta_info['os']        = 'WIN_32_XP_SP3'
    meta_info['version']   = '1.1Alpha'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)

        curr_ctl_set = regapi.reg_get_currentcontrolset(fullname = True)
        if not curr_ctl_set:
            debug.error("Unable to identify CurrentControlSet from registry")

        regapi.reset_current()
        
        tcp_param_key  = curr_ctl_set + "\\Services\\Tcpip\\Parameters"
        compname_key   = curr_ctl_set + "\\Control\\ComputerName\\ComputerName"
        wincurrver_key = "Microsoft\\Windows NT\\CurrentVersion"
        software_hive  = "SOFTWARE"
        system_hive    = "SYSTEM"

        sysinfo_set = []

        entry_set = {}
        entry_set['Name'] = "_SECTION"
        entry_set['Value'] = "Volatility Internals"
        sysinfo_set.append(entry_set)

        entry_set = {}
        entry_set['Name'] = "CurrentControlSet"
        entry_set['Value'] = curr_ctl_set
        sysinfo_set.append(entry_set)

        entry_set = {}
        entry_set['Name'] = "_SECTION"
        entry_set['Value'] = "HKLM\SOFTWARE"
        sysinfo_set.append(entry_set)

        regapi.reset_current()

        RegisteredOrganization = regapi.reg_get_value(hive_name = software_hive, key = wincurrver_key, value = "RegisteredOrganization")
        entry_set = {}
        entry_set['Name'] = "RegisteredOrganization"
        entry_set['Value'] = RegisteredOrganization
        sysinfo_set.append(entry_set)

        InstallDate = regapi.reg_get_value(hive_name = software_hive, key = wincurrver_key, value = "InstallDate")
        entry_set = {}
        entry_set['Name'] = "InstallDate"
        entry_set['Value'] = datetime.datetime.fromtimestamp(int(InstallDate)).strftime('%Y-%m-%d %H:%M:%S')
        sysinfo_set.append(entry_set)

        ProductName = regapi.reg_get_value(hive_name = software_hive, key = wincurrver_key, value = "ProductName")
        entry_set = {}
        entry_set['Name'] = "ProductName"
        entry_set['Value'] = ProductName
        sysinfo_set.append(entry_set)
 
        regapi.reset_current()

        entry_set = {}
        entry_set['Name'] = "_SECTION"
        entry_set['Value'] = "HKLM\SYSTEM"
        sysinfo_set.append(entry_set)

        #ctlset = regapi.reg_get_value(hive_name = system_hive, key = "CurrentControlSet", value = "CurrentControlSet")
        for value, data in regapi.reg_yield_values(hive_name = system_hive, key = "CurrentControlSet"):
            entry_set = {}
            entry_set['Name'] = "CurrentControlSet"
            entry_set['Value'] = data.split('\\')[4]
            sysinfo_set.append(entry_set)
            if (entry_set['Value'] <> curr_ctl_set):
                curr_ctl_set = entry_set['Value']
                entry_set = {}
                entry_set['Name'] = "CurrentControlSet"
                entry_set['Value'] = "VOLATILITY INTERNAL MISMATCH"
                sysinfo_set.append(entry_set)
                tcp_param_key  = curr_ctl_set + "\\Services\\Tcpip\\Parameters"
                compname_key   = curr_ctl_set + "\\Control\\ComputerName\\ComputerName"
                
        ComputerName = regapi.reg_get_value(hive_name = system_hive, key = compname_key, value = "ComputerName")
        entry_set = {}
        entry_set['Name'] = "ComputerName"
        entry_set['Value'] = ComputerName
        sysinfo_set.append(entry_set)

        Hostname = regapi.reg_get_value(hive_name = system_hive, key = tcp_param_key, value = "Hostname")
        entry_set = {}
        entry_set['Name'] = "Hostname"
        entry_set['Value'] = Hostname
        sysinfo_set.append(entry_set)

        DhcpDomain = regapi.reg_get_value(hive_name = system_hive, key = tcp_param_key, value = "DhcpDomain")
        entry_set = {}
        entry_set['Name'] = "DhcpDomain"
        entry_set['Value'] = DhcpDomain
        sysinfo_set.append(entry_set)    
        
                
        return sysinfo_set

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "30"), ("Value", "45")])
        for entry in data:
            if(entry['Name'] == "_SECTION"):
               outfd.write("\n** {0} **\n\n".format(entry['Value']))
            else:
               self.table_row(outfd, entry['Name'], entry['Value'])

