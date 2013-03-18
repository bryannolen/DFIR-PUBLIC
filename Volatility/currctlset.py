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

class CurrentControlSet(common.AbstractWindowsCommand):
    """Extract the details of CurrentControlSet from the windows registry"""

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

        return curr_ctl_set

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Current Control Set", "30")])
        self.table_row(outfd, data)

