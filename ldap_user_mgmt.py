import time
import cloudshell.api.cloudshell_api as cs_api
import json
import os
import base64
import ldap


class ldapimport(object):
    """Used to align CloudShell users/groups with Active Directory Users"""

    def __init__(self):
        """
        :rtype: object
        :param self:
        :return:
        """
        # set the config file path & load the json file
        self.json_file_path = 'config.json'
        self.configs = json.loads(open(self.json_file_path).read())

        # set logging file path
        self.logfile = self.configs['log_file_path']

        # set the primary search group
        self.main_group = self.configs['ldap_main_group']

        # set the default password for new user
        self.default_password = self.configs['new_user_default_password']

        # start CloudShell API Session
        self.cs_session = cs_api.CloudShellAPISession(self.configs["qs_server_hostname"],
                                                      self.configs["qs_admin_username"],
                                                      base64.b64decode(self.configs["qs_admin_password"]),
                                                      domain="Global")

    # Active Directory Commands
    def ldap_query(self, ldap_connection, ldap_user, ldap_pw, ldap_query_str, auth):
        """
        Returns a group list from an Active Directory Query
        :param self:
        :param ad_connection: LDAP Server String
        :param ad_user: Active Directory username for connection
        :param ad_pw: Active Directory password for connection
        :return:
        """

        ldap_con = ldap.initialize(ldap_connection)

        try:
            ldap_con.protocol_version = ldap.VERSION3
            ldap_con.set_option(ldap.OPT_REFERRALS, 0)
            if auth == 1:
                ldap_con.simple_bind_s(ldap_user, ldap_pw)
        except ldap.LDAPError as error_msg:
            print error_msg

        name_list = []

        ad_list = ldap_con.read_s(ldap_query_str)
        for name in ad_list["uniqueMember"]:
            parse = name.split(",", 1)
            trash, ldap_name = parse[0].split('uid=')
            name_list.append(ldap_name)

        return name_list

    # Cloudshell Commands
    def load_cloudshell_users(self):
        user_list = []
        cs_query = self.cs_session.GetAllUsersDetails().Users
        for entry in cs_query:
            user_list.append(entry.Name)
        return user_list

    def create_cloudshell_user(self, user_name, password, email):
        self.cs_session.AddNewUser(username=user_name, password=password, email=email, isActive=True, isAdmin=False)

    def _delete_cloudshell_user(self, user_name):
        self.cs_session.DeleteUser(username=user_name)

    def assign_cloudshell_usergroup(self, user_list, group_name):
        self.cs_session.AddUsersToGroup(usernames=user_list, groupName=group_name)

    def remove_cloudshell_usergroup(self, user_list, group_name):
        self.cs_session.RemoveUsersFromGroup(usernames=user_list, groupName=group_name)

    def get_cloudshell_user_detail(self, user_name):
        return self.cs_session.GetUserDetails(username=user_name)

    def is_active(self, user_name):
        active_flag = self.cs_session.GetUserDetails(user_name).IsActive
        if active_flag:
            return True
        else:
            return False

    def make_cloudshell_user_inactive(self, user_name):
        self.cs_session.UpdateUser(username=user_name, isActive=False)

    def make_cloudshell_user_active(self, user_name):
        self.cs_session.UpdateUser(username=user_name, isActive=True)

    def is_admin(self, user_name):
        my_user_groups = self.cs_session.GetUserDetails(user_name).Groups
        for x in my_user_groups:
            if x.Name == "System Administrators":
                return True
        else:
            return False

    # Logging function

    def write2log(self, entry):
        f=open(self.logfile, 'a')
        temp = ''
        temp += time.strftime('%Y-%m-%d %H:%M:%S')
        temp += ' || '
        temp += entry
        temp += '\n'
        f.write(temp)
        f.close()

    # list comparision
    def check_list(self, list, item):
        # returns true if the item is in the list
        try:
            index = list.index(item)
            return True
        except:
            return False

######################################################
def main():
    """

    :rtype: object
    """
    local = ldapimport()
    local.write2log('-=* Starting AD import *=-')

    master_list = []

    # start adding new users
    for each in local.configs["ldap_base_DN"]:
        local.write2log('query to ' + local.configs["ldap_connection"] + ' ' + each)

        # get ldap group
        ldap_list = local.ldap_query(local.configs["ldap_connection"],
                                    local.configs["ldap_username"],
                                    local.configs["ldap_password"],
                                    each,
                                    local.configs["ldap_use_auth"])

        # get CloudShell user list
        cs_list = local.load_cloudshell_users()

        # compare ldap to cs - add if not in cloudshell
        for ldap_name in ldap_list:
            master_list.append(ldap_name)
            if local.check_list(cs_list, ldap_name) is False:
                local.create_cloudshell_user(ldap_name, local.configs["new_user_default_password"], '')
                local.write2log('Created new CloudShell User: ' + ldap_name)
                if local.configs["use_new_user_default_group"] == 1:
                    local.assign_cloudshell_usergroup([ldap_name],
                                                      local.configs["new_user_default_group"])
                    local.write2log('Added ' + ldap_name + ' to ' + local.configs["new_user_default_group"])
            elif local.is_active(ldap_name) is False:
                local.make_cloudshell_user_active(ldap_name)
                local.write2log('Acitvated User: ' + ldap_name)

        # get updated cs_list
        cs_list = local.load_cloudshell_users()

        # compare CS to LDAP and de-activate users not found
        for name in cs_list:
            if local.check_list(master_list, name) is False:
                # if using whitelist see if they are on it
                if local.configs["qs_use_whitelist"] == 1:
                    wl_check = local.check_list(local.configs["qs_whitelist"], name)
                else:
                    wl_check = False

                # check to see if they are an admin
                admin_check = local.is_admin(name)

                # if admin or on whitelist - ignore active status (don't do anything)
                if admin_check or wl_check:
                    pass
                else:
                    local.make_cloudshell_user_inactive(name)
                    local.write2log('Deactivated User: ' + name)
            elif local.is_active(name) is False:  # if on master list and is inactive, activate
                local.make_cloudshell_user_active(name)
                local.write2log('Activated User: ' + name)
    # end for Each - putting all new users into groups

    # start sub-group ordering
    if local.configs["use_subgroups"] == 1:
        local.write2log("-- Subgroup ordering")
        subgroup_list = local.configs["qs_subgroups"]
        for index, each_ldap in enumerate(local.configs["ldap_subgroups"]):
            local.write2log('SubGroup Query ' + each_ldap)

            ldap_list = local.ldap_query(local.configs["ldap_connection"],
                            local.configs["ldap_username"],
                            local.configs["ldap_password"],
                            each_ldap,
                            local.configs["ldap_use_auth"])

            cs_list = local.load_cloudshell_users()

            for name in cs_list:
                cs_user_detail = local.get_cloudshell_user_detail(name)
                group = subgroup_list[index]

                # if user in on the ldap subgroup list, and not already in cloudshell group, put in subgroup
                if local.check_list(ldap_list, name) and local.check_list(cs_user_detail.Groups, group) is False:
                    local.assign_cloudshell_usergroup(name, group)
                    local.write2log('Added User ' + name + ' to group ' + group)

                # if not in said ldap group, but are in the subgroup, pull them out
                elif local.check_list(cs_user_detail.Groups, group):
                    if local.is_admin(name) is False:
                        if local.configs["qs_use_whitelist"] == 1:
                            if local.check_list(local.configs["qs_whitelist"], name) is False:
                                local.write2log('Removing user ' + name + ' from group ' + group)
                                local.remove_cloudshell_usergroup(name, group)

    # end subgroup ordering

    local.write2log(">> COMPLETE <<")
    print 'all done'

################################################################

if __name__ == '__main__':
    main()
