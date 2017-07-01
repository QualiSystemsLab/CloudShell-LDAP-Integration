"""
__author__ ksaper
this is designed to look through a series of ldap groups and:
import, managed as active, and place in specific groups, within
Quali's CloudShell, ignoring admins and whitelisted users
"""
import time
import cloudshell.api.cloudshell_api as cs_api
import json
import base64
import ldap
import logging
import os


LOG_DICT = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "WARN": 30, "ERROR": 40, "CRITICAL": 50, "CRIT": 50}


class LDAPImport(object):
    """Used to align CloudShell users/groups with LDAP Group Users"""

    def __init__(self):
        """
        :rtype: object
        :param self:
        :return:
        """
        # set the config file path & load the json file
        cwd = os.getcwd()
        self.json_file_path = '%s/config.json' % cwd
        self.configs = json.loads(open(self.json_file_path).read())

        # set logging file path
        self.logfilename = self.configs['log_file_path']
        self.loglevel = self.configs['log_level'].upper()

        # set logging
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',
                            filename=self.logfilename,
                            level=LOG_DICT[self.loglevel])

        # set the default password for new user
        self.default_password = self.configs['new_user_default_password']

        # start CloudShell API Session
        self.cs_session = cs_api.CloudShellAPISession(self.configs["qs_server_hostname"],
                                                      self.configs["qs_admin_username"],
                                                      base64.b64decode(self.configs["qs_admin_password"]),
                                                      domain="Global")

    # Active Directory Commands
    def ldap_query(self, ldap_connection, ldap_query_str='', ldap_user='', ldap_pw='', auth=False):
        """
        Returns a group list from an Active Directory Query
        :param self:
        :param str ldap_connection: LDAP Server String
        :param str ldap_user: Active Directory username for connection
        :param str ldap_pw: Active Directory password for connection
        :param str ldap_query_str: LDAP Query to run
        :param bool auth: If the LDAP Server requires login authentication
        :return:
        """

        ldap_con = ldap.initialize(ldap_connection)

        try:
            ldap_con.protocol_version = ldap.VERSION3
            ldap_con.set_option(ldap.OPT_REFERRALS, 0)
            if auth:
                ldap_con.simple_bind_s(ldap_user, ldap_pw)
        except ldap.LDAPError as error_msg:
            print error_msg

        name_list = []

        ad_list = ldap_con.read_s(ldap_query_str)
        for name in ad_list["uniqueMember"]:
            parse = name.split(",", 1)  # this is the first line for split mod
            trash, ldap_name = parse[0].split('uid=')  # this is the 2nd line for split mod
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
            if x.Name == "System Administrators" or x.Name == "Domain Administrators":
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
    local = LDAPImport()
    logging.info('Starting LDAP Session')

    master_list = []

    if local.configs["do_ldap_import"]:
        logging.info('Running LDAP user import subroutine')
        # start adding new users
        for each in local.configs["ldap_import_DN"]:
            logging.info('query to %s: %s' %(local.configs["ldap_connection"], each))

            # get ldap group
            ldap_list = local.ldap_query(local.configs["ldap_connection"],
                                         each,
                                         local.configs["ldap_username"],
                                         local.configs["ldap_password"],
                                         local.configs["ldap_use_auth"])

            # get CloudShell user list
            cs_list = local.load_cloudshell_users()

            # compare ldap to cs - add if not in cloudshell
            for ldap_name in ldap_list:
                master_list.append(ldap_name)
                if ldap_name not in cs_list:
                    local.create_cloudshell_user(ldap_name, local.configs["new_user_default_password"], '')
                    logging.info('Created new CloudShell User: %s' % ldap_name)
                    if local.configs["use_new_user_default_group"]:
                        local.assign_cloudshell_usergroup([ldap_name],
                                                          local.configs["new_user_default_group"])
                        logging.info('Added %s to %s' %(ldap_name, local.configs["new_user_default_group"]))
                elif not local.is_active(ldap_name):
                    local.make_cloudshell_user_active(ldap_name)
                    logging.info('Acitvated User: %s' % ldap_name)
        # end for Each - putting all new users into groups
    # end ldap import

    if local.configs["do_deactivation"] and local.configs["do_ldap_import"]:
        logging.info('Running deactivation subroutine')
        # get updated cs_list
        cs_list = local.load_cloudshell_users()

        # compare CS to LDAP and de-activate users not found
        for name in cs_list:
            if not local.check_list(master_list, name):
                wl_check = False
                # if using whitelist see if they are on it
                if local.configs["qs_use_whitelist"]:
                    if name in local.configs['qs_whitelist']:
                        wl_check = True

                # check to see if they are an admin
                admin_check = local.is_admin(name)

                # if admin or on whitelist - ignore active status (don't do anything)
                if admin_check or wl_check:
                    pass
                else:
                    if local.is_active(name):  # de-active if active
                        local.make_cloudshell_user_inactive(name)
                        logging.info('Deactivated User: %s' % name)
            elif not local.is_active(name):  # if on master list and is inactive, activate
                local.make_cloudshell_user_active(name)
                logging.info('Activated User: %s' % name)
    #end deactivation loop

    # start sub-group ordering
    if local.configs["use_subgroups"]:
        logging.info("Running subgroup ordering subroutine")
        subgroup_list = local.configs["subgroup_listing"].keys()
        for group in subgroup_list:
            logging.info('query to %s %s' %(local.configs["ldap_connection"],
                                            local.configs['subgroup_listing'][group]))

            ldap_list = local.ldap_query(local.configs["ldap_connection"],
                                         ldap_query_str=local.configs['subgroup_listing'][group],
                                         ldap_user=local.configs["ldap_username"],
                                         ldap_pw=local.configs["ldap_password"],
                                         auth=local.configs["ldap_use_auth"])

            cs_list = local.load_cloudshell_users()

            for name in cs_list:
                cs_user_detail = local.get_cloudshell_user_detail(name)

                member_list = []
                for ea in cs_user_detail.Groups:
                    # groupname = ea.Name
                    member_list.append(ea.Name)

                # if user in on the ldap subgroup list, not a member of the group, add them to the group
                if (name in ldap_list) and (group not in member_list):
                    local.assign_cloudshell_usergroup([name], group)
                    logging.info('Added User %s to group %s' % (name, group))

                # if not in said ldap group, but are in the subgroup, pull them out
                elif (group in member_list) and name not in ldap_list:
                    if local.is_admin(name) is False:
                        if local.configs["qs_use_whitelist"]:
                            if name not in local.configs["qs_whitelist"]:
                                local.remove_cloudshell_usergroup([name], group)
                                logging.info('Removed user %s from group %s' % (name, group))
                        else:
                            local.remove_cloudshell_usergroup([name], group)
                            logging.info('Removed user %s from group %s' % (name, group))
    # end subgroup ordering

    logging.info("COMPLETE")

################################################################

if __name__ == '__main__':
    main()
