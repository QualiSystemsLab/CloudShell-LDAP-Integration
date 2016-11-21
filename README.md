# CloudShell-LDAP-Integration
This project syncs specific LDAP groups with specific CloudShell user groups, so CloudShell and LDAP remain synced when there are changes to user information in LDAP

## Instructions

The main python script is designed to loop through the “ldap_import_DN” list, creating new CloudShell users for any ID’s that are on the list, but not currently in CloudShell.
 - They users will be assigned the default password.
 - Optionally they will be assigned to a default CloudShell user group.

In addition, after the main import is ran, all CloudShell users can be validated against the combined list of users from all imports DNs, and deactivated, excluding system admins and users in the whitelist.
* Note - this does not work without doing the import first - it’s an option of import

Last the system can optionally arrange users against a list of DN groups.
The script will pull a list of users from each of the ldap groups, and if that user exists in CloudShell, will then assign them to the corresponding CloudShell Group.
It will also attempt to remove any users that don’t belong in that CloudShell group, excluding system admins and whitelist users.


## JSON Config File:

* ldap_conncetion - ldap URL
* ldap_use_auth - the ldap server requires authentication on log in
* ldap_username - authentication user name
* ldap_password - authentication password
* qs_server_hostname - hostname or IP of the Quali CloudShell Server (app server, not portal)
* qs_admin_username - the CloudShell Admin account name
* qs_admin_password - the CloudShell Admin password, base64 hash
* log_file_path - where you would like the log to be written, including name of file
* qs_use_whitelist - 1 for true, use the qs_whitelist to exclude filtering of users
* qs_whitelist - list of CloudShell usernames for exclusion
* do_ldap_import - 1 for true, use the ldap_import_DN list to create users in CloudShell
* ldap_import_DN - list of LDAP Group (ou) quires to extract users from
	* in the code splits by uniqueMember & uid= can be modified if needed (line 62)
* new_user_default_password - the default password for any user created in CloudShell by the script
* use_new_user_default_group - 1 for true, assign a new user to a default group when created
* new_user_default_group - name of the CloudShell group to assign new users too
* do_deactivation - 1 for true, run deactivation routine of users not found in the import lookups
* use_subgroups - 1 for true, use the ldap_subgroup list to assign users to CloudShell Groups
* ldap_subgroups - list of additional DN’s to lookup and assign to CloudShell Groups
	* 1 to 1 match of the list in qs_subgroups - must be evenly matched
* qs_subgroups - list of CloudShell groups, matched to ldap_subgroups
