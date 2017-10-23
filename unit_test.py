from ldap_user_mgmt import ldapimport

test_runner = ldapimport()
error_log = []
t_user = 'unit_test_user'
user_created = 0


# Get user list from CloudShell
try:
    master_list = test_runner.load_cloudshell_users()
    print 'CloudShell User List'
    print master_list
except:
    error_log.append('Fail user list CloudShell')
    print 'Unable to get user list from CloudShell'

# check whitelist
print 'The white list: '
for name in test_runner.configs['qs_whitelist']:
    print name

# check is_admin
try:
    if test_runner.is_admin('admin'):
        print '"admin" is an admin'
    else:
        print('Error "admin" is not an admin')
        error_log.append('"admin" not flagged as admin')
except:
    error_log.append('Error on is_admin check with "admin"')
    print 'Unable to validate "admin" as an admin'

# create a new user
try:
    test_runner.create_cloudshell_user(user_name=t_user,
                                       password='none',
                                       email='blank@blank.com')
    user_created = 1
except:
    error_log.append('Fail user creation')
    print 'Unable to create user'

if user_created == 1:
    # validate is_active
    try:
        check = test_runner.is_active(t_user)
        if check:
            print 'Test User is active'
        else:
            error_log.append('Test user was not created in an active state')
    except:
        error_log.append('Unable to check active status')
        print 'Unable to check active status'

    # check make_inactive & make_active
    try:
        test_runner.make_cloudshell_user_inactive(t_user)
        try:
            test_runner.make_cloudshell_user_active(t_user)
        except:
            error_log.append('Unable to make user active')
            print 'Error making user active'
    except error_log.append('Unable to make user inactive'):
        print 'Error making user inactive'

    # assign to user group
    try:
        test_runner.assign_cloudshell_usergroup([t_user], test_runner.configs['new_user_default_group'])
    except:
        error_log.append('Unable to assign user to usergroups')
        print 'Error assigning user to a usergroup'

    # remove user from usergroup
    try:
        test_runner.remove_cloudshell_usergroup([t_user], test_runner.configs['new_user_default_group'])
    except:
        error_log.append('Unable to remove user from usergroup')
        print 'Error removing user from usergroup'

    try:
        test_runner._delete_cloudshell_user(t_user)
    except:
        error_log.append('Unable to delete the test user: ' + t_user)
        print 'Error deleting the test user account'
    # end if statment

# get user details from admin
try:
    details = test_runner.get_cloudshell_user_detail('admin')
    print details.Name
except:
    error_log.append('Unable to get user detail for admin')
    print 'Error get_cloudshell_user_details'

# try the ldap user lists
for each in test_runner.configs['ldap_import_DN']:
    try:
        list = test_runner.ldap_query(test_runner.configs["ldap_connection"],
                                      test_runner.configs["ldap_username"],
                                      test_runner.configs["ldap_password"],
                                      each,
                                      test_runner.configs["ldap_use_auth"])

        print '\nLDAP user list from ' + each
        for name in list:
            print name
    except:
        error_log.append('Unable to get LDAP query, ' + each)
        print 'Error on Group ' + each
        raise

# try the ldap subgroups
for each in test_runner.configs['ldap_subgroups']:
    try:
        list = test_runner.ldap_query(test_runner.configs["ldap_connection"],
                                      test_runner.configs["ldap_username"],
                                      test_runner.configs["ldap_password"],
                                      each,
                                      test_runner.configs["ldap_use_auth"])
        print '\nLDAP subgroup user list from ' + each
        for name in list:
            print name
    except:
        error_log.append('Unable to get LDAP subgroup query, ' + each)
        print 'Error on subgroup ' + each

# last thing, print out error_log

print '\n>> Unit test complete'
if len(error_log) > 0:
    print 'Errors during run:'
    for error in error_log:
        print '- ' + error
else:
    print 'No Errors found'
