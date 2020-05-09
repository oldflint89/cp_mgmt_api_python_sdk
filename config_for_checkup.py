from __future__ import print_function
from time import sleep
import getpass
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cpapi import APIClient, APIClientArgs

def main():
    # getting details from the user
    api_server = input("Enter server IP address or hostname:")
    username = input("Enter username: ")

    if sys.stdin.isatty():
        password = getpass.getpass("Enter password: ")
    else:
        print("Attention! Your password will be shown on the screen!")
        password = input("Enter password: ")
    client_args = APIClientArgs(server=api_server)

    with APIClient(client_args) as client:
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)
        login_res = client.login(username, password)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)


        gw_name = input("Enter the gateway name:")
        gw_ip = input("Enter th gateway IP address:")
        sic = input("Enter one-time password for the gateway(SIC):")
        version = input("Enter the gateway version(like RXX.YY):")
        add_gw = client.api_call("add-simple-gateway", {'name' : gw_name, 'ipv4-address' : gw_ip, 'one-time-password' : sic, 'version': version.capitalize(), 'application-control' : 'true', 'url-filtering' : 'true', 'ips' : 'true', 'anti-bot' : 'true', 'anti-virus' : 'true', 'threat-emulation' : 'true'})
        if add_gw.success and add_gw.data['sic-state'] != "communicating":
            print("Secure connection with the gateway hasn't established!")
            exit(1)
        elif add_gw.success:
            print("The gateway was added successfully.")
            gw_uid = add_gw.data['uid']
        else:
            print("Failed to add the gateway - {}".format(add_gw.error_message))
            exit(1)

        change_policy = client.api_call("set-access-layer", {"name" : "Network", "applications-and-url-filtering": "true", "content-awareness": "true"})
        if change_policy.success:
            print("The policy has been changed successfully")
        else:
            print("Failed to change the policy- {}".format(change_policy.error_message))
        change_rule = client.api_call("set-access-rule", {"name" : "Cleanup rule", "layer" : "Network", "action": "Accept", "track": {"type": "Detailed Log", "accounting": "true"}})
        if change_rule.success:
            print("The cleanup rule has been changed successfully")
        else:
            print("Failed to change the cleanup rule- {}".format(change_rule.error_message))

        # publish the result
        publish_res = client.api_call("publish", {})
        if publish_res.success:
            print("The changes were published successfully.")
        else:
                print("Failed to publish the changes.")

        install_access_policy = client.api_call("install-policy", {"policy-package" : "Standard", "access" : 'true',  "threat-prevention" : 'false', "targets" : gw_uid})

        if install_access_policy.success:
            print("The access policy is installing...")
        else:
            print("Failed to install access policy - {}".format(install_access_policy.error_message))

        def check_policy_progress(connection):
            check_policy = connection.api_call("show-tasks", {"status" : "in-progress"})
            if check_policy.success:
                if int(check_policy.data['total']) == 0:
                    print('Policy has installed')
                    return True
                else:
                    print('The policy installation progress is {}%'.format(check_policy.data))
                    return False

        policy_installed = False
        while not policy_installed:
            check_policy_progress(client)
            sleep(2)

        install_tp_policy = client.api_call("install-policy", {"policy-package" : "Standard", "access" : 'false',  "threat-prevention" : 'true', "targets" : gw_uid})

        if install_tp_policy.success:
            print("The threat prevention policy is installing...")
        else:
            print("Failed to install threat prevention policy - {}".format(install_tp_policy.error_message))

        policy_installed = False
        while not policy_installed:
            check_policy_progress(client)
            sleep(2)

if __name__ == "__main__":
    main()
