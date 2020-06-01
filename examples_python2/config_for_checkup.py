from __future__ import print_function
import getpass
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from cpapi import APIClient, APIClientArgs

def main():
    with APIClient() as client:
       # if client.check_fingerprint() is False:
       #     print("Could not get the server's fingerprint - Check connectivity with the server.")
       #     exit(1)
        login_res = client.login_as_root()

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        gw_name = raw_input("Enter the gateway name:")
        gw_ip = raw_input("Enter the gateway IP address:")
        if sys.stdin.isatty():
            sic = getpass.getpass("Enter one-time password for the gateway(SIC): ")
        else:
            print("Attention! Your password will be shown on the screen!")
            sic = raw_input("Enter one-time password for the gateway(SIC): ")
        version = raw_input("Enter the gateway version(like RXX.YY):")
        add_gw = client.api_call("add-simple-gateway", {'name' : gw_name, 'ipv4-address' : gw_ip, 'one-time-password' : sic, 'version': version.capitalize(), 'application-control' : 'true', 'url-filtering' : 'true', 'ips' : 'true', 'anti-bot' : 'true', 'anti-virus' : 'true', 'threat-emulation' : 'true'})
        if add_gw.success and add_gw.data['sic-state'] != "communicating":
            print("Secure connection with the gateway hasn't established!")
            exit(1)
        elif add_gw.success:
            print("The gateway was added successfully.")
            gw_uid = add_gw.data['uid']
            gw_name = add_gw.data['name']
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
                print("Failed to publish the changes - {}".format(install_tp_policy.error_message))

        install_access_policy = client.api_call("install-policy", {"policy-package" : "Standard", "access" : 'true',  "threat-prevention" : 'false', "targets" : gw_uid})
        if install_access_policy.success:
            print("The access policy has been installed")
        else:
                print("Failed to install access policy - {}".format(install_tp_policy.error_message))

        install_tp_policy = client.api_call("install-policy", {"policy-package" : "Standard", "access" : 'false',  "threat-prevention" : 'true', "targets" : gw_uid})
        if install_tp_policy.success:
            print("The threat prevention policy has been installed")
        else:
            print("Failed to install threat prevention policy - {}".format(install_tp_policy.error_message))
        
        # add passwords and passphrases to dictionary
        with open('additional_pass.conf') as f:
            line_num = 0
            for line in f:
                line_num += 1
                add_password_dictionary = client.api_call("run-script", {"script-name" : "Add passwords and passphrases", "script" : "printf \"{}\" >> $FWDIR/conf/additional_pass.conf".format(line), "targets" : gw_name})
                if add_password_dictionary.success:
                    print("The password dictionary line {} was added successfully".format(line_num))
                else:
                    print("Failed to add the dictionary - {}".format(add_password_dictionary.error_message))

main()
