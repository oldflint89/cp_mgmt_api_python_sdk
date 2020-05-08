from __future__ import print_function
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

    add_gw = client.api_call("add-simple-gateway", {'name' : gw_name, 'ipv4-address' : gw_ip, 'one-time-password' : sic, 'version': 'R80', 'application-control' : 'true', 'url-filtering' : 'true', 'ips' : 'true', 'anti-bot' : 'true', 'anti-virus' : 'true', 'threat-emulation' : 'true'})
    if add_gw.success:
	    print("The gateway was added successfully.")
	    print(add_gw.data['uid'])
    else:
	    print("Failed to add the gateway.")
	    exit(1)

        # publish the result
    publish_res = client.api_call("publish", {})
    if publish_res.success:
        print("The changes were published successfully.")
    else:
            print("Failed to publish the changes.")

if __name__ == "__main__":
    main()
