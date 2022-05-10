#!/usr/bin/python

import argparse
from ast import arg
import getpass
import requests

timeout = 5

def get_args(argv=None) -> dict:
    parser = argparse.ArgumentParser(description="Creates an SVM-DR relationship from an ONTAP vserver to a new FSx for ONTAP vserver.")
    parser.add_argument("-sa", "--source-address", help="Address of the source management interface.", required=True)
    parser.add_argument("-da", "--destination-address", help="Address of the destination management interface.", required=True)
    parser.add_argument("-su", "--source-username", help="Username of an admin account on the source ONTAP cluster.", required=True)
    parser.add_argument("-du", "--destination-username", help="Username of an admin account on the destination FSx for ONTAP system.", required=True)
    parser.add_argument("-sv", "--source-vserver", help="Name of the source SVM on the source cluster.", required=True)
    parser.add_argument("-dv", "--destination-vserver", help="Name of the destination SVM on the destination FSx for ONTAP system.", required=True)
    return parser.parse_args(argv)

def get_password(prompt: str) -> str:
    try:
        return getpass.getpass(prompt=prompt)
    except Exception as error:
        print("ERROR", error)

def get_volumes(cluster_address: str, vserver_name: str, username: str, password: str) -> dict:
    url = "https://{}/api/storage/volumes?fields=is_svm_root&svm.name={}".format(cluster_address, vserver_name)
    response = requests.get(
        url=url,
        auth=(username, password),
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["records"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def get_peers(cluster_address: str, vserver_name: str, username: str, password: str) -> dict:
    url = "https://{}/api/svm/peers?svm.name={}".format(cluster_address, vserver_name)
    response = requests.get(
        url=url,
        auth=(username, password),
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["records"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))
    

def good_ontap_response(ontap_response: dict) -> bool:
    if ontap_response["error"]:
        return False
    else:
        return True

def peers_in_peered_state(src_get_svm_response: dict, src_vserver: str, dst_get_svm_response: dict, dst_vserver: str) -> bool:
    if any(obj["peer"]["svm"]["name"] == dst_vserver for obj in src_get_svm_response) and \
        any(obj["peer"]["svm"]["name"] == src_vserver for obj in dst_get_svm_response):
        return True
    else:
        return False

def create_volume_on_dest(cluster_address: str, vserver_name: str, username: str, password: str, volume_name: str, volume_size_gb: str) -> dict:
    url = "https://{}/api/storage/volumes".format(cluster_address)
    body = {
        "name": volume_name,
        "size": "{}G".format(volume_size_gb),
        "type": "DP",
        "svm": {
            "name": vserver_name
        }
    }
    response = requests.post(
        url=url,
        auth=(username, password),
        json=body,
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["job"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))
            
def rename_volume(cluster_address: str, username: str, password: str, volume_uuid: str, new_volume_name: str) -> dict:
    url = "https://{}/api/storage/volumes/{}".format(cluster_address, volume_uuid)
    body = {
        "name": new_volume_name
    }
    response = requests.patch(
        url=url,
        auth=(username, password),
        json=body,
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["job"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def get_root_volume_info(get_volume_json: dict) -> dict:
    for i, volume in enumerate(get_volume_json):
        if volume["is_svm_root"] == True:
            return {
                "name": volume["name"],
                "uuid": volume["uuid"]
                }
    raise Exception("No root volume found!")

def create_volume_snapmirror(dst_cluster_address: str, dst_cluster_username: str, dst_cluster_password: str, src_vserver: str, src_volume: str, src_vol_size_gb: str, dst_vserver: str, dst_volume: str) -> dict:
    url = "https://{}/api/snapmirror/relationships".format(dst_cluster_address)
    body = {
        "source": {
            "path": "{}:{}".format(src_vserver, src_volume)
        },
        "destination": {
            "path": "{}:{}".format(dst_vserver, dst_volume)
        },
        "create_destination": {
            "size": "{}G".format(src_vol_size_gb),
            "enabled": True
        },
        "policy": {
            "name": "MirrorAllSnapshotsDiscardNetwork"
        },
        "preserve": True,
        "schedule": "pg-15-minutely"
    }
    response = requests.post(
        url=url,
        auth=(dst_cluster_username, dst_cluster_password),
        json=body,
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["job"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def get_snapmirror_relationships(cluster_address: str, vserver_name: str,  username: str, password: str) -> dict:
    url = "https://{}/api/snapmirror/relationships?svm.name={}".format(cluster_address, vserver_name)
    response = requests.get(
        url=url,
        auth=(username, password),
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["records"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def initialize_snapmirror_relationship(cluster_address: str, username: str, password: str, snapmirror_uuid: str) -> dict:
    url = "https://{}/api/snapmirror/relationships/{}".format(cluster_address, snapmirror_uuid)
    body = {
        "state": "snapmmirrored"
    }
    response = requests.patch(
        url=url,
        auth=(username, password),
        json=body,
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["job"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def stop_vserver(cluster_address: str, vserver_uuid: str,  username: str, password: str) -> dict:
    url = "https://{}/api/svm/svms/{}".format(cluster_address, vserver_uuid)
    body = {
        "state": "stopped"
    }
    response = requests.patch(
        url=url,
        auth=(username, password),
        json=body,
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["job"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def create_svm_snapmirror(dst_cluster_address: str, dst_cluster_username: str, dst_cluster_password: str, src_vserver: str, dst_vserver: str) -> dict:
    url = "https://{}/api/snapmirror/relationships".format(dst_cluster_address)
    body = {
        "source": {
            "path": "{}:".format(src_vserver)
        },
        "destination": {
            "path": "{}:".format(dst_vserver)
        },
        "policy": {
            "name": "MirrorAllSnapshotsDiscardNetwork"
        },
        "preserve": True,
        "schedule": "pg-15-minutely"
    }
    response = requests.post(
        url=url,
        auth=(dst_cluster_username, dst_cluster_password),
        json=body,
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["job"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def build_all_snapmirrors_on_dst_vserver_not_root(src_volumes_json: dict, dst_address: str, dst_vserver: str, dst_username: str, dst_password: str, src_vserver: str) -> None:
    for volume in src_volumes_json:
        if (not volume["is_svm_root"]):
            create_volume_snapmirror(dst_cluster_address=dst_address, dst_cluster_username=dst_username, dst_cluster_password=dst_password, src_vserver=src_vserver, src_volume=volume["name"], src_vol_size_gb=volume["size"], dst_vserver=dst_vserver, dst_volume=volume["name"])

def initialize_all_snapmirrors(cluster_address: str, vserver_name: str,  username: str, password: str) -> None:
    all_snapmirrors = get_snapmirror_relationships(cluster_address=cluster_address, vserver_name=vserver_name, username=username, password=password)
    for relationship in all_snapmirrors:
        initialize_snapmirror_relationship(cluster_address=cluster_address, username=username, password=password, snapmirror_uuid=relationship["uuid"])

def get_svm_uuid(cluster_address: str, vserver_name: str, username: str, password: str) -> str:
    url = "https://{}/api/svm/svms?name={}".format(cluster_address, vserver_name)
    response = requests.get(
        url=url,
        auth=(username, password),
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["records"][0]["uuid"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def get_svm_dr_relationship_uuid(cluster_address: str, dst_vserver_name: str, username: str, password: str) -> str:
    url = "https://{}/api/snapmirror/relationships?destination.path={}:".format(cluster_address, dst_vserver_name)
    response = requests.get(
        url=url,
        auth=(username, password),
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        return response["records"][0]["uuid"]
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def job_successful(cluster_address: str, username: str, password: str, job_uuid: str) -> bool:
    url = "https://{}/api/cluster/jobs/{}:".format(cluster_address, job_uuid)
    response = requests.get(
        url=url,
        auth=(username, password),
        verify=False,
        timeout=timeout
        )
    if good_ontap_response(response):
        if (response["state"] == "success"):
            return True
        elif (response["state"] == "failure"):
            raise Exception("Job Failed: \n{}".format(response))
        else:
            return False
    else:
        raise Exception("Bad ONTAP response: \n{}".format(response))

def work(args: dict) -> None:
    source_password = get_password("Enter the source cluster password:")
    destination_password = get_password("Enter the destination FSx for ONTAP password:")
    src_volumes = get_volumes(cluster_address=args.source_address, vserver_name=args.source_vserver, username=args.source_username, password=source_password)
    dst_volumes = get_volumes(cluster_address=args.destination_address, vserver_name=args.destination_vserver, username=args.destination_username, password=destination_password)
    src_peers = get_peers(cluster_address=args.source_address, vserver_name=args.source_vserver, username=args.source_username, password=source_password)
    dst_peers = get_peers(cluster_address=args.destination_address, vserver_name=args.destination_vserver, username=args.destination_username, password=destination_password)
    if (not peers_in_peered_state(src_get_svm_response=src_peers, src_vserver=args.source_vserver, dst_get_svm_response=dst_peers, dst_vserver=args.destination_vserver)):
        raise Exception("Vservers are not peered! Please peer the vservers then try again.")
    build_all_snapmirrors_on_dst_vserver_not_root(src_volumes_json=src_volumes, dst_address=args.destination_address, dst_vserver=args.destination_vserver, dst_username=args.destination_username, dst_password=destination_password, src_vserver=args.source_vserver)
    src_root_volume_info = get_root_volume_info(src_volumes)
    dst_root_volume_info = get_root_volume_info(dst_volumes)
    rename_volume(cluster_address=args.destination_address, username=args.destination_username, password=destination_password, volume_uuid=dst_root_volume_info["uuid"], new_volume_name=src_root_volume_info["name"])
    initialize_all_snapmirrors(cluster_address=args.destination_address, vserver_name=args.destination_vserver, username=args.destination_username, password=destination_password)
    dst_svm_uuid = get_svm_uuid(cluster_address=args.destination_address, vserver_name=args.destination_vserver, username=args.destination_username, password=destination_password)
    stop_vserver(cluster_address=args.destination_address, vserver_uuid=dst_svm_uuid)
    create_svm_snapmirror(dst_cluster_address=args.destination_address, dst_vserver=args.destination_vserver, dst_cluster_username=args.destination_username, dst_cluster_password=destination_password, src_vserver=args.source_vserver)
    svm_snapmirror_uuid = get_svm_dr_relationship_uuid(cluster_address=args.destination_address, username=args.destination_username, password=destination_password, dst_vserver_name=args.destination_vserver)
    initialize_snapmirror_relationship(cluster_address=args.destination_address, username=args.destination_username, password=destination_password, snapmirror_uuid=svm_snapmirror_uuid)

if __name__ == "__main__":
    argvals = None
    argvals = '-sa 10.0.0.1 -da 10.0.0.2 -su admin -du admin -sv source_vserver -dv destination_vserver'.split() # Test
    args = get_args(argvals)
    work(args)