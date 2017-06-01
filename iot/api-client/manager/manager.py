#!/usr/bin/env python

# Copyright 2017 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Example of using the Google Cloud IoT Core device manager to administer
devices.

This example uses the Device Manager API to create, retrieve, disable, list and
delete Cloud IoT Core devices and registries, using both RSA and eliptic curve
keys for authentication.

Before you run the sample, configure Cloud IoT Core as described in the
documentation at https://cloud.google.com/iot or by following the instructions
in the README located in the parent folder.

Usage example:

  $ python manager.py \
      --project_id=my-project-id \
      --pubsub_topic=projects/my-project-id/topics/my-topic-id \
      --api_key=YOUR_API_KEY \
      --ec_public_key_file=../ec_public.pem \
      --rsa_certificate_file=../rsa_cert.pem \
      --service_account_json=$HOME/service_account.json

Troubleshooting:

  - If you get a 400 error when running the example, with the message "The API
    Key and the authentication credential are from different projects" it means
    that you are using the wrong API Key. Ensure that you are using the API key
    from Google Cloud Platform's API Manager's Credentials page.
"""

import argparse
import sys
import time

from google.cloud import pubsub
from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError


def create_iot_topic(topic_name):
    """Creates a PubSub Topic and grants access to Cloud IoT Core."""
    pubsub_client = pubsub.Client()
    topic = pubsub_client.topic(topic_name)
    topic.create()

    topic = pubsub_client.topic(topic_name)
    policy = topic.get_iam_policy()
    publishers = policy.get('roles/pubsub.publisher', [])
    publishers.append(policy.service_account(
            'cloud-iot@system.gserviceaccount.com'))
    policy['roles/pubsub.publisher'] = publishers
    topic.set_iam_policy(policy)

    return topic


def get_client(service_account_json, api_key):
    """Returns an authorized API client by discovering the IoT API using the
    provided API key and creating a service object using the service account
    credentials JSON."""
    # [START authorize]
    API_SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
    API_VERSION = 'v1beta1'
    DISCOVERY_API = 'https://cloudiot.googleapis.com/$discovery/rest'
    SERVICE_NAME = 'cloudiotcore'

    credentials = service_account.Credentials.from_service_account_file(
            service_account_json)
    scoped_credentials = credentials.with_scopes(API_SCOPES)

    if not credentials:
        sys.exit(
                'Could not load service account credential from {}'
                .format(service_account_json))

    discovery_url = '{}?version={}&key={}'.format(
            DISCOVERY_API, API_VERSION, api_key)

    return discovery.build(
            SERVICE_NAME,
            API_VERSION,
            discoveryServiceUrl=discovery_url,
            credentials=scoped_credentials)
    # [END authorize]


def create_rs256_device(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id, certificate_file):
    """Create a new device with the given id, using RS256 for
    authentication."""
    # [START create_rs256_device]
    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    client = get_client(service_account_json, api_key)
    with open(certificate_file) as f:
        certificate = f.read()

    # Note: You can have multiple credentials associated with a device.
    device_template = {
        'id': device_id,
        'credentials': [{
            'publicKey': {
                'format': 'RSA_X509_PEM',
                'key': certificate
            }
        }]
    }

    return client.projects().locations().registries().devices(
    ).create(parent=registry_name, body=device_template).execute()
    # [END create_rs256_device]


def create_es256_device(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id, public_key_file):
    """Create a new device with the given id, using ES256 for
    authentication."""
    # [START create_rs256_device]
    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    client = get_client(service_account_json, api_key)
    with open(public_key_file) as f:
        public_key = f.read()

    # Note: You can have multiple credentials associated with a device.
    device_template = {
        'id': device_id,
        'credentials': [{
            'publicKey': {
                'format': 'ES256_PEM',
                'key': public_key
            }
        }]
    }

    return client.projects().locations().registries().devices(
    ).create(parent=registry_name, body=device_template).execute()
    # [END create_rs256_device]


def create_unauth_device(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id):
    """Create a new device without authentication."""
    # [START create_noauth_device]
    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    client = get_client(service_account_json, api_key)
    device_template = {
        'id': device_id,
    }

    return client.projects().locations().registries().devices(
    ).create(parent=registry_name, body=device_template).execute()
    # [END create_noauth_device]


def delete_device(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id):
    """Delete the device with the given id."""
    # [START delete_device]
    print('Delete device')
    client = get_client(service_account_json, api_key)
    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    device_name = '{}/devices/{}'.format(registry_name, device_id)

    return client.projects().locations().registries().devices(
    ).delete(name=device_name).execute()
    # [END delete_device]


def delete_registry(
        service_account_json, api_key, project_id, cloud_region, registry_id):
    """Deletes the specified registry."""
    # [START delete_registry]
    print('Delete registry')
    client = get_client(service_account_json, api_key)
    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    return client.projects().locations().registries().delete(
            name=registry_name).execute()
    # [END delete_registry]


def get_device(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id):
    """Retrieve the device with the given id."""
    # [START delete_device]
    print('Getting device')
    client = get_client(service_account_json, api_key)
    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    device_name = '{}/devices/{}'.format(registry_name, device_id)
    device = client.projects().locations().registries().devices(
            ).get(name=device_name).execute()

    print 'Id : {}'.format(device.get('id'))
    print 'Name : {}'.format(device.get('name'))
    print ('Credentials:')
    if device.get('credentials') is not None:
        for credential in device.get('credentials'):
            keyinfo = credential.get('publicKey')
            print '\tcertificate: \n{}'.format(keyinfo.get('key'))
            print '\tformat : {}'.format(keyinfo.get('format'))
            print '\texpiration: {}'.format(credential.get('expirationTime'))

    print 'Config:'
    print '\tdata: {}'.format(device.get('config').get('data'))
    print '\tversion: {}'.format(device.get('config').get('version'))
    print '\tcloudUpdateTime: {}'.format(device.get('config').get(
            'cloudUpdateTime'))

    return device
    # [END delete_device]


def list_devices(
        service_account_json, api_key, project_id, cloud_region, registry_id):
    """List all devices in the registry."""
    # [START list_devices]
    print('Listing devices')
    registry_path = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)
    client = get_client(service_account_json, api_key)
    devices = client.projects().locations().registries().devices(
            ).list(parent=registry_path).execute().get('devices', [])

    for device in devices:
            print('Device: {} : {}'.format(
                    device.get('numId'),
                    device.get('id')))

    return devices
    # [list_devices]


def open_registry(
        service_account_json, api_key, project_id, cloud_region, pubsub_topic,
        registry_id):
    """Gets or creates a device registry."""
    print ('Creating registry')
    client = get_client(service_account_json, api_key)
    registry_parent = 'projects/{}/locations/{}'.format(
            project_id,
            cloud_region)
    body = {
        'eventNotificationConfig': {
            'pubsubTopicName': pubsub_topic
        },
        'id': registry_id
    }
    request = client.projects().locations().registries().create(
        parent=registry_parent, body=body)

    try:
        response = request.execute()
        print('Created registry', registry_id)
        print(response)
    except HttpError as e:
        if e.resp.status == 409:
            # Device registry already exists
            print(
                    'Registry', registry_id,
                    'already exists - looking it up instead.')
            topic_name = '{}/registries/{}'.format(
                    registry_parent, registry_id)
            request = client.projects().locations().registries(
                    ).get(name=topic_name)
            request.execute()


def patch_es256_auth(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id, public_key_file):
    """Patch the device to add an ES256 public key to the device."""
    print('Patch device with ES256 certificate')
    client = get_client(service_account_json, api_key)
    registry_path = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    with open(public_key_file) as f:
        public_key = f.read()

    patch = {
        'credentials': [{
            'publicKey': {
                'format': 'ES256_PEM',
                'key': public_key
            }
        }]
    }

    device_name = '{}/devices/{}'.format(registry_path, device_id)

    return client.projects().locations().registries().devices().patch(
            name=device_name, updateMask='credentials', body=patch).execute()


def patch_rsa256_auth(
        service_account_json, api_key, project_id, cloud_region, registry_id,
        device_id, public_key_file):
    """Patch the device to add an RSA256 public key to the device."""
    print('Patch device with RSA256 certificate')
    client = get_client(service_account_json, api_key)
    registry_path = 'projects/{}/locations/{}/registries/{}'.format(
            project_id, cloud_region, registry_id)

    with open(public_key_file) as f:
        public_key = f.read()

    patch = {
        'credentials': [{
            'publicKey': {
                'format': 'RSA_X509_PEM',
                'key': public_key
            }
        }]
    }

    device_name = '{}/devices/{}'.format(registry_path, device_id)

    return client.projects().locations().registries().devices().patch(
            name=device_name, updateMask='credentials', body=patch).execute()


def parse_command_line_args():
    """Parse command line arguments."""
    default_registry = 'cloudiot_device_manager_example_registry_{}'.format(
            int(time.time()))

    parser = argparse.ArgumentParser(
            description='Example of Google Cloud IoT Core device management.')

    # Required arguments
    parser.add_argument(
            '--project_id', required=True, help='GCP cloud project name.')
    parser.add_argument(
            '--pubsub_topic',
            required=True,
            help=('Google Cloud Pub/Sub topic. '
                  'Format is projects/project_id/topics/topic-id'))
    parser.add_argument('--api_key', required=True, help='Your API key.')
    parser.add_argument(
            '--command',
            default='list',
            help='Operation to perform (create-device, create-registry, '
                    'delete-device, delete-registry, get, list, patch-es256, '
                    'patch-rs256)')

    # Optional arguments
    parser.add_argument(
            '--ec_public_key_file',
            default=None,
            help='Path to public ES256 key file.')
    parser.add_argument(
            '--rsa_certificate_file',
            default=None,
            help='Path to RS256 certificate file.')
    parser.add_argument(
            '--cloud_region', default='us-central1', help='GCP cloud region')
    parser.add_argument(
            '--service_account_json',
            default='service_account.json',
            help='Path to service account json file.')
    parser.add_argument(
            '--registry_id',
            default=default_registry,
            help='Registry id. If not set, a name will be generated.')
    parser.add_argument(
            '--device_id',
            default=None,
            help='Device id.')

    return parser.parse_args()


def run_command(args):
    """Calls the program using the specified command."""
    if args.command == 'create-device':
        created = False
        if args.rsa_certificate_file is not None:
            create_rs256_device(
                    args.service_account_json, args.api_key, args.project_id,
                    args.cloud_region, args.registry_id, args.device_id,
                    args.rsa_certificate_file)
            created = True

        if args.ec_public_key_file is not None:
            create_es256_device(
                    args.service_account_json, args.api_key, args.project_id,
                    args.cloud_region, args.registry_id, args.device_id,
                    args.ec_public_key_file)
            created = True

        if not created:
            create_unauth_device(
                    args.service_account_json, args.api_key, args.project_id,
                    args.cloud_region, args.registry_id, args.device_id)

    elif args.command == 'create-topic':
        create_iot_topic(args.pubsub_topic)

    elif args.command == 'create-registry':
        open_registry(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.pubsub_topic, args.registry_id)

    elif args.command == 'delete-device':
        delete_device(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.registry_id, args.device_id)

    elif args.command == 'delete-registry':
        delete_registry(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.registry_id)

    elif args.command == 'get':
        get_device(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.registry_id, args.device_id)

    elif args.command == 'list':
        list_devices(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.registry_id)

    elif args.command == 'patch-es256':
        if (args.ec_public_key_file is None):
            sys.exit('Error: specify --ec_public_key_file')
        patch_es256_auth(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.registry_id, args.device_id,
                args.ec_public_key_file)

    elif args.command == 'patch-rs256':
        if (args.rsa_certificate_file is None):
            sys.exit('Error: specify --rsa_certificate_file')
        patch_rsa256_auth(
                args.service_account_json, args.api_key, args.project_id,
                args.cloud_region, args.registry_id, args.device_id,
                args.rsa_certificate_file)

    elif args.command is 'update-config':
        print('Update config')

    else:
        print(
                'Unrecognized command, must be one of: \n'
                '\tcreate-device, create-registry, delete-device, '
                'delete-registry, get, list, patch-es256, patch-rs256')


def main():
    args = parse_command_line_args()
    run_command(args)


if __name__ == '__main__':
    main()
