#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

__author__ = "Christopge Gauge"
__version__ = "1.0.2"


'''

Install and configure the server management scripts and other supporting scripts.

'''


# I M P O R T S ###############################################################

import os
import sys
import logging
import traceback
import base64
import github
import yaml
import hashlib
import rsa_crypto
import argparse

if (sys.version_info > (3, 0)):
    from urllib.parse import urljoin
else:
    from urlparse import urljoin


# G L O B A L S ###############################################################

# # Uncomment if you are using your own internal GitHub Repository
# ghe_organization = 'my_ghe_repo'
# ghe_hostname = mydomain.com

ghe_repo = 'Christophe-Gauge/GitHub'
remote_base_path = '/'
local_base_path = '/opt/scripts'
remote_config_file = 'update_scripts.yaml'
ghe_branch = 'main'

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO)
logger.info("Path:    %s" % (os.path.realpath(__file__)))
logger.info("Version:  %s" % (__version__))

args = argparse.Namespace(option='ghe_token')
ghe_token = rsa_crypto.decrypt_value(args)


# C O D E #####################################################################

def get_ghe(remote_file, repo, always_update):
    """Get a file from GHE and save it locally"""
    my_file_name = os.path.basename(remote_file)
    remote_file_name = urljoin(remote_base_path, remote_file)
    local_file_name = os.path.join(local_base_path, my_file_name)
    logger.info("Retrieving remote GHE file %s%s to %s" % (repo.full_name, remote_file_name, local_file_name))

    try:
        remoteSHA = repo.get_contents(remote_file_name, ref=ghe_branch).sha
    except github.UnknownObjectException as e:
        logger.error(f"Remote file not found {remote_file_name}")
        return
    except Exception as e:
        logger.error("Error {0}".format(str(e)))
        logger.error(traceback.format_exc())
        return

    # If the file exists then let's get the hash to see if an update is needed
    if os.path.exists(local_file_name):
        # Compute the SHA1 hash of the local file
        with open(local_file_name, 'rb') as file_for_hash:
            data = file_for_hash.read()
        filesize = len(data)
        content = "blob " + str(filesize) + "\0" + data.decode('utf-8')
        encoded_content = content.encode('utf-8')
        localSHA = hashlib.sha1(encoded_content).hexdigest()
        if remoteSHA == localSHA:
            logger.info('File is present, hash is the same, we already have the latest file, NOT updating.')
            return
        else:
            logger.info('File is present, hash is different %s - %s' % (remoteSHA, localSHA))
    else:
        # This flag indicates that a file should only be updated if it already exists
        if not always_update:
            logger.info('File is not present NOT updating')
            return
    try:
        file_contents = repo.get_contents(remote_file_name, ref=ghe_branch)
        local_file_content = str(base64.b64decode(file_contents.content).decode('utf-8', 'ignore'))

        # Write the new file to disk
        with open(local_file_name, "w") as text_file:
            text_file.write(local_file_content)
        if my_file_name.endswith('.py'):
            os.chmod(local_file_name, 0o700)
        else:
            os.chmod(local_file_name, 0o400)
        logger.info('File was updated')

    except Exception as e:
        logger.error("Error {0}".format(str(e)))
        logger.error(traceback.format_exc())

def main():
    """Main function."""

    gh = github.Github(login_or_token=ghe_token)
    repo = gh.get_repo(ghe_repo)

    # # Uncomment if you are using your own internal GitHub Repository
    # gh = github.Github(base_url=f"https://{ghe_hostname}/api/v3", login_or_token=ghe_token)
    # org = gh.get_organization(ghe_organization)
    # repo = org.get_repo(ghe_repo)

    if not os.path.exists(local_base_path):
        os.makedirs(local_base_path)

    remote_file_name = urljoin(remote_base_path, remote_config_file)
    logger.info("Retrieving remote GHE file %s%s" % (repo.full_name, remote_file_name))

    try:
        file_contents = repo.get_contents(remote_file_name, ref=ghe_branch)
        text_contents = str(base64.b64decode(file_contents.content).decode('utf-8', 'ignore'))
        file_list = yaml.load(text_contents, Loader=yaml.SafeLoader)
        logger.info(yaml.safe_dump(file_list, default_flow_style=False))
    except Exception as e:
        if e.args[0] == 404:
            logger.error(f"Remote file not found {remote_file_name}")
            sys.exit(1)
        else:
            logger.error("Error {0}".format(str(e)))
            logger.error(traceback.format_exc())
            sys.exit(1)

    for file in file_list['update_always']:
        logger.info(file)
        get_ghe(file, repo, True)

    for file in file_list['update_if_present']:
        logger.info(file)
        get_ghe(file, repo, False)

    for file in file_list['remove']:
        if os.path.exists(file):
            os.remove(file)
            logger.info('File %s was deleted' % file)

    sys.exit(0)

###############################################################################


if __name__ == "__main__":
    main()

# E N D   O F   F I L E #######################################################
