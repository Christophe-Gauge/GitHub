#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

__author__ = "Christophe Gauge"
__version__ = "1.0.4"

'''
Backup HAproxy and nginx configuration files.
'''


# I M P O R T S ###############################################################


import github
import os
import sys
import time
import io
import logging
import traceback
import hashlib
import rsa_crypto
import argparse
import socket
import getpass
import base64
if (sys.version_info > (3, 0)):
    from urllib.parse import urljoin
else:
    from urlparse import urljoin


# G L O B A L S ###############################################################

file_list = ['/tmp/test.txt', '/etc/haproxy/haproxy.cfg', '/etc/nginx/nginx.conf']

# # Uncomment if you are using your own internal GitHub Repository
# ghe_organization = 'my_ghe_repo'
# ghe_hostname = mydomain.com

ghe_repo = 'Christophe-Gauge/GitHub'
remote_base_path = ''

ghe_branch = 'main'

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO)
logger.info("Path:    %s" % (os.path.realpath(__file__)))
logger.info("Version:  %s" % (__version__))

args = argparse.Namespace(option='ghe_token')
ghe_token = rsa_crypto.decrypt_value(args)


# C O D E #####################################################################


def main():
    """Main function."""
    global logger
    global repo
    global args

    # Get the server name to use as a directory in GitHub
    server_name = socket.gethostname().split('.')[0].lower()
    # Get the username to log who made the change, nobody will be a Cron task or such
    try:
        user_name = getpass.getuser()
    except Exception as e:
        user_name = None
    if user_name is None:
        try:
            user_name = os.getlogin()
        except OSError as e:
            user_name = 'nobody'
        except Exception as e:
            user_name = 'unknown'

    gh = github.Github(login_or_token=ghe_token)
    repo = gh.get_repo(ghe_repo)

    # # Uncomment if you are using your own internal GitHub Repository
    # gh = github.Github(base_url=f"https://{ghe_hostname}/api/v3", login_or_token=ghe_token)
    # org = gh.get_organization(ghe_organization)
    # repo = org.get_repo(ghe_repo)

    for local_file_name in file_list:
        file_content = ''
        if os.path.exists(local_file_name):
            logger.info('File %s exists, processing.' % local_file_name)
            # Redacting HAproxy auth passwords, more may be needed for your use-case
            with io.open(local_file_name, "r", encoding="utf-8") as f:
                for line in f:
                    if 'auth' in line:
                        file_content += line[:line.find('auth')] + 'auth <REMOVED>\n'
                    else:
                        file_content += line
            # print(file_content)

            data = file_content.encode('utf-8', 'ignore')
            filesize = len(data)
            content = "blob " + str(filesize) + "\0" + data.decode('utf-8')
            encoded_content = content.encode('utf-8')
            localSHA = hashlib.sha1(encoded_content).hexdigest()

            remote_file_name = urljoin(remote_base_path, server_name + '/' + os.path.basename(local_file_name))
            logger.info(f"Saving local file {local_file_name} to remote GitHub repo {repo.full_name} file {remote_file_name}")

            try:
                remoteSHA = repo.get_contents(remote_file_name, ref=ghe_branch).sha
            except github.UnknownObjectException as e:
                logger.error(f"Remote file not found {remote_file_name}")
                remoteSHA = None
            except Exception as e:
                logger.error("Error {0}".format(str(e)))
                logger.error(traceback.format_exc())
                remoteSHA = None

            if remoteSHA == localSHA:
                logger.info('Remote file is present, hash is the same, NOT updating.')
                continue
            else:
                try:
                    if remoteSHA is None:
                        logger.info('Remote file file is NOT present, creating new file')
                        repo.create_file(remote_file_name, f"Updated by {user_name}", data, branch=ghe_branch)
                    else:
                        logger.info('Remote file file is present but hash has changed, updating file')
                        repo.update_file(remote_file_name, f"Updated by {user_name}", data, remoteSHA, branch=ghe_branch)

                except Exception as e:
                    logger.error("Error {0}".format(str(e)))
                    logger.error(traceback.format_exc())
                logger.info('Done updating GitHub')

        else:
            logger.warning('File does not exist %s' % local_file_name)

    logger.info('*** DONE ***')
    sys.exit(0)

###############################################################################


if __name__ == "__main__":
    main()

# E N D   O F   F I L E #######################################################
