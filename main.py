#########################
# Name:
#     main.py
# 
# Description:
#     TODO
#     NOTE: You will need to create a GitHub Personal Access Token
#           Which will also need full repo access and then read access in other settings
#     NOTE: The very first time you run this with a PAT token you will need to hit a url
#           and let it allow SSO SAML access via the token
#
# Parameters
#     -u, --username = GitHub user name
#     -t, --token = GitHub Personal Access Token (PAT)
#     -o, --organisation = Organisaton to use, defaults to nationwide-building-society
#     -g, --gitprovider = Git Provider to use, defaults to github.com
#
# Usage:
#         python3 main.py -u <MY_GITHUB_USER> -t <MY_PAT_TOKEN>
#
# Notes:
#
#########################

import os
import sys
import fnmatch
import codecs
import git
#from git import Repo
import csv
from github import Github
from github import Auth
import logging
import datetime
import argparse
import json
import re
import os
import fileinput
import string

COMMIT_MESSAGE="Update docker compose to use new LZ registry"
PR_TITLE="Update docker compose to use new LZ registry"
BRANCH_NAME="CCOE-LZ-MIGRATION"
PR_BODY="""
As per Artifactory migration, updating all docker image pulls to point to new LZ registry.

Please check the changed files carefully as this was an automated replace of **ccoe-docker-rel-local** for **lz-docker-rel-local**.

Please confirm branch build succeeds to the extent as expected, and containers are pulled from lz-docker-rel-local before approving. If there are no changes this PR can be discarded.

If there are authentication issues present, please ensure buildkite authentication is enabled for the queue, as per:

https://nbs-enterprise.atlassian.net/wiki/spaces/ACPCM/pages/851812835/Buildkite+Artifactory+Authentication+-+Implementation+Usage+Enablement

Any issues or questions please reach out to the Amigos team.
"""


class RepoSearch:

    current_datetime = None                 # date/time of execution - used for the log and reporting filenames
    logfile_final_name = None               # Completed with the current date/time appended
    current_path = None                     # Where this code exists locally
    local_repo_path = None                  # Path to folder that is created to hold the cloned repositories to search on

    def __init__(self, options=None):
        self.current_datetime = datetime.datetime.now().strftime("%d-%m-%Y-%H%M")
        self.logfile_final_name = f"logging-reposearch-{self.current_datetime}.log"
        # Sets up normal file logging (DEBUG) and add additional logging formatting
        logging.basicConfig(filename=self.logfile_final_name,level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s: %(message)s')

        # If used then these should be sanitised/restricted before being used
        self.options = options


    def output_logging(self):
        """
        Add an additional (INFO) logger (to the file logger) to also output information to the screen. Intended for terminal, AWS Lambda functions or similar.
        :return:
        """
        root_logger = logging.getLogger()
        output_logger = logging.StreamHandler(sys.stdout)
        output_logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        output_logger.setFormatter(formatter)
        root_logger.addHandler(output_logger)


    def run(self):
        self.configure()
        try:
            self.clone_repos(self.get_lz_repo_list())
        except Exception as e:
            print(e)
            raise


    def configure(self):
        """
        Pull in the command line args
        """
        parser = argparse.ArgumentParser()
        parser.add_argument("-u", "--username", help="Username for account", required=True)
        parser.add_argument("-t", "--token", help="Personal Access Token (readonly)", required=True)
        parser.add_argument("-o", "--organisation", help="Git Organisation to query", nargs="?", default="nationwide-building-society")
        parser.add_argument("-g", "--gitprovider", help="Git Provider", nargs="?", default="github.com")
        args = parser.parse_args()
        logging.info(args)
        self.username = args.username
        self.token = args.token
        self.organisation = args.organisation
        self.gitprovider = args.gitprovider

        self.configure_repo_folder()


    def configure_repo_folder(self):
        # organise local paths
        self.current_path = os.getcwd()
        repo_folder = 'lz_repos'
        self.local_repo_path = os.path.join(self.current_path, repo_folder)
        REPO_FOLDER_CHECK = os.path.isdir(self.local_repo_path)
        if not REPO_FOLDER_CHECK:
            os.makedirs(self.local_repo_path)

    def get_organisation_repo_list(self):
        """
        TODO: Query for all Git repositories under this organisation
        - Define github.com
        - Use self.organisation (defaults to nationwide-building-society)
        """
        return []


    def get_lz_repo_list(self):
        """
        Holds  alist of currently identified core Cloud Hosting repositories
        """
        # Full_list=["ansible-nbs-lz-base", "horizon-elasticsearch-deployments", "horizon-logstash-module", "nbs-buildkite-terraform", "nbs-ctdf", "nbs-ecs-lambda", "nbs-eks", "nbs-example-terraform",
        #            "nbs-github-terraform", "nbs-helm-charts", "nbs-horizon", "nbs-k8s-deployments", "nbs-luminate-policies", "nbs-lz", "nbs-lz-account-vendor", "nbs-lz-ami-aws-inspector-report", 
        #            "nbs-lz-ami-bakery", "nbs-lz-ami-bakery-aws-linux", "nbs-lz-ami-bakery-vtm", "nbs-lz-ami-bakery-windows", "nbs-lz-ami-cleanup", "nbs-lz-ami-compliance", "nbs-lz-ami-notify", 
        #            "nbs-lz-ami-report", "nbs-lz-ansible-rhel8-base", "nbs-lz-aws-test", "nbs-lz-bk-autoscaler", "nbs-lz-bucket-emptier", "nbs-lz-buildkite-autoscaler", "nbs-lz-client-vpn", "nbs-lz-codepipeline", 
        #            "nbs-lz-compliance-reporter", "nbs-lz-config-sechub-integration-lambda", "nbs-lz-container-bakery", "nbs-lz-container-bakery-2.0", "nbs-lz-container-bakery-move", "nbs-lz-cpu-credit-checker", 
        #            "nbs-lz-cwlog-processor", "nbs-lz-east-west-palofirewalls", "nbs-lz-east-west-palofirewalls-config", "nbs-lz-ec2-scheduler", "nbs-lz-ecr", "nbs-lz-egress-allowlist", "nbs-lz-egress-config", 
        #            "nbs-lz-egress-failover", "nbs-lz-egress-palofirewalls", "nbs-lz-egress-palofirewalls-config", "nbs-lz-eks-ami-patching", "nbs-lz-eks-ami-update-status", "nbs-lz-eks-ssm-ami", 
        #            "nbs-lz-endpoint-monitor", "nbs-lz-epaas-eks", "nbs-lz-epaas-eks-apps", "nbs-lz-es-shipper", "nbs-lz-f5", "nbs-lz-f5-config", "nbs-lz-ft-extended-bk-permissions", "nbs-lz-github-alerts", 
        #            "nbs-lz-github-authorizer", "nbs-lz-global-protect-palofirewalls", "nbs-lz-global-protect-palofirewalls-config", "nbs-lz-globalprotect", "nbs-lz-globalprotect-config", 
        #            "nbs-lz-globalprotect-user-counter", "nbs-lz-ingress-avi", "nbs-lz-ip-space-checker", "nbs-lz-ipam", "nbs-lz-lambda-bakery", "nbs-lz-lambda-python-twistlock-layer", "nbs-lz-log-receiver", 
        #            "nbs-lz-log-shipper", "nbs-lz-nacl-analyser", "nbs-lz-networking-dev", "nbs-lz-panorama", "nbs-lz-panorama-config", "nbs-lz-phd-event-handler", "nbs-lz-pocs", "nbs-lz-rds-scheduler", 
        #            "nbs-lz-rhel-upgrade", "nbs-lz-sandbox", "nbs-lz-sechub-extract", "nbs-lz-sechub-workflow-lambda", "nbs-lz-secrets-report", "nbs-lz-service-policy-reporting", "nbs-lz-splunk-sorter", 
        #            "nbs-lz-spoke-blueprints", "nbs-lz-suppress-resource-sechub-findings", "nbs-lz-tag-verifier", "nbs-lz-tagging-non-compliance-reporter", "nbs-lz-tdp-1", "nbs-lz-tdp-2", "nbs-lz-test-repo", 
        #            "nbs-lz-thousandeyes", "nbs-lz-tooling-roles", "nbs-splunk-sechub-input", "nbs-splunk-terraform", "nbs-vault-policies", "terraform-aws-eks", "actions-checkout", 
        #            "ansible-role-nbs-luminate-ssh-ca", "nbs-aad-registration", "nbs-ansible-cloudwatch-agent", "nbs-cloudad-infra", "nbs-finops", "nbs-pre-commit", "nbs-terraform-modules", "nbs-twistlock-config", 
        #            "nbs-windows-ami-packer", "terraform-aws-elasticsearch", "terraform-compliance", "nbs-buildkite-terraform-provider", "nbs-compliance-dashboard", "nbs-eks-lambda", "nbs-eks-twistlock", 
        #            "nbs-forensics-cado", "nbs-prismacloud-saas", "nbs-rbac-edbhub", "nbs-rbac-shared-default", "nbs-secops-utils", "nbs-splunk-ansible", "nbs-splunk-cluster-master", "nbs-splunk-deployer", 
        #            "nbs-splunk-deployment-server", "nbs-splunk-saas-apps", "nbs-twistlock-aws", "nbs-twistlock-deployment-examples", "nbs-twistlock-epaas", "nbs-twistlock-saas", "nbs-vectr-aws"]
        
        # Full_list_to_split=["ansible-nbs-lz-base", "nbs-buildkite-terraform", "nbs-ctdf", "nbs-ecs-lambda", "nbs-eks", "nbs-example-terraform",
        #            "nbs-luminate-policies", "nbs-lz", "nbs-lz-account-vendor", "nbs-lz-ami-aws-inspector-report", 
        #            "nbs-lz-ami-bakery", "nbs-lz-ami-bakery-aws-linux", "nbs-lz-ami-bakery-vtm", "nbs-lz-ami-bakery-windows", "nbs-lz-ami-cleanup", "nbs-lz-ami-compliance", "nbs-lz-ami-notify", 
        #            "nbs-lz-ami-report", "nbs-lz-ansible-rhel8-base", "nbs-lz-aws-test", "nbs-lz-bk-autoscaler", "nbs-lz-bucket-emptier", "nbs-lz-buildkite-autoscaler", "nbs-lz-client-vpn", "nbs-lz-codepipeline", 
        #            "nbs-lz-compliance-reporter", "nbs-lz-config-sechub-integration-lambda", "nbs-lz-container-bakery", "nbs-lz-cpu-credit-checker", 
        #            "nbs-lz-cwlog-processor", "nbs-lz-ec2-scheduler", "nbs-lz-ecr", "nbs-lz-eks-ami-patching", "nbs-lz-eks-ami-update-status", "nbs-lz-eks-ssm-ami", 
        #            "nbs-lz-endpoint-monitor", "nbs-lz-es-shipper", "nbs-lz-f5", "nbs-lz-f5-config", "nbs-lz-ft-extended-bk-permissions", "nbs-lz-github-alerts", 
        #            "nbs-lz-github-authorizer", "nbs-lz-ingress-avi", "nbs-lz-ip-space-checker", "nbs-lz-lambda-bakery", "nbs-lz-log-receiver", 
        #            "nbs-lz-log-shipper", "nbs-lz-phd-event-handler", "nbs-lz-pocs", "nbs-lz-rds-scheduler", 
        #            "nbs-lz-rhel-upgrade", "nbs-lz-sandbox", "nbs-lz-sechub-extract", "nbs-lz-sechub-workflow-lambda", "nbs-lz-secrets-report", "nbs-lz-service-policy-reporting", "nbs-lz-splunk-sorter", 
        #            "nbs-lz-spoke-blueprints", "nbs-lz-suppress-resource-sechub-findings", "nbs-lz-tag-verifier", "nbs-lz-tagging-non-compliance-reporter", "nbs-lz-tdp-1", "nbs-lz-tdp-2", "nbs-lz-test-repo", 
        #            "nbs-lz-thousandeyes", "nbs-lz-tooling-roles", "nbs-splunk-sechub-input", "nbs-splunk-terraform", "nbs-vault-policies", "terraform-aws-eks", "actions-checkout", 
        #            "ansible-role-nbs-luminate-ssh-ca", "nbs-aad-registration", "nbs-ansible-cloudwatch-agent", "nbs-cloudad-infra", "nbs-finops", "nbs-pre-commit", "nbs-terraform-modules", 
        #            "nbs-windows-ami-packer", "terraform-aws-elasticsearch", "terraform-compliance", "nbs-buildkite-terraform-provider"]

        quokka = ["nbs-lz-egress-allowlist", "nbs-lz-egress-config", "nbs-lz-egress-failover", "nbs-lz-egress-palofirewalls", "nbs-lz-egress-palofirewalls-config", "nbs-lz-epaas-eks", 
                    "nbs-lz-epaas-eks-apps", "nbs-lz-global-protect-palofirewalls", "nbs-lz-global-protect-palofirewalls-config", "nbs-lz-globalprotect", "nbs-lz-globalprotect-config", 
                    "nbs-lz-globalprotect-user-counter", "nbs-lz-ipam", "nbs-lz-east-west-palofirewalls", "nbs-lz-east-west-palofirewalls-config", "nbs-k8s-deployments", "nbs-lz-nacl-analyser", 
                    "nbs-lz-networking-dev", "nbs-lz-panorama", "nbs-lz-panorama-config",'nbs-lz-thousandeyes' ]

        rokku = ["nbs-helm-charts", "nbs-eks-lambda", "nbs-eks-twistlock", "nbs-forensics-cado", "nbs-prismacloud-saas", "nbs-rbac-edbhub", "nbs-rbac-shared-default", "nbs-secops-utils", 
                 "nbs-splunk-ansible", "nbs-splunk-cluster-master", "nbs-splunk-deployer", "nbs-splunk-deployment-server", "nbs-splunk-saas-apps", "nbs-twistlock-aws", "nbs-twistlock-deployment-examples", 
                 "nbs-twistlock-epaas", "nbs-twistlock-saas", "nbs-vectr-aws", "nbs-compliance-dashboard", "nbs-twistlock-config", "nbs-lz-lambda-python-twistlock-layer", 'nbs-splunk-terraform']

        lz = [   [   'ansible-nbs-lz-base',
        'nbs-buildkite-terraform',
        'nbs-ctdf',
        'nbs-ecs-lambda',
        'nbs-eks',
        'nbs-example-terraform',
        'nbs-lz',
        'nbs-lz-account-vendor',
        'nbs-lz-ami-aws-inspector-report'],
    [   'nbs-lz-ami-bakery',
        'nbs-lz-ami-bakery-vtm',
        'nbs-lz-ami-bakery-windows',
        'nbs-lz-ami-cleanup',
        'nbs-lz-ami-compliance',
        'nbs-lz-ami-notify',
        'nbs-lz-ami-report',
        'nbs-lz-ansible-rhel8-base',
        'nbs-lz-aws-test'],
    [   'nbs-lz-bucket-emptier',
        'nbs-lz-compliance-reporter',
        'nbs-lz-config-sechub-integration-lambda',
        'nbs-lz-container-bakery',
        'nbs-lz-cpu-credit-checker',
        'nbs-lz-cwlog-processor'],
    [   'nbs-lz-ec2-scheduler',
        'nbs-lz-ecr',
        'nbs-lz-eks-ami-patching',
        'nbs-lz-eks-ami-update-status',
        'nbs-lz-eks-ssm-ami',
        'nbs-lz-endpoint-monitor',
        'nbs-lz-es-shipper',
        'nbs-lz-ft-extended-bk-permissions'],
    [   'nbs-lz-github-alerts',
        'nbs-lz-github-authorizer',
        'nbs-lz-ip-space-checker',
        'nbs-lz-lambda-bakery',
        'nbs-lz-log-receiver',
        'nbs-lz-log-shipper',
        'nbs-lz-phd-event-handler',
        'nbs-lz-rds-scheduler'],
    [   'nbs-lz-rhel-upgrade',
        'nbs-lz-sandbox',
        'nbs-lz-sechub-extract',
        'nbs-lz-sechub-workflow-lambda',
        'nbs-lz-secrets-report',
        'nbs-lz-service-policy-reporting',
        'nbs-lz-splunk-sorter',
        'nbs-lz-suppress-resource-sechub-findings',
        'nbs-lz-tag-verifier'],
    [   'nbs-lz-tagging-non-compliance-reporter',
        'nbs-lz-test-repo'
        'nbs-lz-tooling-roles',
        'nbs-splunk-sechub-input',
        'terraform-aws-eks'],
    [   'actions-checkout',
        'ansible-role-nbs-luminate-ssh-ca',
        'nbs-ansible-cloudwatch-agent',
        'nbs-cloudad-infra',
        'nbs-finops',
        'nbs-terraform-modules',
        'terraform-aws-elasticsearch'],
    ['terraform-compliance', 'nbs-buildkite-terraform-provider']]

        return lz[1]
        
  

    def is_binary(self, filename):
        with open(filename, 'rb') as file:
            try:
                file_contents = file.read()
                if b'\0' in file_contents:
                    return True
                else:
                    # Check for non-printable characters
                    is_printable = all(char in string.printable for char in file_contents.decode())
                    return not is_printable
            except UnicodeDecodeError:
                return True
            
    def replace_string_in_files(self, directory, old_string, new_string):
        """
        Iterates through each file recursively in a directory, exlcuding the .git directory
        First confirms the file is not a binary file.
        Replaces any instance of old_string with new_string
        Returns True if changes were made, False if there were no changes
        """
        updates = False
        for dirpath, dirnames, filenames in os.walk(directory):
            # skip the git directory
            if ".git" in dirpath:
                 continue
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                # check if file is binary and skip if so
                if self.is_binary(filepath):
                    logging.info(f'BINARY FOUND FILE, SKIPPING: {filepath}')
                    continue
                # inefficient, but first check if text is in file, before reading and replacing instead of rewriting all files
                with open(filepath) as file:
                    if old_string in file.read():
                        # Read and re-write every line as there is a replacement required
                        with fileinput.FileInput(filepath, inplace=True) as file:
                            for line in file:
                                newline = line.replace(old_string, new_string)
                                if newline != line:
                                    logging.info(f"FILE UPDATED: {filename}")
                                    logging.info(f"OLD LINE: {line}")
                                    logging.info(f"NEW LINE: {newline}")
                                    updates = True
                                print(newline, end='')   
        return updates
    def set_primary_head(self, repo_path):
        """
        checks avaiable heads, uses main if available, else master
        """
        names = list(map(lambda head: head.name, git.Repo(repo_path).heads))

        if "main" in names:
            return "main"
        else:
            return "master"


    def clone_repos(self, repos_name):
        """
        Iterates over the list of repositories and clones them locally
        """

        repo_base_path = f"https://{self.username}:{self.token}@{self.gitprovider}/{self.organisation}"
        #print(repo_base_path)

        for repo in repos_name:
            repo_path = os.path.join(self.local_repo_path,repo)

            CHECK_FOLDER = os.path.isdir(repo_path)
            if not CHECK_FOLDER:
                os.makedirs(repo_path)
                remote_url = f"{repo_base_path}/{repo}.git"
                logging.info(f"CLONING: {remote_url}")
                git.Repo.clone_from(remote_url, repo_path)
                primary_head = self.set_primary_head(repo_path)         
            else:
                os.chdir(repo_path)
                primary_head = self.set_primary_head(repo_path)
                logging.info(f"REPO ALREADY EXISTS, PULLING LATEST: {repo_path}")
                git.Repo(repo_path).git.pull('origin', primary_head)
                os.chdir("../..")
            
            logging.info(f"CREATING BRANCH AND CHECKOUT: {BRANCH_NAME}")
            current = git.Repo(repo_path).create_head(BRANCH_NAME)
            current.checkout()
            logging.info(f"UPDATING FILES IN PATH: {repo_path}")

            changes = self.replace_string_in_files(repo_path, 'ccoe-docker-rel-local', 'lz-docker-rel-local')
            #Only commit and raise a pr if there are changes.
            if changes:
                logging.info("COMMITTING..")
                git.Repo(repo_path).git.add(update=True)
                git.Repo(repo_path).index.commit(COMMIT_MESSAGE)
                git.Repo(repo_path).git.push('origin', BRANCH_NAME)
                auth = Auth.Token(self.token)
                gh = Github(auth=auth)
                body = PR_BODY
                ghurl= gh.get_repo(f"{self.organisation}/{repo}")
                logging.info(f"CREATING PR: {PR_TITLE}")
                pr = ghurl.create_pull(title=PR_TITLE, body=body, head=BRANCH_NAME, base=primary_head)
                print(f"https://{self.gitprovider}/{self.organisation}/{repo}/pull/{pr.number}")           
                logging.info(f"CREATED PR: https://{self.gitprovider}/{self.organisation}/{repo}/pull/{pr.number}")
            else:
                logging.info(f"NO CHANGES MADE FOR REPO: {repo}")
                print(f"NO CHANGES MADE FOR REPO: {repo}")
if __name__ == "__main__":
    #try:
    report = RepoSearch()
    report.run()
    #except Exception as e:
    #    print("EXCEPTION ENCOUNTERED:")
    #    print(e)
    #    sys.exit(1)