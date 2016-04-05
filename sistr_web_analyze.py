import os, re, json
import logging
from time import sleep
import requests
import sys
import argparse

from src.logger import init_console_logger
from src.config import BASE_SISTR_URL, TASK_POLL_SLEEP_TIME

PROG_DESC = '''
Python script for web analysis of genome by SISTR
=================================================
Analyze a genome with SISTR using the public REST API.
'''

parser = argparse.ArgumentParser(prog='sistr_web_analyze',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=PROG_DESC)

parser.add_argument('-i', '--input-fasta',
                    required=True,
                    type=argparse.FileType('rb'),
                    help='Input genome FASTA file')
parser.add_argument('-n', '--genome-name')
parser.add_argument('-f', '--output-format',
                    default='json',
                    help='Output format (json, pickle)')
parser.add_argument('-o', '--output-dest',
                    type=argparse.FileType('w'),
                    default=sys.stdout,
                    help='Output destination')
parser.add_argument('-u', '--sistr-user',
                    help='SISTR username (anonymous temporary user is created if no user specified; if registered user, password is also required)')
parser.add_argument('-p', '--sistr-password',
                    help='SISTR user password (required for registered users)')
parser.add_argument('--sistr-api-url',
                    help='SISTR base HTTP API URL (default=lfz.corefacility.ca/sistr-wtf/api/)')
parser.add_argument('-v', '--verbose',
                    action='count',
                    default=2,
                    help='Logging verbosity level (-v == show warnings; -vvv == show debug info)')


def create_new_temp_user():
    logging.info('Creating new anonymous user on SISTR server')
    r = requests.post(BASE_SISTR_URL + 'user/sistr')
    assert isinstance(r, requests.Response)
    if r.status_code == 201:
        user_info = r.json()
        username = user_info['name']
        logging.info('Created new user "{}"; role={}'.format(username, user_info['role']))
        logging.debug('User info: %s', user_info)
        return username, user_info
    else:
        err_msg = 'Unable to create new user on SISTR server; HTTP code={}; URL={}'.format(r.status_code,
                                                                                               r.url)
        logging.error(err_msg)
        raise Exception(err_msg)


def get_registered_user_info(username, password):
    """Get registered SISTR user info

    Args:
        username (str): User name
        password (str): Password
    """
    logging.info('Trying to get registered user info for "{}"'.format(username))
    r = requests.get('{}user/{}'.format(BASE_SISTR_URL, username),
                             auth=(username, password))
    assert isinstance(r, requests.Response)
    if r.status_code == 200:
        user_info = r.json()
        logging.info('Credentials valid for user "{}"'.format(username))
        logging.debug('User info: %s', user_info)
        return username, user_info
    elif r.status_code == 403:
        err_msg = 'Credentials invalid for user "{}"'.format(username)
        logging.error(err_msg)
        raise Exception(err_msg)
    else:
        err_msg = 'Unable to retrieve user info for "{}"; HTTP code={}; URL="{}"'.format(username,
                                                                                         r.status_code,
                                                                                         r.url)
        logging.error(err_msg)
        raise Exception(err_msg)


def get_temp_user_info(username):
    logging.info('Trying to get temporary user info for "{}"'.format(username))
    r = requests.get('{}user/{}'.format(BASE_SISTR_URL, username))
    assert isinstance(r, requests.Response)
    if r.status_code == 200:
        user_info = r.json()
        username = user_info['name']
        logging.info('Retrieved user info for user "{}"'.format(username))
        logging.debug('User info: %s', user_info)
        return username, user_info
    else:
        err_msg = 'Unable to retrieve user info for "{}"; HTTP code={}; URL="{}"'.format(username,
                                                                                         r.status_code,
                                                                                         r.url)
        logging.error(err_msg)
        raise Exception(err_msg)


def get_user_info(username, password):
    if username is None:
        return create_new_temp_user()
    else:
        if password is not None:
            return get_registered_user_info(username, password)
        else:
            return get_temp_user_info(username)


if __name__ == '__main__':
    args = parser.parse_args()
    init_console_logger(args.verbose)

    logging.debug('argparse args: %s', args)

    if args.sistr_api_url:
        logging.info('Using user specified SISTR base API URL %s', args.sistr_api_url)
        BASE_SISTR_URL = args.sistr_api_url

    input_fasta = args.input_fasta
    assert isinstance(input_fasta, file)
    input_fasta_path = input_fasta.name
    logging.debug('input_fasta name: %s', input_fasta_path)
    input_fasta_basename = os.path.basename(input_fasta_path)
    logging.debug('input_fasta_basename: %s', input_fasta_basename)
    genome_name = args.genome_name
    if not genome_name:
        fasta_filename_regex = r'(.*)\.f\w+'
        m = re.match(fasta_filename_regex, input_fasta_basename)
        if m:
            logging.debug('regex match groups: %s', m.groups())
            genome_name = m.group(1)
            logging.debug('Using regex "%s" match group 1 = "%s"', fasta_filename_regex, genome_name)
        else:
            genome_name = input_fasta_basename
            logging.warning('Could not extract fasta filename without extension. Using os.path.basename string as genome_name: %s', genome_name)
        logging.info('Genome name assumed to be "%s"', genome_name)
    else:
        logging.info('Genome name is "%s" as specified by user', genome_name)

    # TODO: registered user requests need Basic HTTP Auth preferably with SISTR provided auth token
    username, user_info = get_user_info(args.sistr_user, args.sistr_password)

    # Output data
    mist_results_json = None
    serovar_prediction_json = None
    sistr_genome_name = genome_name

    post_files = {'fasta': input_fasta}
    genome_post_resp = requests.post('{}user/{}/genome/{}'.format(BASE_SISTR_URL, username, genome_name), files=post_files)
    if genome_post_resp.status_code == 201:
        logging.debug('Successfully created genome resource and started genome analysis on SISTR server')
    else:
        logging.error('SISTR returned %s HTTP status code after genome POST!', genome_post_resp.status_code)
        # TODO: retry HTTP POST of genome fasta on certain HTTP codes
        exit(1)
    genome_post_json = genome_post_resp.json()
    sistr_genome_name = genome_post_json['genome']
    task_id = genome_post_json['task']

    # Poll genome analysis progress until either success or failure
    # TODO: genome analysis timeout? >5 min?
    while(True):
        logging.info('Waiting for %s seconds before polling SISTR for progress', TASK_POLL_SLEEP_TIME)
        sleep(TASK_POLL_SLEEP_TIME)
        logging.info('Waited %s seconds. Checking task %s status...', TASK_POLL_SLEEP_TIME, task_id)
        task_poll_resp = requests.get(BASE_SISTR_URL + 'task', params={'task_id': task_id})
        task_poll_json = task_poll_resp.json()
        # SISTR returns list of analysis task results since multiple task ids could be checked at the same time
        # get first analysis task progress result
        task_info = task_poll_json[0]
        logging.debug('Task info: %s', task_info)
        task_status = task_info['status']
        if task_status == 'SUCCESS':
            logging.info('Genome analysis successfully completed. Retrieving results')
            break
        elif task_status == 'FAILED':
            logging.error('Genome analysis FAILED! SISTR gave the following info: %s', task_info['result'])
            logging.error('Task info: %s', task_info)
            # TODO: retry on genome analysis failure?
            exit(1)
        elif task_status == 'PROGRESS':
            logging.info('SISTR genome analysis progress %s percent: %s', task_info['info']['progress'], task_info['info']['desc'])

    logging.info('Getting serovar prediction results for genome "%s"', genome_name)
    serovar_prediction_resp = requests.get('{}user/{}/genome/{}/serovar_prediction'.format(BASE_SISTR_URL, username, sistr_genome_name))
    serovar_prediction_json = serovar_prediction_resp.json()

    logging.debug('Serovar prediction results: %s', serovar_prediction_json)
    logging.info('Serovar prediction = "%s"', serovar_prediction_json['serovar_prediction'])

    mist_results_resp = requests.get('{}user/{}/genome/{}/mist_results'.format(BASE_SISTR_URL, username, sistr_genome_name))
    mist_results_json = mist_results_resp.json()

    logging.debug('In silico typing results: %s', mist_results_json)
    logging.info('Retrieved in silico typing results: %s', mist_results_json['test_results'])

    output_dest = args.output_dest
    assert isinstance(output_dest, file)

    out = {'in_silico_typing': mist_results_json,
           'serovar_prediction': serovar_prediction_json,
           'sistr_api_url': BASE_SISTR_URL,
           'sistr_user_info':  user_info,
           'sistr_genome_name': sistr_genome_name,
           'genome_fasta_path': input_fasta_path,
           }

    logging.info('Writing "%s" output to %s', args.output_format, output_dest)
    if args.output_format == 'json':
        json.dump(out, output_dest)
    elif args.output_format == 'pickle':
        import cPickle
        cPickle.dump(out, output_dest)
