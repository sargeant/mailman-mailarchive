# Copyright 2008-2017 Henrik Levkowetz
# Copyright 2008-2023 by the Free Software Foundation, Inc.
# Copyright 2023-2024 by Stephen J. Turnbull
#
# This file is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This file is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# GNU Mailman.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Stephen J. Turnbull <stephen.turnbull@siriusopensource.com>

# This file is derived in part from mailman-hyperkitty and postconfirm.
# https://gitlab.com/mailman/mailman-hyperkitty
# Author: Aurelien Bompard <abompard@fedoraproject.org>
# https://github.com/ietf-tools/postconfirm
# Author: Henrik Levkowetz <henrik@merlot.tools.ietf.org>


"""Mailman 3 IArchiver for IETF Mail Archive."""

import logging
import traceback
from base64 import b64encode, urlsafe_b64encode
from email.utils import make_msgid
from hashlib import sha1
from io import StringIO
from os.path import join as pathjoin
from urllib.parse import urljoin

from mailman.config import config
from mailman.config.config import external_configuration
from mailman.core.switchboard import Switchboard
from mailman.interfaces.archiver import IArchiver
from public import public
from requests import post
from requests.exceptions import RequestException
from zope.interface import implementer

log = logging.getLogger('mailman.archiver')


def _log_exception(exc):
    log.error('Exception in the IETF archiver: %s', exc)
    s = StringIO()
    traceback.print_exc(file=s)
    log.error('%s', s.getvalue())


class _MockRunStatus:
    """Emulate subprocess.CompletedProcess for HTTP responses."""

    def __init__(self, HTTP_status, stdout, stderr):
        self.returncode = 0 if HTTP_status == 201 else HTTP_status
        self.stdout = stdout
        self.stderr = stderr
        self.args = ["HTTP", "POST"]


@public
@implementer(IArchiver)
class IETFMailarchive:
    """
    Mailman 3 IArchiver for IETF Mail Archive.
    """

    name = 'ietf_mailarchive'
    is_enabled = False

    def __init__(self):
        archiver_config = external_configuration(
            config.archiver.ietf_mailarchive.configuration)
        # In theory configuration could change on the fly, but there's no API
        # to notify us.  So we don't bother with a _load_configuration method.
        self.api = archiver_config.get('general', 'api')
        self.api_key = archiver_config.get('general', 'api_key')
        self.base_url = archiver_config.get('general', 'base_url')
        if not self.base_url.endswith('/'):
            self.base_url += '/'
        self.command = archiver_config.get('general', 'command')
        self.destination = archiver_config.get('general', 'destination')
        queue_dir = pathjoin(config.ARCHIVE_DIR, self.name, 'spool')
        self._switchboard = Switchboard(self.name, queue_dir, recover=False)

    def list_url(self, mlist):
        """
        Returns the URL for the archive index of mlist.

        :param mlist: The IMailingList object.
        :returns: The url string.
        """
        return urljoin(self.base_url, pathjoin("browse", mlist.list_name))

    def permalink(self, mlist, msg):
        """
        Calculate the URL for the archived message.

        :param mlist: The IMailingList object.
        :param msg: The message object.
        :returns: The url string, or None on failure.
        """
        
        # Not necessarily a hash of the only the Message-Id
        message_id_hash = self._make_hash(mlist, msg)
        if message_id_hash is None:
            return None
        url = urljoin(self.base_url,
                      pathjoin("msg", mlist.list_name, message_id_hash))
        return url

    def archive_message(self, mlist, msg):
        """
        Send the message to the archiver, but process the queue first if it
        contains any held messages.

        :param mlist: The IMailingList object.
        :param msg: The message object.
        :returns: The url string or None if the message's archive url cannot
            be calculated.
        """

        self._process_queue()
        self._archive_message(mlist, msg)
        return self.permalink(mlist, msg)

    ## Private attributes: implementation of archive_message

    process_errfmt = "{cmd}: returned {code} for {msg_id}"
    policy_errfmt = \
        "{list_name} archive policy {policy} not 'public' or 'private'"

    # Partly based on mailman_hyperkitty:_send_message() and _archive_message()
    def _archive_message(self, mlist, msg, stem=None):
        """Send the message to the archiver.
        If an exception occurs when flattening msg, send it to the bad queue
        If an exception occurs otherwise, queue the message for later retry.

        :param mlist: The IMailingList object.
        :param msg: The message object.
        :param stem: If the message already comes from the retry queue, set
            stem to the stem of the queuefile name.  It will be removed on
            success, or stored for analysis on error.
        :returns: The url string.
        """

        try:
            message_id = self._get_message_id(msg)
            message_text = msg.as_bytes()
        except Exception as error:
            # if either failed, the message cannot be archived
            log.exception(
                'Could not render the message with id %s to text: %s',
                message_id, exc_info=error)
            # send it to the bad queue
            try:
                if stem is None:
                    stem = self._switchboard.enqueue(msg, mlist=mlist)
                self._switchboard.finish(stem, preserve=True)
            except Exception as error:
                # This would be some kind of insufficient resource.
                # I think we're stuck because we don't have the original queue
                # file -- that would require changing the runner code.  We just
                # have to drop it on the floor.
                log.exception(
                    'Failed to preserve the message with id %s: %s',
                    message_id or 'unknown', exc_info=error)
                if stem is not None:
                    self._switchboard.finish(stem)
            return None

        list_name = mlist.list_name
        policy = mlist.archive_policy.name
        try:
            self._send_message(list_name, policy, message_id, message_text)
            if stem is not None:
                self._switchboard.finish(stem)
        except Exception as error:
            # Archiving failed, send the message to our own queue.
            log.error(
                'archiving failed, re-queuing (mailing-list %s, message id %s, exception %s)',
                mlist.list_id, message_id, error)
            #_log_exception(error)
            # Enqueuing can throw an exception, e.g. a permissions problem or a
            # MemoryError due to a really large message.  Try to be graceful.
            # #### Does this effort make sense?  Maybe better just log and raise
            try:
                self._switchboard.enqueue(msg, mlist=mlist)
            except Exception as error:
                log.error(
                    'queuing failed on mailing-list %s for message %s with exception %s',
                    mlist.list_id, message_id, error)
                if stem is not None:
                    # Try to preserve the original queue entry for possible
                    # analysis.
                    self._switchboard.finish(stem, preserve=True)
            if stem is not None:
                self._switchboard.finish(stem)

    def _send_message(self, list_name, policy, message_id, message):
        """
        Use the appropriate API to send the message (a bytes) to Mailarchive.

        :param list_name: The localpart of the List-Post address.
        :param policy: The name of the list's archive_policy.
        :param message_id: The message's Message-Id.
        :param message: The message as a bytes.
        :returns: None
        """

        log.debug('%s archiver: sending message %s', self.name, message_id)
        if self.api == 'HTTP':
            proc = self._post_to_mailarchive(list_name, policy, message)
        elif self.api == 'FILE':
            proc = self._queue_file_for_mailarchive(list_name, policy, message)
        elif self.api == 'PIPE':
            proc = self._pipe_to_mailarchive(list_name, policy, message)
        else:
            # can't get here
            proc = _MockRunStatus(500, None, None)
        if proc.returncode != 0:
            log.error(self.process_errfmt.format(cmd=' '.join(' '.join(proc.args)),
                                                 code=proc.returncode,
                                                 msg_id=message_id))
        if proc.stdout:
            log.info(proc.stdout)
        if proc.stderr:
            log.error(proc.stderr)
        if proc.returncode != 0:
            # #### bad design?!  Just return proc and let _archive_message or
            # archive_message handle it.
            raise RuntimeError(proc)

    def _post_to_mailarchive(self, list_name, policy, message):
        """
        Use the HTTP API v1 to POST the message (a bytes) to Mailarchive.
        Expect status codes 201 (Created), 400 (Bad Request), or 403 (Forbidden).

        :param list_name: The localpart of the List-Post address.
        :param policy: The name of the list's archive_policy.
        :param message: The message as a bytes.
        :returns: The subprocess's status.
        :rtype: _MockRunStatus.
        """

        # This will error (KeyError) on the old format with list and policy parameters
        url = self.destination.format()
        api_v1_data = {
            'list_name' : list_name,
            'list_visibility' : policy,
            'message' : b64encode(message).decode()
            }
        try:
            response = post(url,
                            json=api_v1_data,
                            headers={'X-API-Key' : self.api_key})
        except RequestException as error:
            log.error(
                'Connection to Mailarchive failed: %s',
                error)
            raise
        status = response.status_code
        if status == 201:
            pass
        elif status == 400:
            log.error('Bad Request: most likely non-conforming email')
        elif status == 403:
            log.error('Forbidden; not allowed to archive message')
        elif status == 404:
            log.error(f"Not found; {self.destination} doesn't implement the API")
        elif status == 502:
            log.error('Bad Gateway: most likely Mailarchive is down')
        else:
            log.error(f'Unexpected status {status}')
        return _MockRunStatus(status, response.content, None)

    # Based in part on mailman_hyperkitty:_send_message()
    def _old_post_to_mailarchive(self, list_name, policy, message):
        """
        Use the new HTTP API to POST the message (a bytes) to Mailarchive.
        Expect Status Codes 201 (Created) Or 400 (Bad Request).

        :param list_name: The localpart of the List-Post address.
        :param policy: The name of the list's archive_policy.
        :param message: The message as a bytes.
        :returns: The subprocess's status.
        :rtype: _MockRunStatus.
        """

        url = self.destination.format(policy=policy, listName=list_name)
        try:
            response = post(url, data=message,
                            headers={'X-API-Key' : self.api_key})
        except RequestException as error:
            log.error(
                'Connection to Mailarchive failed: %s',
                error)
            raise
        status = response.status_code
        if status == 201:
            pass                        # we be jammin'!
        elif status == 400:
            log.error('Bad Request: most likely non-conforming email')
        else:
            log.error(f'Unexpected status {status}')
        return _MockRunStatus(status, response.content, None)

    def _pipe_to_mailarchive(self, list_name, policy, message):
        """
        Archive a message using the old piping API.

        :param list_name: The localpart of the List-Post address.
        :param policy: The name of the list's archive_policy.
        :param message: The message as a bytes.
        :returns: The subprocess's status.
        :rtype: subprocess.CompletedProcess.
        """

        # convert policy to long option form
        # self.command must be absolute path
        command = [self.command, list_name, '--' + policy]
        return run(command, capture_output=True, input=message)

    def _queue_file_for_mailarchive(self, list_name, policy, message):
        """
        Archive a message using the old temporary file API.

        :param list_name: The localpart of the List-Post address.
        :param policy: The name of the list's archive_policy.
        :param message: The message as a bytes.
        :returns: The subprocess's status.
        :rtype: subprocess.CompletedProcess.
        """

        with NamedTemporaryFile(delete=False,
                                dir=self.destination,
                                prefix=f'{list_name}.{policy}.') as tempfile:
            tempfile.write(message)
            # self.command must be absolute path
            command = [self.command, tempfile.name]
            return run(command, capture_output=True)

    # Slightly modified mailman_hyperkitty:process_queue()
    def _process_queue(self):
        """Go through the queue of held messages to archive and send them to
        the archive.
        If the archiving is successful, remove them from the queue, otherwise
        re-enqueue them.
        """
        self._switchboard.recover_backup_files()
        files = self._switchboard.files
        for stem in files:
            log.debug('%s archiver processing queued : %s', self.name, stem)
            try:
                # Ask the switchboard for the message and metadata objects
                # associated with this queue file.
                msg, msgdata = self._switchboard.dequeue(stem)
            except Exception as error:
                # We don't want the process to die here or no further email can
                # be archived, so we just log and skip the entry, but preserve
                # it for analysis.
                _log_error(error)
                log.error('Skipping and preserving failed message: %s', stem)
                self._switchboard.finish(stem, preserve=True)
                continue
            mlist = msgdata["mlist"]
            self._archive_message(mlist, msg, stem=stem)

    def _make_hash(self, mlist, msg):
        if not self.base_url:
            return None
        sha = sha1(self._get_message_id(msg).encode('us-ascii'))
        sha.update(mlist.list_name.encode('utf-8'))
        return urlsafe_b64encode(sha.digest()).strip(b"=").decode('us-ascii')

    @staticmethod
    def _get_message_id(msg):
        """Extract or generate a message ID."""
        message_id = msg['Message-Id']
        if not message_id:
            message_id = msg['Resent-Message-Id']
        if message_id:
            message_id = message_id.strip().strip('<>')
        else:
            message_id = make_msgid('ARCHIVE')
        return message_id
