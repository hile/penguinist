"""Iptables logs

Classes to parse various types of iptables logs

"""

import re

from seine.address import parse_address
from systematic.log import LogFile, LogfileTailReader, LogEntry, SOURCE_FORMATS

FLAGS = (
    'ACK',
    'CWR',
    'DF',
    'ECE',
    'FIN',
    'INCOMPLETE',
    'PSH',
    'RST',
    'SYN',
)
ADDRESS_FIELDS = (
    'SRC',
    'DST',
)

INTEGER_FIELDS = (
    'DPT',
    'FLOWLBL',
    'ID',
    'SPT',
    'TTL',
    'URGP',
    'WINDOW',
)
HEX_FIELDS = (
    'PREC',
    'RES',
    'TOS',
)
RE_IPTABLES_FORMATS = (
    re.compile('^\[(?P<chain>[^\]]*)\](?P<tokens>.*)$'),
)
RE_BYTECOUNT = [
    re.compile('^(?P<bytes>\d+) bytes$'),
]

class IPTablesTokenGroup(dict):
    """Iptables log tokens

    Tokens in a iptables log entry

    """
    def __init__(self, parent=None):
        self.parent = parent
        self.groups = []
        self['flags'] = []

        if isinstance(self.parent, IPTablesTokenGroup):
            self.parent.groups.append(self)

    def add_token(self, token):
        """Add token

        Add a token to iptables log entry

        """
        key = None
        for separator in ('=', ':'):
            try:
                key, value = [x.strip() for x in token.split(separator, 1)]
                break
            except ValueError:
                pass

        for matcher in RE_BYTECOUNT:
            m = matcher.match(token)
            if m:
                key = 'bytes'
                value = m.groupdict()['bytes']
                break

        if key is None:
            return token

        if key in INTEGER_FIELDS:
            value = int(value)

        if key in ADDRESS_FIELDS:
            value = parse_address(value)

        key = key.lower()
        if key in self:
            if 'proto' in self:
                if self['proto'] == 'UDP' and key == 'len':
                    key = 'udp_eln'
                    return

            else:
                raise ValueError('Duplicate key %s' % key)

        self[key] = value

        return None

    def match_source(self, address):
        if 'SRC' in self and self['SRC'] == address:
            return True

        for group in self.groups:
            if group.match_source(address):
                return True

        return False

    def as_dict(self):
        data = self.copy()
        data['groups'] = []
        for group in self.groups:
            data['groups'].append(group.as_dict())
        return data


class IPTablesLogEntry(LogEntry):
    """Iptables log entry

    LogEntry parser for iptables logs

    """
    def __init__(self, line, year, source_formats=[]):
        LogEntry.__init__(self, line, year, source_formats)

        self.chain = None
        self.is_iptables = False
        self.tokens = IPTablesTokenGroup()

        if self.program not in ('kernel'):
            return

        for format in RE_IPTABLES_FORMATS:
            m = format.match(self.message)
            if m:
                self.chain = m.groupdict()['chain']
                self.program = 'iptables'
                self.is_iptables = True

                group = self.tokens
                parent = group
                unparsed = None
                for token in m.groupdict()['tokens'].split():
                    if token.startswith('['):
                        token = token[1:]
                        group = IPTablesTokenGroup(parent)

                    if token.endswith(']'):
                        group = group.parent
                        token = token[:-1]

                    if token == '':
                        continue

                    if token in FLAGS:
                        group['flags'].append(token)
                    else:
                        try:
                            if isinstance(unparsed, basestring):
                                unparsed = group.add_token(' '.join([unparsed,token]))
                            else:
                                unparsed = group.add_token(token)
                        except ValueError, emsg:
                            raise ValueError('%s: %s' % (self.message, emsg))

                if unparsed is not None:
                    raise ValueError('Unparsed data left: %s' % unparsed)

                break

    def __getattr__(self, attr):
        try:
            return self.tokens[attr]
        except KeyError:
            raise AttributeError('No such attribute: %s' % attr)

    def has(self, attr):
        return attr in self.tokens

    def match_source(self, address):
        try:
            address = parse_address(address)
        except ValueError:
            return False

        return self.tokens.match_source(address)


    def as_dict(self):
        """Return as dict

        Return entry contents as dict

        """
        data = {
            'time': self.time,
            'program': self.program,
            'chain': self.chain,
        }
        data.update(self.tokens.as_dict())
        return data


class IPTablesLog(LogFile):
    """Iptables logfile

    Parse iptables log files

    """
    def __init__(self, path):
        LogFile.__init__(self, path)
        self.lineloader = IPTablesLogEntry

    def next(self):
        try:
            while True:
                try:
                    entry = LogFile.next(self)
                except ValueError, emsg:
                    raise ValueError('%s: %s' % (self.path, emsg))
                if entry.is_iptables:
                    return entry
        except StopIteration:
            raise StopIteration

    def match_source(self, address):
        """Filter by source address

        Return log entries matching source address

        """
        return [x for x in self if x.match_source(address)]

class IPTablesLogTailReader(LogfileTailReader):
    """Tail reader for iptables

    Monitor iptables log file. Example usage:

    import sys
    tail = IPTablesLogTailReader(sys.argv[1])
    tail.seek_to_end()
    while True:
        entry = tail.readline()
        print entry.time
        for k,v in entry.as_dict().items():
            print '  %s=%s' % (k,v,)

    """
    def __init__(self, path=None, fd=None, source_formats=SOURCE_FORMATS, lineparser=IPTablesLogEntry):
        LogfileTailReader.__init__(self, path, fd, source_formats, lineparser)
