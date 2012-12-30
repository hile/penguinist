#!/usr/bin/env python
"""
Implementation of linux filesystem mount point parsing
"""

import os,re,logging
from subprocess import check_output,CalledProcessError

#noinspection PyPackageRequirements,PyPackageRequirements,PyPackageRequirements,PyPackageRequirements
from systematic.filesystems import MountPoint,FileSystemError

PSEUDO_FILESYSTEM = [
    'proc','sysfs','devpts',
    'fusectl','securityfs','debugfs',
    'rpc_pipefs','binfmt_misc','nfsd'
]

DM_PREFIX = '/dev/mapper/'
MAPPER_PATH = '/dev/mapper'

UUID_PATH = '/dev/disk/by-uuid'
LABEL_PATH = '/dev/disk/by-label'

RE_MOUNT = re.compile(r'([^\s]*) on (.*) type ([^\s]+) \(([^\)]*)\)$')

class MountPoints(dict):
    """
    Mount points for linux filesystems
    """
    def __init__(self):
        self.update()

    def update(self):
        """
        Update list of linux mountpoints based on /bin/mount output
        """
        try:
            output = check_output(['/bin/mount'])
        except CalledProcessError:
            raise FileSystemError('Error running /bin/mount')

        for l in [l for l in output.split('\n') if l.strip()!='']:
            if l[:4] == 'map ':
                continue

            m = RE_MOUNT.match(l)
            if not m:
                continue
            device = m.group(1)
            mountpoint = m.group(2)
            filesystem = m.group(3)
            flags = map(lambda x: x.strip(), m.group(4).split(','))

            entry = LinuxMountPoint(device,mountpoint,filesystem)
            for f in flags:
                entry.flags.set(f,True)
            self[mountpoint] = entry

class LinuxMountPoint(MountPoint):
    """
    One linux mountpoint based on /bin/mount output line
    Additional attributes:
    uuid        Filesystem uuid
    label       Filesystem label
    """
    def __init__(self,device,mountpoint,filesystem):
        MountPoint.__init__(self,device,mountpoint,filesystem)

        if self.device[:len(DM_PREFIX)] == DM_PREFIX:
            for name in os.listdir(MAPPER_PATH):
                dev = os.path.realpath(os.path.join(MAPPER_PATH,name))
                if name == os.path.basename(self.device):
                    self.device = dev
                    break

        self.uuid = None
        for uuid in os.listdir(UUID_PATH):
            dev = os.path.realpath(os.path.join(UUID_PATH,uuid))
            if dev == self.device:
                self.uuid = uuid
                break

        self.label = None
        if os.path.isdir(LABEL_PATH):
            for label in os.listdir(LABEL_PATH):
                dev = os.path.realpath(os.path.join(LABEL_PATH,label))
                if dev == self.device:
                    self.label = label
                    break

    @property
    def usage(self):
        """
        Check usage percentage for this mountpoint.
        Returns dictionary with usage details.
        """
        if self.filesystem in PSEUDO_FILESYSTEM:
            return {}

        try:
            output = check_output(['df','-k',self.mountpoint])
        except CalledProcessError:
            raise FileSystemError('Error getting usage for %s' % self.mountpoint)
        (header,usage) = output.split('\n',1)

        try:
            usage = ' '.join(usage.split('\n'))
        except ValueError:
            pass

        (fs,size,used,free,percent,mp) = [x.strip() for x in usage.split()]
        percent = percent.rstrip('%')

        return {
            'mountpoint': self.mountpoint,
            'size': long(size),
            'used': long(used),
            'free': long(free),
            'percent': int(percent),
        }

