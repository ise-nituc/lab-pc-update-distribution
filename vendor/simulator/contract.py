"""Deployment adapter contract. No commands or executable paths from project JSON."""
import hashlib
from pathlib import Path
import struct

REVISION = 'a49c058ef57ee568ebbc9d70569469bbb70de75f'
VLAB = '/opt/lab/virtual-lab/' + REVISION
ENV = 'nucleo_f446re'
INI = (b'[env:nucleo_f446re]\nplatform = ststm32@20.0.0\nboard = nucleo_f446re\n'
       b'framework = stm32cube\nplatform_packages =\n'
       b'    platformio/framework-stm32cubef4@1.28.3\n'
       b'    platformio/toolchain-gccarmnoneeabi@1.70201.0\n'
       b'    platformio/tool-ldscripts-ststm32@0.3.0\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def plain(path):
    """Reject symlinks/junctions, including ancestors; no writes through links."""
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or (item.exists() and getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('LinkedPathRejected')
    return path


def boot_values(data):
    """Read launch values only; no ELF acceptance/map/Thumb validation gate.

    This profile uses the STM32 vector table at 0x08000000. Values are read
    from this build, never substituted from an old ELF or a known constant.
    """
    try:
        h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
        for i in range(h[10]):
            kind, offset, va, pa, size, mem, flags, align = struct.unpack_from('<8I', data, h[5] + i * h[9])
            if kind == 1 and va <= 0x08000000 and 0x08000008 <= va + size:
                sp, reset = struct.unpack_from('<II', data, offset + 0x08000000 - va)
                return h[4], sp
    except struct.error:
        pass
    raise ValueError('CannotReadELFLaunchValues')
