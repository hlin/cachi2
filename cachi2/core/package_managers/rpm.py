import asyncio
import logging
import os
from typing import List

import yaml
from pydantic import BaseModel

from cachi2.core.config import get_config
from cachi2.core.models.input import Request
from cachi2.core.models.output import RequestOutput
from cachi2.core.models.sbom import Component
from cachi2.core.package_managers.general import async_download_files

log = logging.getLogger(__name__)


class Package(BaseModel):
    repoid: str
    url: str
    checksum: str
    size: int


class Arch(BaseModel):
    arch: str
    packages: List[Package]
    sources: List[Package]


class RpmsLock(BaseModel):
    lockfileVersion: int
    lockfileVendor: str
    lockfileType: str
    arches: List[Arch]

    @classmethod
    def from_file(cls, lockfile_path):
        with open(lockfile_path) as f:
            lockfile = yaml.safe_load(f)
            return cls(**lockfile)

    def download(self, output_dir):
        for arch in self.arches:
            # Download binary packages
            files = {}
            for pkg in arch.packages:
                dest = os.path.join(
                    output_dir, "deps", "rpm", arch.arch, pkg.repoid, os.path.basename(pkg.url)
                )
                files[pkg.url] = dest
                os.makedirs(os.path.dirname(dest), exist_ok=True)
            asyncio.run(async_download_files(files, get_config().concurrency_limit))

            # Download source packages
            files = {}
            for pkg in arch.sources:
                dest = os.path.join(
                    output_dir,
                    "deps",
                    "rpm",
                    "sources",
                    arch.arch,
                    pkg.repoid,
                    os.path.basename(pkg.url),
                )
                files[pkg.url] = dest
                os.makedirs(os.path.dirname(dest), exist_ok=True)
            asyncio.run(async_download_files(files, get_config().concurrency_limit))


def fetch_rpm_source(request: Request) -> RequestOutput:
    """Resolve and fetch rpm dependencies for the given request.

    :param request: the request to process
    :return: A RequestOutput object with content for all rpm packages in the request
    """
    components: list[Component] = []

    rpmslock = RpmsLock.from_file("rpms.lock.yaml")
    rpmslock.download(request.output_dir)

    return RequestOutput.from_obj_list(
        components=components,
    )
