import io
from distutils import dist
from typing import Mapping

import pkg_resources


def extract_metadata() -> Mapping[str, str]:

    distribution = pkg_resources.get_distribution("vault-cli")
    metadata_str = distribution.get_metadata(distribution.PKG_INFO)
    metadata_obj = dist.DistributionMetadata()  # type: ignore
    metadata_obj.read_pkg_file(io.StringIO(metadata_str))

    return {
        "author": metadata_obj.author,
        "email": metadata_obj.author_email,
        "license": metadata_obj.license,
        "url": metadata_obj.url,
        "version": metadata_obj.version,
    }
